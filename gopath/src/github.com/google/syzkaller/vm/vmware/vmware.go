package vmware

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
	"strings"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

var hostIP = "127.0.0.1"

// https://apple.stackexchange.com/questions/48502/how-can-i-permanently-add-my-ssh-private-key-to-keychain-so-it-is-automatically
// See above to know how to set up ssh with key.
// Get preferred outbound ip of this machine
func getOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP.String(), nil
}

func init() {
	vmimpl.Register("vmware", ctor, true)

	var err error
	hostIP, err = getOutboundIP()
	if err != nil {
		log.Fatalf("Failed to get IP address: %v", err)
	}
}

type Config struct {
	Addrs   []string `json:"address"` // IP address for the VMware
	VMXPath string   `json:"vmxpath"`
}

type Pool struct {
	env    *vmimpl.Env
	cfg    *Config
	target *targets.Target
}

type instance struct {
	cfg     *Config
	addr    string
	closed  chan bool
	debug   bool
	workdir string
	sshkey  string
	sshuser string
	target  *targets.Target
	merger  *vmimpl.MergerError
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vmware config: %v", err)
	}
	if len(cfg.Addrs) == 0 {
		return nil, fmt.Errorf("no vmware address specified")
	}
	pool := &Pool{
		cfg: 		cfg,
		env: 		env,
		target:     targets.Get(env.OS, env.Arch),
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return len(pool.cfg.Addrs)
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		cfg:     pool.cfg,
		addr:    pool.cfg.Addrs[index],
		closed:  make(chan bool),
		debug:   pool.env.Debug,
		sshkey:  pool.env.SSHKey,
		sshuser: pool.env.SSHUser,
		target:  pool.target,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()

	if err := inst.boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}

func (inst *instance) Close() {
	start := osutil.Command("vmrun", "stop", inst.cfg.VMXPath)
	log.Logf(0, "vmrun stop %s", inst.cfg.VMXPath)
	if err := start.Start(); err != nil {
		log.Logf(0, "failed to stop %v", inst.cfg.VMXPath)
	}
	close(inst.closed)
}

func (inst *instance) RunCmd(commands ...string) ([]byte, error) {
	sshArgs := vmimpl.SSHArgs(inst.debug, inst.sshkey, 22)
	args := []string{"ssh"}
	args = append(args, sshArgs...)
	args = append(args, inst.sshuser+"@"+inst.addr, strings.Join(commands, " "))
	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}

	out, err := osutil.RunCmd(time.Minute, "", args[0], args[1:]...)
	if inst.debug {
		log.Logf(0, "ssh returned")
	}
	return out, err
}

func (inst *instance) boot() error {
	// Grace period
	time.Sleep(30 * time.Second)

	start := osutil.Command("vmrun", "start", inst.cfg.VMXPath)
	log.Logf(0, "vmrun start %s", inst.cfg.VMXPath)
	if err := start.Start(); err != nil {
		return fmt.Errorf("failed to start %v", inst.cfg.VMXPath)
	}
	return inst.waitForSSH()
}

func (inst *instance) waitForSSH() error {
	var err error
	for i := 0; i < 300; i++ {
		if !vmimpl.SleepInterruptible(5 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if _, err = inst.RunCmd("pwd"); err == nil {
			// FIXME: Grace time, VM is still booting though we can connect to it.
			vmimpl.SleepInterruptible(time.Minute)
			return nil
		}
	}
	return fmt.Errorf("instance is dead: %v", err)
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf("%v:%v", hostIP, port), nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	if inst.target.OS == "darwin" && inst.sshuser == "root" {
		// for macOS, the dir for root user is /var/root/.
		vmDst := filepath.Join("/var", "root", filepath.Base(hostSrc))
		return inst.Copy2VM(hostSrc, vmDst)
	} else {
		vmDst := filepath.Join("/Users", inst.sshuser, filepath.Base(hostSrc))
		return inst.Copy2VM(hostSrc, vmDst)
	}
}

func (inst *instance) Copy2VM(hostSrc, vmDst string) (string, error) {
	sshArgs := vmimpl.SCPArgs(inst.debug, inst.sshkey, 22)
	args := []string{"scp"}
	args = append(args, sshArgs...)
	args = append(args, hostSrc)
	args = append(args, inst.sshuser+"@"+inst.addr+":"+vmDst)
	if inst.debug {
		log.Logf(0, "running command: %#v", args)
	}

	if _, err := osutil.RunCmd(time.Minute, "", args[0], args[1:]...); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	// We have no idea what is the crash output we should expect, for now we set a
	// non-existing process name to ignore the output.
	tty, err1 := vmimpl.OpenDarwinConsole(inst.debug, inst.sshkey, inst.sshuser, inst.addr,
		"/usr/bin/log stream --color none --type log --process test")
	if err1 != nil {
		return nil, nil, err1
	}

	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		tty.Close()
		return nil, nil, err
	}
	sshArgs := vmimpl.SSHArgs(inst.debug, inst.sshkey, 22)
	args := []string{"ssh"}
	args = append(args, sshArgs...)
	args = append(args, inst.sshuser+"@"+inst.addr, command)
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		tty.Close()
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("console", tty)
	merger.Add("ssh", rpipe)

	return vmimpl.Multiplex(cmd, merger, tty, timeout, stop, inst.closed, inst.debug)
}

func (inst *instance) Diagnose() ([]byte, bool) {
	return nil, false
}
