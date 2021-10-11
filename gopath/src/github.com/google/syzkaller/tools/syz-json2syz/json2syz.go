package main

import (
	"flag"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagFile = flag.String("file", "", "file to parse")
	flagDir  = flag.String("dir", "", "directory to parse")
	flagOS   = flag.String("os", runtime.GOOS, "target OS")
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
)

func main() {
	flag.Parse()
	target := initializeTarget(*flagOS, *flagArch)
	progs := parseJSON(target)
	log.Logf(0, "successfully converted traces; generating corpus.db")
	pack(progs)
}

func initializeTarget(os, arch string) *prog.Target {
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		log.Fatalf("failed to load target: %s", err)
	}
	// target.ConstMap = make(map[string]uint64)
	// for _, c := range target.Consts {
	// 	target.ConstMap[c.Name] = c.Value
	// }
	return target
}

func parseJSON(target *prog.Target) []*prog.Prog {
	var ret []*prog.Prog
	var names []string

	if *flagFile != "" {
		names = append(names, *flagFile)
	} else if *flagDir != "" {
		names = getJSONFiles(*flagDir)
	} else {
		log.Fatalf("-file or -dir must be specified")
	}

	totalFiles := len(names)
	log.Logf(0, "parsing %v traces", totalFiles)
	for i, file := range names {
		log.Logf(1, "parsing file %v/%v: %v", i+1, totalFiles, filepath.Base(names[i]))
		prog, err := parseFile(file, target)
		if err != nil {
			log.Fatalf("%v", err)
		}
		ret = append(ret, prog)
		log.Logf(1, "Program: %s", prog.Serialize())
	}
	return ret
}

func getJSONFiles(dir string) []string {
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("%s", err)
	}
	var names []string
	for _, info := range infos {
		if strings.HasSuffix(info.Name(), ".prog") {
			name := filepath.Join(dir, info.Name())
			names = append(names, name)
		}
	}
	return names
}

func pack(progs []*prog.Prog) {
	var records []db.Record
	for _, prog := range progs {
		records = append(records, db.Record{Val: prog.Serialize()})
	}
	if err := db.Create("corpus.db", 0, records); err != nil {
		log.Fatalf("%v", err)
	}
	log.Logf(0, "finished!")
}
