package main

import (
	"flag"
	"runtime"
	"sort"
	"math/rand"
	"time"
	"fmt"
	"os"
	"strings"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOutputPath = flag.String("out", "", "file path to the output")
	flagCallName = flag.String("call", "", "syscall Name")

	flagOS      = flag.String("os", runtime.GOOS, "target OS")
	flagArch    = flag.String("arch", runtime.GOARCH, "target arch")

	flagGen     = flag.Bool("gen", false, "allow to generate testcase")
)

func main() {
	flag.Parse()
	if *flagOutputPath == "" {
		log.Fatalf("no output path provided!")
	}
	if *flagCallName == "" {
		log.Fatalf("no syscall name provided")
	}
	
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var targetCall *prog.Syscall
	calls := make(map[*prog.Syscall]bool)
	for _, call := range target.Syscalls {
		log.Logf(4, "syscall: %s", call.Name)
		calls[call] = true
		if *flagCallName == call.Name {
			targetCall = call
			log.Logf(2, "find target call %s", call.Name)
		}
	}

	if targetCall == nil {
		log.Fatalf("failed to find the syscall")
	}
	log.Logf(2, "target call %s %s", targetCall.Name, *flagCallName)

	corpus := loadCorpus(target)
	sort.Slice(corpus, func(i, j int) bool {
		return len(corpus[i].Calls) < len(corpus[j].Calls)
	})

	var candidates []*prog.Prog
	for _, p := range corpus {
		log.Logf(4, "corpus: %s", p.Serialize())
		found := false
		for _, c := range p.Calls {
			if c.Meta == targetCall {
				found = true
				break
			}
		}

		if found {
			candidates = append(candidates, p)
		}
	}

	if len(candidates) == 0 && *flagGen {
		log.Logf(0, "no testcase in the corpus uses this func")
		// Generate a testcase based on our template
		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		choiceTable := target.BuildChoiceTable(corpus, calls)

		var resources []string
		prog.ForeachCallType(targetCall, func(typ prog.Type, ctx prog.TypeCtx) {
			if ctx.Dir == prog.DirOut {
				return
			}
			switch typ1 := typ.(type) {
			case *prog.ResourceType:
				log.Logf(0, "find resource %s %s", typ1.TypeName, typ1.Desc.Name)
				resources = append(resources, typ1.Desc.Name)
			default:
				// Some special dependences are encoded as const/union/flags, etc.
				if strings.Contains(typ.Name(), "connection") {
					log.Logf(0, "find special dependence %s", typ.Name())
					resources = append(resources, typ.Name())
				}
			}
		})

		found := false
		// Find the most similar syscall in the reversed order
		for _, p := range corpus {
			// for idx := len(p.Calls)-1; idx >= 0; idx-- {
				// c := p.Calls[idx]
			for idx, c := range p.Calls {
				results := make(map[string]bool)
				prog.ForeachCallType(c.Meta, func(typ prog.Type, ctx prog.TypeCtx) {
					switch typ1 := typ.(type) {
					case *prog.ResourceType:
						if ctx.Dir == prog.DirIn {
							results[typ1.Desc.Name] = true
						}
					default:
						if strings.Contains(typ.Name(), "connection") {
							log.Logf(0, "match special dependence %s", typ.Name())
							results[typ.Name()] = true
						}
					}
				})

				succeed := true
				for _, res := range resources {
					if _, ok := results[res]; !ok {
						succeed = false
						break
					}
				}
				if succeed {
					found = true
					log.Logf(0, "%d: find the prog with similar syscall: %s", idx, p.Serialize())
					p := p.Clone()
					new_prog := target.GenerateValidProgram(rnd, targetCall, p, idx+1, choiceTable, corpus)
					candidates = append(candidates, new_prog)
					break
				}
			}

			if found {
				break
			}
		}

		if !found {
			for _, p := range corpus {
				pos := -1
				succeed := true
				for _, resource := range resources {
					// Find the first use of the resource
					var indices []int
					for idx, c := range p.Calls {
						prog.ForeachCallType(c.Meta, func(typ prog.Type, ctx prog.TypeCtx) {
							if ctx.Dir == prog.DirOut {
								return
							}
							switch typ1 := typ.(type) {
							case *prog.ResourceType:
								if resource == typ1.Desc.Name {
									indices = append(indices, idx)
								}
							default:
								if resource == typ.Name() {
									indices = append(indices, idx)
								}
							}
						})
					}
	
					if len(indices) == 0 {
						succeed = false
						break
					}
					// Find the first use of the resource
					if indices[0] > pos {
						pos = indices[0]
					}
				}

				if succeed {
					found = true
					log.Logf(0, "find the prog %s", p.Serialize())
					p := p.Clone()
					new_prog := target.GenerateValidProgram(rnd, targetCall, p, pos, choiceTable, corpus)
					candidates = append(candidates, new_prog)
					break
				}
			}
		}

		if !found {
			new_prog := target.GenerateValidProgram2(rnd, targetCall, choiceTable)
			candidates = append(candidates, new_prog)
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		return len(candidates[i].Calls) < len(candidates[j].Calls)
	})

	for _, p := range candidates {
		// We may cut off the program and hence it could not be translated to c code
		// directly. To cope with it, we serialize it to syz program and deserialize it
		// with non-strict mode.
		data := p.Serialize()
		if err := osutil.WriteFile(*flagOutputPath + ".syz", data); err != nil {
			log.Fatalf("failed to output file: %v", err)
		}
		if np, err1 := target.Deserialize(data, prog.NonStrict); err1 != nil {
			log.Fatalf("failed to deserialize: %v", err1)
		} else {
			p = np
		}

		if err := build(target, p, *flagOutputPath + ".c"); err != nil {
			log.Fatalf("failed to output file: %v", err)
		}

		for _, c := range p.Calls {
			if c.Meta == targetCall {
				inputCnt, _ := c.Args[3].(*prog.ConstArg).Value()
				inputStructCnt, _ := c.Args[5].(*prog.ConstArg).Value()
				outputCnt, outputStructCnt := uint64(0), uint64(0)
				if arg, ok := c.Args[7].(*prog.PointerArg); ok {
					outputCnt, _ = arg.Res.(*prog.ConstArg).Value()
				}
				if arg, ok := c.Args[9].(*prog.PointerArg); ok {
					outputStructCnt, _ = arg.Res.(*prog.ConstArg).Value()
				}
				log.Logf(0, "{\"inputCnt\": %v, \"inputStructCnt\": %v, \"outputCnt\": %v, \"outputStructCnt\": %v}", 
					inputCnt, inputStructCnt, outputCnt, outputStructCnt)
				break
			}
		}
		break
	}
}

func getCompatibleResources(p *prog.Prog, resourceType string) (ret []int) {
	for idx, c := range p.Calls {
		prog.ForeachArg(c, func(arg prog.Arg, _ *prog.ArgCtx) {
			a, ok := arg.(*prog.ResultArg)
			if !ok || a.Dir() != prog.DirOut {
				return
			}
			log.Logf(0, "get resource %s %s", a.Type().Name(), resourceType)
			if a.Type().Name() != resourceType {
				return
			}
			// if !r.target.isCompatibleResource(resourceType, a.Type().Name()) {
			// 	return
			// }
			ret = append(ret, idx)
		})
	}
	return
}

func loadCorpus(target *prog.Target) []*prog.Prog {
	var corpus []*prog.Prog

	corpusDB, err := db.Open("corpus.db")
	if err != nil {
		log.Logf(2, "failed to open corpus database: %v", err)
		return corpus
	}

	broken := 0
	for key, rec := range corpusDB.Records {
		p, bad := checkProgram(target, rec.Val)
		if bad {
			corpusDB.Delete(key)
			broken++
			continue
		}
		corpus = append(corpus, p)
	}
	log.Logf(2, "delete %v/%v broken", broken, len(corpus))
	return corpus
}

func checkProgram(target *prog.Target, data []byte) (*prog.Prog, bool) {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return nil, true
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil, true
	}
	return p, false
}

func build(target *prog.Target, p *prog.Prog, path string) error {
	opts := csource.Options{
		Threaded:     false,
		Collide:      false,
	}
	src, err := csource.Write(p, opts)
	if err != nil {
		return fmt.Errorf("failed to generate C source: %v", err)
	}
	if formatted, err := csource.Format(src); err != nil {
		return fmt.Errorf("%v", err)
	} else {
		src = formatted
	}
	if err := osutil.WriteFile(path, src); err != nil {
		return fmt.Errorf("failed to output file: %v", err)
	}

	bin, err := csource.BuildNoWarn(target, src)
	if err != nil {
		return fmt.Errorf("failed to build C source: %v", err)
	}

	if err := os.Rename(bin, "poc"); err != nil {
		return fmt.Errorf("failed to move poc %v", err)
	}
	return nil
}
