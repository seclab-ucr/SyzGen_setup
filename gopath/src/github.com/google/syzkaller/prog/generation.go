// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.removeCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}

func (target *Target) GenerateValidProgram(rs rand.Source, meta *Syscall, p *Prog,
	insertPos int, ct *ChoiceTable, corpus []*Prog) *Prog {
	r := newRand(target, rs)
	r.generate = true
	s := newState(target, ct, corpus)
	for _, c := range p.Calls[:insertPos] {
		s.analyze(c)
	}

	calls := r.generateParticularCall(s, meta)
	for _, c := range calls {
		s.analyze(c)
	}

	// trim the rest
	// for _, c := range p.Calls[insertPos:len(p.Calls)] {
	// 	s.analyze(c)
	// 	calls = append(calls, c)
	// }
	p.Calls = append(p.Calls[:insertPos], calls...)
	p.sanitizeFix()
	p.debugValidate()
	return p
}

func (target *Target) GenerateValidProgram2(rs rand.Source, meta *Syscall, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	r.generate = true
	s := newState(target, ct, nil)

	calls := r.generateParticularCall(s, meta)
	for _, c := range calls {
		s.analyze(c)
		p.Calls = append(p.Calls, c)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}
