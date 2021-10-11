package report

import (
	"bytes"
	// "regexp"
)

type darwin struct {
	*config
}

func ctorDarwin(cfg *config) (Reporter, []string, error) {
	ctx := &darwin{
		config: cfg,
	}
	return ctx, nil, nil
}

func (ctx *darwin) ContainsCrash(output []byte) bool {
	return containsCrash(output, darwinOopses, ctx.ignores)
}

func (ctx *darwin) Parse(output []byte) *Report {
	rep := &Report{
		Output: output,
	}
	var oops *oops
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops1 := range darwinOopses {
			if !matchOops(output[pos:next], oops1, ctx.ignores) {
				continue
			}
			if oops == nil {
				oops = oops1
				rep.StartPos = pos
			}
			rep.EndPos = next
		}
		// Console output is indistinguishable from fuzzer output,
		// so we just collect everything after the oops.
		if oops != nil {
			lineEnd := next
			if lineEnd != 0 && output[lineEnd-1] == '\r' {
				lineEnd--
			}
			rep.Report = append(rep.Report, output[pos:lineEnd]...)
			rep.Report = append(rep.Report, '\n')
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	title, corrupted, _ := extractDescription(output[rep.StartPos:], oops, freebsdStackParams)
	rep.Title = title
	rep.Corrupted = corrupted != ""
	rep.CorruptedReason = corrupted
	return rep
}

func (ctx *darwin) Symbolize(rep *Report) error {
	return nil
}

var darwinOopses = []*oops{
	// {
	// 	[]byte("com.apple.securityd:security_exception"),
	// 	[]oopsFormat{},
	// 	[]*regexp.Regexp{},
	// },
}
