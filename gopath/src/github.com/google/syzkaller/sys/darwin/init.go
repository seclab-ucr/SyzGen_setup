package darwin

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	target.MakeDataMmap = targets.MakePosixMmap(target, true, false)
	target.Neutralize = targets.MakeUnixNeutralizer(target).Neutralize
}
