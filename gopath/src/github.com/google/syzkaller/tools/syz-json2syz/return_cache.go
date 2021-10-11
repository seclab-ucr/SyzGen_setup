package main

import (
	"fmt"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

type returnCache map[string]prog.Arg

func newRCache() returnCache {
	return make(map[string]prog.Arg)
}

func returnCacheKey(syzType prog.Type, arg interface{}) string {
	a, ok := syzType.(*prog.ResourceType)
	if !ok {
		log.Fatalf("caching non resource type")
	}
	return fmt.Sprintf("%s-%v", a.Desc.Kind[0], arg)
	// return a.Desc.Kind[0] + "-" + traceType.String()
}

func (r returnCache) cache(syzType prog.Type, arg interface{}, res prog.Arg) {
	log.Logf(2, "caching resource: %v", returnCacheKey(syzType, arg))
	r[returnCacheKey(syzType, arg)] = res
}

func (r returnCache) get(syzType prog.Type, arg interface{}) prog.Arg {
	result := r[returnCacheKey(syzType, arg)]
	log.Logf(2, "fetching resource: %s, val: %v", returnCacheKey(syzType, arg), result)
	return result
}
