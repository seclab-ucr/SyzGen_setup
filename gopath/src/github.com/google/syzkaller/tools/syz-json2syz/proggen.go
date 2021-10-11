package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

func parseFile(filename string, target *prog.Target) (*prog.Prog, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return parseData(data, target)
}

type context struct {
	builder        *prog.Builder
	target         *prog.Target
	returnCache    returnCache
	currentSyzCall *prog.Syscall
	currentCall    *prog.Call
}

func getBytes(data []interface{}) []byte {
	ret := []byte{}
	for _, a := range data {
		b := a.(float64)
		ret = append(ret, uint8(b))
	}
	return ret
}

func getValue(rawData []interface{}, size uint64) uint64 {
	data := getBytes(rawData)
	switch size {
	case 8:
		return binary.LittleEndian.Uint64(data)
	case 4:
		return uint64(binary.LittleEndian.Uint32(data))
	case 2:
		return uint64(binary.LittleEndian.Uint16(data))
	case 1:
		return uint64(data[0])
	default:
		log.Fatalf("wrong size %d for %v", size, rawData)
	}
	return 0
}

func parseData(data []byte, target *prog.Target) (*prog.Prog, error) {
	retCache := newRCache()
	ctx := &context{
		builder:     prog.MakeProgGen(target),
		target:      target,
		returnCache: retCache,
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var data map[string]interface{}
		if err := json.Unmarshal(line, &data); err != nil {
			return nil, fmt.Errorf("Fail to unmarshal json data: %v", err)
		}
		name := data["group"].(string)
		if syzCall, ok := target.SyscallMap[name]; ok {
			// log.Logf(0, "%s %s", name, syzCall.CallName)
			ctx.currentSyzCall = syzCall
			call := ctx.genCall(data["args"].([]interface{}))
			if call == nil {
				continue
			}
			log.Logf(2, "call: %s %v", call.Meta.Name, call.Args)
			if err := ctx.builder.AppendNoSize(call); err != nil {
				return nil, err
			}
		}
	}
	log.Logf(2, "finalize")
	return ctx.builder.Finalize()
}

func (ctx *context) genCall(args []interface{}) *prog.Call {
	ctx.currentCall = new(prog.Call)
	ctx.currentCall.Meta = ctx.currentSyzCall
	call := ctx.currentCall
	call.Ret = prog.MakeReturnArg(call.Meta.Ret)

	for i := range call.Meta.Args {
		res := ctx.genArg(call.Meta.Args[i].Type, prog.DirIn, args[i])
		call.Args = append(call.Args, res)
	}
	return call
}

func (ctx *context) genArg(syzType prog.Type, dir prog.Dir, arg interface{}) prog.Arg {
	if arg == nil {
		log.Logf(3, "parsing syzType: %s, arg is nil. generating default arg...", syzType.Name())
		return syzType.DefaultArg(dir)
	}
	log.Logf(3, "parsing arg of syz type: %T %s, ir type: %T, %#v, %v", syzType, syzType.Name(), arg, arg, dir)

	if dir == prog.DirOut {
		switch syzType.(type) {
		case *prog.PtrType, *prog.StructType, *prog.ResourceType, *prog.BufferType:
			// Resource Types need special care. Pointers, Structs can have resource fields e.g. pipe, socketpair
			// Buffer may need special care in out direction
		default:
			return syzType.DefaultArg(dir)
		}
	}

	switch a := syzType.(type) {
	case *prog.IntType, *prog.FlagsType, *prog.CsumType, *prog.LenType:
		return ctx.genInt(a, dir, arg)
	case *prog.ConstType:
		return ctx.genConst(a, dir, arg)
	case *prog.PtrType:
		return ctx.genPtr(a, dir, arg)
	case *prog.StructType:
		return ctx.genStruct(a, dir, arg)
	case *prog.ResourceType:
		return ctx.genResource(a, dir, arg)
	case *prog.UnionType:
		return ctx.genUnionArg(a, dir, arg)
	case *prog.BufferType:
		return ctx.genBuffer(a, dir, arg)
	case *prog.ArrayType:
		return ctx.genArray(a, dir, arg)
	default:
		log.Fatalf("unimplemented arg type %T", syzType)
	}
	return nil
}

func (ctx *context) genArray(syzType *prog.ArrayType, dir prog.Dir, arg interface{}) prog.Arg {
	// Similar to buffer
	field := arg.(map[string]interface{})
	typ := field["type"].(string)

	var args []prog.Arg
	var data []interface{}
	if typ == "buffer" {
		data = field["data"].([]interface{})
	} else if typ == "struct" {
		data = field["fields"].([]interface{})
	} else {
		log.Fatalf("unimplemented array type %s", typ)
	}

	for _, each := range data {
		args = append(args, ctx.genArg(syzType.Elem, dir, each))
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

func (ctx *context) genBuffer(syzType *prog.BufferType, dir prog.Dir, arg interface{}) prog.Arg {
	field := arg.(map[string]interface{})
	if dir == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, dir, syzType.Size())
		}
		return prog.MakeOutDataArg(syzType, dir, uint64(field["size"].(float64)))
	}

	data := getBytes(field["data"].([]interface{}))
	switch syzType.Kind {
	case prog.BufferFilename, prog.BufferString:
		data = append(data, '\x00')
	}
	if !syzType.Varlen() {
		size := syzType.Size()
		for uint64(len(data)) < size {
			data = append(data, 0)
		}
		data = data[:size]
	}
	return prog.MakeDataArg(syzType, dir, data)
}

func (ctx *context) genResource(syzType *prog.ResourceType, dir prog.Dir, arg interface{}) prog.Arg {
	var val uint64
	switch a := arg.(type) {
	case float64:
		val = uint64(a)
	case map[string]interface{}:
		typ := a["type"].(string)
		if typ == "buffer" || typ == "resource" {
			val = getValue(a["data"].([]interface{}), uint64(a["size"].(float64)))
		} else if typ == "struct" {
			// Take the first field
			fields := a["fields"].([]interface{})
			return ctx.genArg(syzType, dir, fields[0])
		} else {
			log.Fatalf("unsupported type for resource: %T %v", arg, typ)
		}
	default:
		val = 0
		log.Fatalf("unsupported type for resource: %T %#v", arg, arg)
	}

	if dir == prog.DirOut {
		log.Logf(2, "resource returned by call argument: %v, val: %v", arg, val)
		res := prog.MakeResultArg(syzType, dir, nil, syzType.Default())
		ctx.returnCache.cache(syzType, val, res)
		return res
	}

	if res := ctx.returnCache.get(syzType, val); res != nil {
		return prog.MakeResultArg(syzType, dir, res.(*prog.ResultArg), syzType.Default())
	}
	return prog.MakeResultArg(syzType, dir, nil, val)
}

func (ctx *context) genStruct(syzType *prog.StructType, dir prog.Dir, arg interface{}) prog.Arg {
	var args []prog.Arg
	switch a := arg.(type) {
	case map[string]interface{}:
		typ := a["type"].(string)
		if typ == "struct" {
			fields := a["fields"].([]interface{})
			for i := 0; i < len(syzType.Fields); i++ {
				if prog.IsPad(syzType.Fields[i].Type) {
					continue
				}

				if i >= len(fields) {
					fields = append(fields, map[string]interface{}{
						"type": "buffer",
						"size": float64(0),
					})
					continue
				}

				field := fields[i].(map[string]interface{})
				cur_size := uint64(field["size"].(float64))
				size := cur_size
				if !syzType.Fields[i].Varlen() {
					size = syzType.Fields[i].Size()
				}
				if cur_size > size {
					if field["type"] != "buffer" {
						log.Fatalf("Inconsistent for non-buffer type")
					}
					// split
					data := field["data"].([]interface{})
					prev := map[string]interface{}{
						"type": "buffer",
						"data": data[0:size],
						"size": float64(size),
					}
					next := map[string]interface{}{
						"type": "buffer",
						"data": data[size:cur_size],
						"size": float64(cur_size - size),
					}
					fields[i] = prev
					fields = append(fields, next)
					copy(fields[i+2:], fields[i+1:])
					fields[i+1] = next
				}
			}

			j := 0
			for i := range syzType.Fields {
				if prog.IsPad(syzType.Fields[i].Type) {
					args = append(args, syzType.Fields[i].DefaultArg(dir))
					continue
				}
				args = append(args, ctx.genArg(syzType.Fields[i].Type, dir, fields[j]))
				j++
			}
		} else {
			data := a["data"].([]interface{})
			// fmt.Printf("genStruct: %v %v\n", data, syzType)
			offset := uint64(0)
			for _, each := range syzType.Fields {
				if prog.IsPad(each.Type) {
					args = append(args, each.DefaultArg(dir))
					offset += each.Size()
					continue
				}
				if offset < uint64(len(data)) {
					field := map[string]interface{}{
						"type": "buffer",
						"data": data[offset : offset+each.Size()],
						"size": float64(each.Size()),
					}
					args = append(args, ctx.genArg(each.Type, dir, field))
				} else {
					field := map[string]interface{}{
						"type": "buffer",
						"size": float64(0),
					}
					args = append(args, ctx.genArg(each.Type, dir, field))
				}
				offset += each.Size()
			}
		}
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

func (ctx *context) genUnionArg(syzType *prog.UnionType, dir prog.Dir, arg interface{}) prog.Arg {
	if arg == nil {
		log.Logf(1, "generating union arg. arg is nil")
		return syzType.DefaultArg(dir)
	}

	for i, field := range syzType.Fields {
		res := ctx.genArg(field.Type, dir, arg)
		if res != nil {
			return prog.MakeUnionArg(syzType, dir, res, i)
		}
	}
	log.Fatalf("Return nil for union arg")
	return nil
}

func (ctx *context) genConst(syzType *prog.ConstType, dir prog.Dir, arg interface{}) prog.Arg {
	switch a := arg.(type) {
	case map[string]interface{}:
		typ := a["type"].(string)
		if typ == "ptr" { // check if it is a null pointer
			if _, ok := a["ref"]; ok && syzType.Val == 0 {
				return nil
			}
		} else if typ != "buffer" && typ != "const" {
			log.Logf(1, "%#v is not const", arg)
			return nil
		} else {
			if syzType.Size() < uint64(len(a["data"].([]interface{}))) {
				log.Logf(1, "%#v has more data", arg)
				return nil
			}
		}
	}

	return prog.MakeConstArg(syzType, dir, syzType.Val)
}

func (ctx *context) genInt(syzType prog.Type, dir prog.Dir, arg interface{}) prog.Arg {
	switch a := arg.(type) {
	case float64:
		return prog.MakeConstArg(syzType, dir, uint64(a))
	case map[string]interface{}:
		typ := a["type"].(string)
		if typ == "ptr" { // it is a null pointer
			if _, ok := a["ref"]; !ok {
				return prog.MakeConstArg(syzType, dir, 0)
			}
		} else {
			size := uint64(a["size"].(float64))
			if size == 0 { // We did not record any data for this
				return prog.MakeConstArg(syzType, dir, 0)
			}
			val := getValue(a["data"].([]interface{}), size)
			return prog.MakeConstArg(syzType, dir, val)
		} 
	default:
		log.Fatalf("unsupported type for Int: %T %#v", arg, arg)
	}
	return nil
}

func (ctx *context) genPtr(syzType *prog.PtrType, dir prog.Dir, arg interface{}) prog.Arg {
	switch a := arg.(type) {
	case float64:
		if a == 0 {
			return prog.MakeSpecialPointerArg(syzType, dir, 0)
		}
	case map[string]interface{}:
		typ := a["type"].(string)
		if typ == "ptr" {
			if ref, ok := a["ref"]; ok {
				res := ctx.genArg(syzType.Elem, syzType.ElemDir, ref)
				return ctx.addr(syzType, dir, res.Size(), res)
			} else {
				// Null pointer
				return prog.MakeSpecialPointerArg(syzType, dir, 0)
			}
		} else if typ == "const" {
			// Null pointer
			return prog.MakeSpecialPointerArg(syzType, dir, 0)
		}
		log.Fatalf("unsupported type of Ptr: %T %#v", syzType, arg)
	}
	return nil
}

func (ctx *context) addr(syzType prog.Type, dir prog.Dir, size uint64, data prog.Arg) prog.Arg {
	return prog.MakePointerArg(syzType, dir, ctx.builder.Allocate(size), data)
}
