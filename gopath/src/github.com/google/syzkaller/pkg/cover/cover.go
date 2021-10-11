// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

import (
	"encoding/binary"
	"reflect"
	"io/ioutil"
	"unsafe"
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/log"
)

type Cover map[uint32]struct{}

func (cov *Cover) Merge(raw []uint32) {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	for _, pc := range raw {
		c[pc] = struct{}{}
	}
}

func (cov Cover) Serialize() []uint32 {
	res := make([]uint32, 0, len(cov))
	for pc := range cov {
		res = append(res, pc)
	}
	return res
}

func RestorePC(pc uint32, base uint32) uint64 {
	return uint64(base)<<32 + uint64(pc)
}

type Kcov_head struct {
	Name	[64]byte
	NumCov	uint64
	Cover	map[uint64]struct{}
}

type Kcov_config struct {
	NumMod	uint64
	Mods    []Kcov_head
}

func (mods *Kcov_config) LoadKCov(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	mods.NumMod = binary.LittleEndian.Uint64(data)
	data = data[8:]
	log.Logf(0, "Num of drivers: %v", mods.NumMod)
	if mods.NumMod != 1 {
		return fmt.Errorf("only support one module right now")
	}

	for i := uint64(0); i < mods.NumMod; i++ {
		var head Kcov_head
		copy(head.Name[:], data[:64])
		log.Logf(0, "driver name: %s", head.Name)
		data = data[64:]
		head.NumCov = binary.LittleEndian.Uint64(data)
		data = data[8:]
		log.Logf(0, "Num of cov: %v", head.NumCov)

		hdr := reflect.SliceHeader{
			Data: uintptr(unsafe.Pointer(&data[0])),
			Len:  int(head.NumCov),
			Cap:  int(head.NumCov),
		}
		res := *(*[]uint64)(unsafe.Pointer(&hdr))
		data = data[head.NumCov*8:]

		head.Cover = make(map[uint64]struct{})
		for _, pc := range res {
			head.Cover[pc] = struct{}{}
			log.Logf(2, "pc: 0x%x", pc)
		}
		mods.Mods = append(mods.Mods, head)
	}
	return nil
}

func (mods *Kcov_config) SaveKCov(path string) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("Could not open file: %v", path)
	}
	defer f.Close()

	binary.Write(f, binary.LittleEndian, mods.NumMod)
	for _, mod := range mods.Mods {
		binary.Write(f, binary.LittleEndian, mod.Name)
		binary.Write(f, binary.LittleEndian, mod.NumCov)
		for pc, _ := range mod.Cover {
			binary.Write(f, binary.LittleEndian, pc)
		}
	}
}

func (mods *Kcov_config) Delete(raw []uint32) {
	for _, pc := range raw {
		addr := uint64(pc)
		if _, ok := mods.Mods[0].Cover[addr]; ok {
			delete(mods.Mods[0].Cover, addr)
			mods.Mods[0].NumCov -= 1
		}
	}
}
