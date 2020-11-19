package srv6

import (
	"errors"
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/newtools/ebpf"
	"github.com/takehaya/srv6-gtp/xdptool"
)

type FunctionTableKey struct {
	Daddr [16]byte
}

type FunctionTable struct {
	Function uint8
}

type FunctionTablesMap struct {
	FD  int
	Map *ebpf.Map
}

func NewFunctionTable(coll *ebpf.Collection) (*FunctionTablesMap, error) {
	log.Println("%v", coll)
	m, ok := coll.Maps[STR_FunctionTable]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v not found", STR_FunctionTable))
	}
	return &FunctionTablesMap{
		FD:  m.FD(),
		Map: m,
	}, nil
}

func (m *FunctionTablesMap) Update(fn FunctionTable, ip [16]byte) error {
	entry := make([]FunctionTable, xdptool.PossibleCpus)
	for i := 0; i < xdptool.PossibleCpus; i++ {
		entry[i] = fn
	}

	key := FunctionTableKey{Daddr: ip}
	return xdptool.UpdateElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]), xdptool.BPF_ANY)
}

func (m *FunctionTablesMap) Get(ip [16]byte) (*FunctionTable, error) {
	key := FunctionTableKey{Daddr: ip}
	entry := make([]FunctionTable, xdptool.PossibleCpus)
	err := xdptool.LookupElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]))
	if err != nil {
		return nil, err
	}
	return &entry[0], nil
}

func (m *FunctionTablesMap) Delete(ip [16]byte) error {
	key := FunctionTableKey{Daddr: ip}
	return xdptool.DeleteElement(m.FD, unsafe.Pointer(&key))
}

func (m *FunctionTablesMap) List() ([]*FunctionTable, error) {
	functables := []*FunctionTable{}
	var key, nextKey FunctionTableKey
	for {
		entry := make([]FunctionTable, xdptool.PossibleCpus)
		err := xdptool.GetNextKey(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
		if err != nil {
			break
		}
		err = xdptool.LookupElement(m.FD, unsafe.Pointer(&nextKey), unsafe.Pointer(&entry[0]))
		if err != nil {
			return nil, fmt.Errorf("unable to lookup %s map: %s", STR_FunctionTable, err)
		}
		functables = append(functables, &entry[0])
		key = nextKey
	}
	return functables, nil
}

func (m *FunctionTablesMap) Pin() error {
	return xdptool.ObjPin(m.FD, FunctionTablePath)
}

func (m *FunctionTablesMap) Unpin() error {
	return os.Remove(FunctionTablePath)
}

func LoadFunctionTables() (*FunctionTablesMap, error) {
	m, err := ebpf.LoadPinnedMap(FunctionTablePath)
	if err != nil {
		return nil, err
	}
	return &FunctionTablesMap{FD: m.FD(), Map: m}, nil
}
