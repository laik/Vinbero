package srv6

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/cilium/ebpf"
	"github.com/takehaya/vinbero/pkg/xdptool"
)

type FunctionTableKey struct {
	Prefixlen uint32
	Daddr     [16]uint8
}

type FunctionTable struct {
	StartSaddr [16]uint8
	Nexthop    [16]uint8
	Function   uint32
	Flaver     uint32
	V4AddrPos  uint32
}

type FunctionTablesMap struct {
	FD  int
	Map *ebpf.Map
}

func NewFunctionTable(coll *ebpf.Collection) (*FunctionTablesMap, error) {
	m, ok := coll.Maps[STR_FunctionTable]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v not found", STR_FunctionTable))
	}
	return &FunctionTablesMap{
		FD:  m.FD(),
		Map: m,
	}, nil
}

func MappingFunctionTable(m *ebpf.Map) *FunctionTablesMap {
	return &FunctionTablesMap{
		FD:  m.FD(),
		Map: m,
	}
}

func (m *FunctionTablesMap) Update(fn FunctionTable, ip [16]byte, prefix uint32) error {
	key := FunctionTableKey{
		Daddr:     ip,
		Prefixlen: prefix,
	}
	if err := m.Map.Put(key, fn); err != nil {
		return errors.WithMessage(err, "Can't put function table map")
	}
	return nil
}

func (m *FunctionTablesMap) Get(ip [16]byte, prefix uint32) (*FunctionTable, error) {
	key := FunctionTableKey{
		Daddr:     ip,
		Prefixlen: prefix,
	}
	entry := make([]FunctionTable, xdptool.PossibleCpus)
	err := xdptool.LookupElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]))
	if err != nil {
		return nil, err
	}
	return &entry[0], nil
}

func (m *FunctionTablesMap) Delete(ip [16]byte, prefix uint32) error {
	key := FunctionTableKey{
		Daddr:     ip,
		Prefixlen: prefix,
	}
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
