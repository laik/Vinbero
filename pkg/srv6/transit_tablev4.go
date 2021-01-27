package srv6

import (
	"fmt"
	"os"

	"github.com/pkg/errors"

	"github.com/cilium/ebpf"
	"github.com/takehaya/vinbero/pkg/xdptool"
)

type TransitTablev4Key struct {
	Prefixlen uint32
	Daddr     [4]byte
}

type TransitTablev4 struct {
	Saddr         [16]byte
	Daddr         [16]byte
	SPrefixlen    uint32
	DPrefixlen    uint32
	SegmentLength uint32
	Action        uint32
	Segments      [MAX_SEGMENTS][16]byte
}

type TransitTablev4sMap struct {
	FD  int
	Map *ebpf.Map
}

func NewTransitTablev4(coll *ebpf.Collection) (*TransitTablev4sMap, error) {
	m, ok := coll.Maps[STR_TransitTablev4]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v not found", STR_TransitTablev4))
	}
	return &TransitTablev4sMap{
		FD:  m.FD(),
		Map: m,
	}, nil
}

func MappingTransitTablev4(m *ebpf.Map) *TransitTablev4sMap {
	return &TransitTablev4sMap{
		FD:  m.FD(),
		Map: m,
	}
}

func (m *TransitTablev4sMap) Update(v4table TransitTablev4, ip [4]byte, prefix uint32) error {
	key := TransitTablev4Key{
		Daddr:     ip,
		Prefixlen: prefix,
	}
	if err := m.Map.Put(key, v4table); err != nil {
		return errors.WithMessage(err, "Can't put function table map")
	}
	return nil
}

func (m *TransitTablev4sMap) Pin() error {
	return xdptool.ObjPin(m.FD, TransitTablev4Path)
}

func (m *TransitTablev4sMap) Unpin() error {
	return os.Remove(TransitTablev4Path)
}

func LoadTransitTablev4() (*TransitTablev4sMap, error) {
	m, err := ebpf.LoadPinnedMap(TransitTablev4Path)
	if err != nil {
		return nil, err
	}
	return &TransitTablev4sMap{FD: m.FD(), Map: m}, nil
}
