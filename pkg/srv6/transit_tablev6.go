package srv6

import (
	"fmt"
	"os"

	"github.com/pkg/errors"

	"github.com/cilium/ebpf"
	"github.com/takehaya/vinbero/pkg/xdptool"
)

type TransitTablev6Key struct {
	Prefixlen uint32
	Daddr     [16]byte
}

type TransitTablev6 struct {
	Saddr         [16]byte
	Daddr         [16]byte
	SPrefixlen    uint32
	DPrefixlen    uint32
	SegmentLength uint32
	Action        uint32
	Segments      [MAX_SEGMENTS][16]byte
}

type TransitTablev6sMap struct {
	FD  int
	Map *ebpf.Map
}

func NewTransitTablev6(coll *ebpf.Collection) (*TransitTablev6sMap, error) {
	m, ok := coll.Maps[STR_TransitTablev6]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v not found", STR_TransitTablev4))
	}
	return &TransitTablev6sMap{
		FD:  m.FD(),
		Map: m,
	}, nil
}

func MappingTransitTablev6(m *ebpf.Map) *TransitTablev6sMap {
	return &TransitTablev6sMap{
		FD:  m.FD(),
		Map: m,
	}
}

func (m *TransitTablev6sMap) Update(v4table TransitTablev6, ip [16]byte, prefix uint32) error {
	key := TransitTablev6Key{
		Daddr:     ip,
		Prefixlen: prefix,
	}
	if err := m.Map.Put(key, v4table); err != nil {
		return errors.WithMessage(err, "Can't put function table map")
	}
	return nil
}

func (m *TransitTablev6sMap) Pin() error {
	return xdptool.ObjPin(m.FD, TransitTablev6Path)
}

func (m *TransitTablev6sMap) Unpin() error {
	return os.Remove(TransitTablev6Path)
}

func LoadTransitTablev6() (*TransitTablev6sMap, error) {
	m, err := ebpf.LoadPinnedMap(TransitTablev6Path)
	if err != nil {
		return nil, err
	}
	return &TransitTablev6sMap{FD: m.FD(), Map: m}, nil
}
