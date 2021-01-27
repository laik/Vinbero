package srv6

import (
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"

	"github.com/cilium/ebpf"
	"github.com/takehaya/vinbero/pkg/xdptool"
)

type V6addrHeep struct {
	Saddr [16]byte
	Daddr [16]byte
}

type V6addrHeepMap struct {
	FD  int
	Map *ebpf.Map
}

func NewV6addrHeep(coll *ebpf.Collection) (*V6addrHeepMap, error) {
	log.Println("%v", coll)
	m, ok := coll.Maps[STR_V6addrHeep]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v not found", STR_V6addrHeep))
	}
	return &V6addrHeepMap{
		FD:  m.FD(),
		Map: m,
	}, nil
}

func MappingV6addrHeep(m *ebpf.Map) *V6addrHeepMap {
	return &V6addrHeepMap{
		FD:  m.FD(),
		Map: m,
	}
}

func (m *V6addrHeepMap) Update(heep []*V6addrHeep, vkey int) error {

	if err := m.Map.Put(uint32(vkey), heep); err != nil {
		return errors.WithMessage(err, "Can't put v6addr map")
	}
	return nil
}

func (m *V6addrHeepMap) Pin() error {
	return xdptool.ObjPin(m.FD, TXPortPath)
}

func (m *V6addrHeepMap) Unpin() error {
	return os.Remove(TXPortPath)
}
