package srv6

import (
	"fmt"
	"log"
	"os"
	"unsafe"

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

// func (m *V6addrHeepMap) Get(iface) (*TxPort, error) {
// 	key := TxPortKey{Iface: iface}
// 	entry := make([]TxPort, xdptool.PossibleCpus)
// 	err := xdptool.LookupElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]))
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &entry[0], nil
// }

func (m *V6addrHeepMap) Delete(iface int) error {
	key := TxPortKey{Iface: iface}
	return xdptool.DeleteElement(m.FD, unsafe.Pointer(&key))
}

func (m *V6addrHeepMap) List() (map[TxPortKey]*TxPort, error) {
	txptables := map[TxPortKey]*TxPort{}
	var key, nextKey TxPortKey
	for {
		entry := make([]TxPort, xdptool.PossibleCpus)
		err := xdptool.GetNextKey(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
		if err != nil {
			break
		}
		err = xdptool.LookupElement(m.FD, unsafe.Pointer(&nextKey), unsafe.Pointer(&entry[0]))
		if err != nil {
			return nil, fmt.Errorf("unable to lookup %s map: %s", STR_TXPort, err)
		}
		txptables[nextKey] = &entry[0]
		key = nextKey
	}
	return txptables, nil
}

func (m *V6addrHeepMap) Pin() error {
	return xdptool.ObjPin(m.FD, TXPortPath)
}

func (m *V6addrHeepMap) Unpin() error {
	return os.Remove(TXPortPath)
}
