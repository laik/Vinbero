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

const MaxTxportDevice = 64

type TxPortKey struct {
	Iface uint32
}

type TxPort struct {
	Iface uint32
}

type TxPortsMap struct {
	FD  int
	Map *ebpf.Map
}

func NewTxPort(coll *ebpf.Collection) (*TxPortsMap, error) {
	log.Println("%v", coll)
	m, ok := coll.Maps[STR_TXPort]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v not found", STR_TXPort))
	}
	return &TxPortsMap{
		FD:  m.FD(),
		Map: m,
	}, nil
}

func MappingTxPort(m *ebpf.Map) *TxPortsMap {
	return &TxPortsMap{
		FD:  m.FD(),
		Map: m,
	}
}

func (m *TxPortsMap) Update(txp TxPort, iface int) error {
	key := TxPortKey{Iface: uint32(iface)}

	if err := m.Map.Put(key, txp); err != nil {
		return errors.WithMessage(err, "Can't put function table map")
	}
	return nil
}

func (m *TxPortsMap) Get(iface int) (*TxPort, error) {
	key := TxPortKey{Iface: uint32(iface)}
	entry := make([]TxPort, xdptool.PossibleCpus)
	err := xdptool.LookupElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]))
	if err != nil {
		return nil, err
	}
	return &entry[0], nil
}

func (m *TxPortsMap) Pin() error {
	return xdptool.ObjPin(m.FD, TXPortPath)
}

func (m *TxPortsMap) Unpin() error {
	return os.Remove(TXPortPath)
}

func LoadTxPort() (*TxPortsMap, error) {
	m, err := ebpf.LoadPinnedMap(TXPortPath)
	if err != nil {
		return nil, err
	}
	return &TxPortsMap{FD: m.FD(), Map: m}, nil
}
