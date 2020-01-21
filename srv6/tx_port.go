
package srv6

import (
	
	"errors"
	"fmt"
	"unsafe"
	"log"
	"os"
	"github.com/newtools/ebpf"
	"github.com/takehaya/srv6-gtp/xdptool"

)

type TxPortKey struct {
	Iface int
}

type TxPort struct {
	Iface int
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

func (m *TxPortsMap) Update(txp TxPort, iface int) error {
	entry := make([]TxPort, xdptool.PossibleCpus)
	for i := 0; i < xdptool.PossibleCpus; i++ {
		entry[i] = txp
	}

	key := TxPortKey{Iface: iface}
	return xdptool.UpdateElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]), xdptool.BPF_ANY)
}


func (m *TxPortsMap) Get(iface int) (*TxPort, error) {
	key := TxPortKey{Iface: iface}
	entry := make([]TxPort, xdptool.PossibleCpus)
	err := xdptool.LookupElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]))
	if err != nil {
		return nil, err
	}
	return &entry[0], nil
}

func (m *TxPortsMap) Delete(iface int) error {
	key := TxPortKey{Iface: iface}
	return xdptool.DeleteElement(m.FD, unsafe.Pointer(&key))
}

func (m *TxPortsMap) List() (map[TxPortKey]*TxPort, error) {
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
			return nil, fmt.Errorf("unable to lookup %s map: %s",STR_TXPort ,err)
		}
		txptables[nextKey] = &entry[0]
		key = nextKey
	}
	return txptables, nil
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
