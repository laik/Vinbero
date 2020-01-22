
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

const MAX_SEGMENTS = 5

type TransitTablev4Key struct {
	Daddr [4]byte
}

type TransitTablev4 struct {
	Action	   	   uint8
	Segment_length uint32
	Saddr		   [16]byte
	Segments	   [][16]byte
}

type TransitTablev4sMap struct {
	FD  int
	Map *ebpf.Map
}

func NewTransitTablev4(coll *ebpf.Collection) (*TransitTablev4sMap, error) {
	log.Println("%v", coll)
	m, ok := coll.Maps[STR_TransitTablev4]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%v not found", STR_TransitTablev4))
	}
	return &TransitTablev4sMap{
		FD:  m.FD(),
		Map: m,
	}, nil
}

func (m *TransitTablev4sMap) Update(v4table TransitTablev4, ip [4]byte) error {
	entry := make([]TransitTablev4, xdptool.PossibleCpus)
	for i := 0; i < xdptool.PossibleCpus; i++ {
		entry[i] = v4table
	}

	key := TransitTablev4Key{Daddr: ip}
	return xdptool.UpdateElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]), xdptool.BPF_ANY)
}


func (m *TransitTablev4sMap) Get(ip [4]byte) (*TransitTablev4, error) {
	key := TransitTablev4Key{Daddr: ip}
	entry := make([]TransitTablev4, xdptool.PossibleCpus)
	err := xdptool.LookupElement(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&entry[0]))
	if err != nil {
		return nil, err
	}
	return &entry[0], nil
}

func (m *TransitTablev4sMap) Delete(ip [4]byte) error {
	key := TransitTablev4Key{Daddr: ip}
	return xdptool.DeleteElement(m.FD, unsafe.Pointer(&key))
}

func (m *TransitTablev4sMap) List() ([]*TransitTablev4, error) {
	v4tables := []*TransitTablev4{}
	var key, nextKey TransitTablev4Key
	for {
		entry := make([]TransitTablev4, xdptool.PossibleCpus)
		err := xdptool.GetNextKey(m.FD, unsafe.Pointer(&key), unsafe.Pointer(&nextKey))
		if err != nil {
			break
		}
		err = xdptool.LookupElement(m.FD, unsafe.Pointer(&nextKey), unsafe.Pointer(&entry[0]))
		if err != nil {
			return nil, fmt.Errorf("unable to lookup %s map: %s",STR_TransitTablev4 ,err)
		}
		v4tables = append(v4tables, &entry[0])
		key = nextKey
	}
	return v4tables, nil
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
