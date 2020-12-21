package xdptool

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// See https://github.com/cilium/cilium/blob/master/pkg/bpf/bpf.go
// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
const (
	BPF_MAP_TYPE_UNSPEC = iota
	BPF_MAP_TYPE_HASH
	BPF_MAP_TYPE_ARRAY
	BPF_MAP_TYPE_PROG_ARRAY
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	BPF_MAP_TYPE_PERCPU_HASH
	BPF_MAP_TYPE_PERCPU_ARRAY
	BPF_MAP_TYPE_STACK_TRACE
	BPF_MAP_TYPE_CGROUP_ARRAY
	BPF_MAP_TYPE_LRU_HASH
	BPF_MAP_TYPE_LRU_PERCPU_HASH
	BPF_MAP_TYPE_LPM_TRIE
	BPF_MAP_TYPE_ARRAY_OF_MAPS
	BPF_MAP_TYPE_HASH_OF_MAPS
	BPF_MAP_TYPE_DEVMAP
	BPF_MAP_TYPE_SOCKMAP
	BPF_MAP_TYPE_CPUMAP
	BPF_MAP_TYPE_XSKMAP
	BPF_MAP_TYPE_SOCKHASH
	BPF_MAP_TYPE_CGROUP_STORAGE
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
)

// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
const (
	BPF_MAP_CREATE = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
	BPF_PROG_QUERY
	BPF_RAW_TRACEPOINT_OPEN
	BPF_BTF_LOAD
	BPF_BTF_GET_FD_BY_ID
	BPF_TASK_FD_QUERY
)

// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
const (
	BPF_ANY = iota
	BPF_NOEXIST
	BPF_EXIST
)

// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
const (
	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1
	BPF_F_NUMA_NODE     = 1 << 2
)

// Fd represents HASH_OF_MAPS value.
type Fd struct{ Fd uint32 }

// This struct must be in sync with union bpf_attr's anonymous struct
// used by the BPF_MAP_CREATE command
type bpfAttrCreateMap struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
	innerID    uint32
}

func CreateLPMtrieKey(s string) *net.IPNet {
	var ipnet *net.IPNet
	// Check if given address is CIDR
	if strings.Contains(s, "/") {
		_, ipnet, _ = net.ParseCIDR(s)
	} else {
		if strings.Contains(s, ":") {
			// IPv6
			_, ipnet, _ = net.ParseCIDR(s + "/128")
		} else {
			// IPv4
			_, ipnet, _ = net.ParseCIDR(s + "/32")
		}
	}
	return ipnet
}

func CreateMap(mapType int, keySize, valueSize, maxEntries, flags, innerID uint32) (int, error) {
	uba := bpfAttrCreateMap{
		uint32(mapType),
		keySize,
		valueSize,
		maxEntries,
		flags,
		innerID,
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_CREATE,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if err != 0 {
		return 0, fmt.Errorf("Unable to create map: %s", err)
	}
	return int(ret), nil
}

type bpfAttrMapOpElem struct {
	mapFd uint32
	pad0  [4]byte
	key   uint64
	value uint64 // union: value or next_key
	flags uint64
}

func UpdateElement(fd int, key, value unsafe.Pointer, flags uint64) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: uint64(flags),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return errors.New(fmt.Sprintf("Unable to update element for map with file descriptor %d: %s", fd, err))
	}

	return nil
}

func LookupElement(fd int, key, value unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return errors.New(fmt.Sprintf("Unable to lookup element in map with file descriptor %d: %s", fd, err))
	}

	return nil
}

func deleteElement(fd int, key unsafe.Pointer) (uintptr, syscall.Errno) {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	return ret, err
}

// DeleteElement deletes the map element with the given key.
func DeleteElement(fd int, key unsafe.Pointer) error {
	ret, err := deleteElement(fd, key)

	if ret != 0 || err != 0 {
		return errors.New(fmt.Sprintf("Unable to lookup element in map with file descriptor %d: %s", fd, err))
	}

	return nil
}

// GetNextKey stores, in nextKey, the next key after the key of the map in fd.
func GetNextKey(fd int, key, nextKey unsafe.Pointer) error {
	uba := bpfAttrMapOpElem{
		mapFd: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(nextKey)),
	}
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return errors.New(fmt.Sprintf("Unable to lookup element in map with file descriptor %d: %s", fd, err))
	}

	return nil
}

const BpfFsPath = "/sys/fs/bpf"

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_OBJ_*_ commands
type bpfAttrObjOp struct {
	pathname uint64
	fd       uint32
	pad0     [4]byte
}

// ObjPin stores the map's fd in pathname.
func ObjPin(fd int, pathname string) error {
	pathStr := C.CString(pathname)
	defer C.free(unsafe.Pointer(pathStr))
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
		fd:       uint32(fd),
	}

	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_PIN,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return errors.New(fmt.Sprintf("Unable to pin object with file descriptor %d to %s: %s", fd, pathname, err))
	}

	return nil
}

// ObjGet reads the pathname and returns the map's fd read.
func ObjGet(pathname string) (int, error) {
	pathStr := C.CString(pathname)
	defer C.free(unsafe.Pointer(pathStr))
	uba := bpfAttrObjOp{
		pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
	}

	fd, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_OBJ_GET,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if fd == 0 || err != 0 {
		return 0, &os.PathError{
			Op:   "Unable to get object",
			Err:  err,
			Path: pathname,
		}
	}

	return int(fd), nil
}

// // NewCollectionWithOptions creates a Collection from a specification.
// //
// // Only maps referenced by at least one of the programs are initialized.
// func NewCollectionWithOptions(spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions) (*ebpf.Collection, error) {
// 	maps := make(map[string]*ebpf.Map)
// 	for mapName, mapSpec := range spec.Maps {
// 		m, err := ebpf.NewMap(mapSpec)
// 		if err != nil {
// 			return nil, errors.Wrapf(err, "map %s", mapName)
// 		}
// 		maps[mapName] = m
// 	}

// 	progs := make(map[string]*ebpf.Program)
// 	for progName, origProgSpec := range spec.Programs {
// 		progSpec := origProgSpec.Copy()
// 		editor := ebpf.Edit(&progSpec.Instructions)

// 		// Rewrite any Symbol which is a valid Map.
// 		for sym := range editor.ReferenceOffsets {
// 			m, ok := maps[sym]
// 			if !ok {
// 				continue
// 			}

// 			// overwrite maps already rewritten
// 			if err := editor.RewriteMap(sym, m); err != nil {
// 				return nil, errors.Wrapf(err, "program %s", progName)
// 			}
// 		}

// 		prog, err := ebpf.NewProgramWithOptions(progSpec, opts.Programs)
// 		if err != nil {
// 			return nil, errors.Wrapf(err, "program %s", progName)
// 		}
// 		progs[progName] = prog
// 	}

// 	return &ebpf.Collection{
// 		progs,
// 		maps,
// 	}, nil
// }
