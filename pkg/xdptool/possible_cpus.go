package xdptool

import (
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
)

const (
	// possibleCPUsFileLength matches the buffer size for CPUs.
	// Reference bpf_num_possible_cpus from
	// https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/tree/tools/testing/selftests/bpf/bpf_util.h
	possibleCPUsFileLength = 128
)

var (
	PossibleCpus int
)

func PossibleCpuInit() {
	calculateNumCpus()
}

// calculateNumCpus replicates the bpf linux helper equivalent `bpf_num_possible_cpus`
// to find total number of possible CPUs i.e CPUs that have been allocated
// resources and can be brought online if they are present.
// Reference bpf_num_possible_cpus from
// https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/tree/tools/testing/selftests/bpf/bpf_util.h
// https://github.com/cilium/cilium/blob/master/pkg/maps/metricsmap/metricsmap.go
func calculateNumCpus() {
	var start, end int

	file, err := os.Open("/sys/devices/system/cpu/possible")
	if err != nil {
		panic(errors.Wrap(err, "unable to open sysfs to get CPU count"))
	}
	defer file.Close()

	data := make([]byte, possibleCPUsFileLength)
	for {
		_, err := file.Read(data)
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(errors.Wrap(err, "unable to open sysfs to get CPU count"))
		}
		n, err := fmt.Sscanf(string(data), "%d-%d", &start, &end)
		if err != nil {
			panic(errors.Wrap(err, "unable to open sysfs to get CPU count"))
		}
		if n == 0 {
			panic(errors.Wrap(err, "failed to retrieve number of possible CPUs!"))
		} else if n == 1 {
			end = start
		}
		if start == 0 {
			PossibleCpus = end + 1
		} else {
			PossibleCpus = 0
		}
		break
	}
}
