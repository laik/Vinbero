// https://github.com/vishvananda/netlink/blob/master/nl/seg6local_linux.go
package srv6

import "fmt"

// seg6local parameters
const (
	SEG6_LOCAL_UNSPEC = iota
	SEG6_LOCAL_ACTION
	SEG6_LOCAL_SRH
	SEG6_LOCAL_TABLE
	SEG6_LOCAL_NH4
	SEG6_LOCAL_NH6
	SEG6_LOCAL_IIF
	SEG6_LOCAL_OIF
	__SEG6_LOCAL_MAX
)
const (
	SEG6_LOCAL_MAX = __SEG6_LOCAL_MAX
)

// seg6End Functions Flaver
const (
	SEG6_LOCAL_FLAVER_NONE = iota + 1 // 1
	SEG6_LOCAL_FLAVER_PSP
	SEG6_LOCAL_FLAVER_USP
	SEG6_LOCAL_FLAVER_USD
	__SEG6_LOCAL_FLAVER_MAX
)
const (
	SEG6_LOCAL_FLAVER_MAX = __SEG6_LOCAL_FLAVER_MAX
)

// Helper functions
func Seg6LocalFlaverString(action int) (string, error) {
	switch action {
	case SEG6_LOCAL_FLAVER_NONE:
		return "NONE", nil
	case SEG6_LOCAL_FLAVER_PSP:
		return "PSP", nil
	case SEG6_LOCAL_FLAVER_USP:
		return "USP", nil
	case SEG6_LOCAL_FLAVER_USD:
		return "USD", nil
	}

	return "", fmt.Errorf("%d action number not match", action)
}

// Helper functions
func Seg6LocalFlaverInt(name string) (uint32, error) {
	switch name {
	case "NONE":
		return SEG6_LOCAL_FLAVER_NONE, nil
	case "PSP":
		return SEG6_LOCAL_FLAVER_PSP, nil
	case "USP":
		return SEG6_LOCAL_FLAVER_USP, nil
	case "USD":
		return SEG6_LOCAL_FLAVER_USD, nil
	}

	return 0, fmt.Errorf("%d action not match", name)
}

// seg6local actions
const (
	SEG6_LOCAL_ACTION_END           = iota + 1 // 1
	SEG6_LOCAL_ACTION_END_X                    // 2
	SEG6_LOCAL_ACTION_END_T                    // 3
	SEG6_LOCAL_ACTION_END_DX2                  // 4
	SEG6_LOCAL_ACTION_END_DX6                  // 5
	SEG6_LOCAL_ACTION_END_DX4                  // 6
	SEG6_LOCAL_ACTION_END_DT6                  // 7
	SEG6_LOCAL_ACTION_END_DT4                  // 8
	SEG6_LOCAL_ACTION_END_B6                   // 9
	SEG6_LOCAL_ACTION_END_B6_ENCAPS            // 10
	SEG6_LOCAL_ACTION_END_BM                   // 11
	SEG6_LOCAL_ACTION_END_S                    // 12
	SEG6_LOCAL_ACTION_END_AS                   // 13
	SEG6_LOCAL_ACTION_END_AM                   // 14
	SEG6_LOCAL_ACTION_END_M_GTP6_E
	SEG6_LOCAL_ACTION_END_M_GTP4_E

	__SEG6_LOCAL_ACTION_MAX
)
const (
	SEG6_LOCAL_ACTION_MAX = __SEG6_LOCAL_ACTION_MAX - 1
)

// Helper functions
func Seg6LocalActionString(action int) (string, error) {
	switch action {
	case SEG6_LOCAL_ACTION_END:
		return "End", nil
	case SEG6_LOCAL_ACTION_END_X:
		return "End.X", nil
	case SEG6_LOCAL_ACTION_END_T:
		return "End.T", nil
	case SEG6_LOCAL_ACTION_END_DX2:
		return "End.DX2", nil
	case SEG6_LOCAL_ACTION_END_DX6:
		return "End.DX6", nil
	case SEG6_LOCAL_ACTION_END_DX4:
		return "End.DX4", nil
	case SEG6_LOCAL_ACTION_END_DT6:
		return "End.DT6", nil
	case SEG6_LOCAL_ACTION_END_DT4:
		return "End.DT4", nil
	case SEG6_LOCAL_ACTION_END_B6:
		return "End.B6", nil
	case SEG6_LOCAL_ACTION_END_B6_ENCAPS:
		return "End.B6.Encaps", nil
	case SEG6_LOCAL_ACTION_END_BM:
		return "End.BM", nil
	case SEG6_LOCAL_ACTION_END_S:
		return "End.S", nil
	case SEG6_LOCAL_ACTION_END_AS:
		return "End.AS", nil
	case SEG6_LOCAL_ACTION_END_AM:
		return "End.AM", nil
	case SEG6_LOCAL_ACTION_END_M_GTP6_E:
		return "End.M.GTP6.E", nil
	case SEG6_LOCAL_ACTION_END_M_GTP4_E:
		return "End.M.GTP4.E", nil
	}
	return "", fmt.Errorf("%d action number not match", action)
}

// Helper functions
func Seg6LocalActionInt(name string) (uint32, error) {
	switch name {
	case "SEG6_LOCAL_ACTION_END":
		return SEG6_LOCAL_ACTION_END, nil
	case "SEG6_LOCAL_ACTION_END_X":
		return SEG6_LOCAL_ACTION_END_X, nil
	case "SEG6_LOCAL_ACTION_END_T":
		return SEG6_LOCAL_ACTION_END_T, nil
	case "SEG6_LOCAL_ACTION_END_DX2":
		return SEG6_LOCAL_ACTION_END_DX2, nil
	case "SEG6_LOCAL_ACTION_END_DX6":
		return SEG6_LOCAL_ACTION_END_DX6, nil
	case "SEG6_LOCAL_ACTION_END_DX4":
		return SEG6_LOCAL_ACTION_END_DX4, nil
	case "SEG6_LOCAL_ACTION_END_DT6":
		return SEG6_LOCAL_ACTION_END_DT6, nil
	case "SEG6_LOCAL_ACTION_END_DT4":
		return SEG6_LOCAL_ACTION_END_DT4, nil
	case "SEG6_LOCAL_ACTION_END_B6":
		return SEG6_LOCAL_ACTION_END_B6, nil
	case "SEG6_LOCAL_ACTION_END_B6_ENCAPS":
		return SEG6_LOCAL_ACTION_END_B6_ENCAPS, nil
	case "SEG6_LOCAL_ACTION_END_BM":
		return SEG6_LOCAL_ACTION_END_BM, nil
	case "SEG6_LOCAL_ACTION_END_S":
		return SEG6_LOCAL_ACTION_END_S, nil
	case "SEG6_LOCAL_ACTION_END_AS":
		return SEG6_LOCAL_ACTION_END_AS, nil
	case "SEG6_LOCAL_ACTION_END_AM":
		return SEG6_LOCAL_ACTION_END_AM, nil
	case "SEG6_LOCAL_ACTION_END_M_GTP6_E":
		return SEG6_LOCAL_ACTION_END_M_GTP6_E, nil
	case "SEG6_LOCAL_ACTION_END_M_GTP4_E":
		return SEG6_LOCAL_ACTION_END_M_GTP4_E, nil
	}
	return 0, fmt.Errorf("%d action not match", name)
}
