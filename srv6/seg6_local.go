// https://github.com/vishvananda/netlink/blob/master/nl/seg6local_linux.go
package srv6

import ()

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
	SEG6_LOCAL_ACTION_T_M_GTP4_E               // 15

	__SEG6_LOCAL_ACTION_MAX
)
const (
	SEG6_LOCAL_ACTION_MAX = __SEG6_LOCAL_ACTION_MAX - 1
)

// Helper functions
func SEG6LocalActionString(action int) string {
	switch action {
	case SEG6_LOCAL_ACTION_END:
		return "End"
	case SEG6_LOCAL_ACTION_END_X:
		return "End.X"
	case SEG6_LOCAL_ACTION_END_T:
		return "End.T"
	case SEG6_LOCAL_ACTION_END_DX2:
		return "End.DX2"
	case SEG6_LOCAL_ACTION_END_DX6:
		return "End.DX6"
	case SEG6_LOCAL_ACTION_END_DX4:
		return "End.DX4"
	case SEG6_LOCAL_ACTION_END_DT6:
		return "End.DT6"
	case SEG6_LOCAL_ACTION_END_DT4:
		return "End.DT4"
	case SEG6_LOCAL_ACTION_END_B6:
		return "End.B6"
	case SEG6_LOCAL_ACTION_END_B6_ENCAPS:
		return "End.B6.Encaps"
	case SEG6_LOCAL_ACTION_END_BM:
		return "End.BM"
	case SEG6_LOCAL_ACTION_END_S:
		return "End.S"
	case SEG6_LOCAL_ACTION_END_AS:
		return "End.AS"
	case SEG6_LOCAL_ACTION_END_AM:
		return "End.AM"
	case SEG6_LOCAL_ACTION_T_M_GTP4_E:
		return "T.M.GTP4.E"
	}
	
	return "unknown"
}

// Helper functions
func SEG6LocalActionEnum(name string) uint8 {
	switch name {
	case "SEG6_LOCAL_ACTION_END":
		return SEG6_LOCAL_ACTION_END
	case "SEG6_LOCAL_ACTION_END_X":
		return SEG6_LOCAL_ACTION_END_X
	case "SEG6_LOCAL_ACTION_END_T":
		return SEG6_LOCAL_ACTION_END_T
	case "SEG6_LOCAL_ACTION_END_DX2":
		return SEG6_LOCAL_ACTION_END_DX2
	case "SEG6_LOCAL_ACTION_END_DX6":
		return SEG6_LOCAL_ACTION_END_DX6
	case "SEG6_LOCAL_ACTION_END_DX4":
		return SEG6_LOCAL_ACTION_END_DX4
	case "SEG6_LOCAL_ACTION_END_DT6":
		return SEG6_LOCAL_ACTION_END_DT6
	case "SEG6_LOCAL_ACTION_END_DT4":
		return SEG6_LOCAL_ACTION_END_DT4
	case "SEG6_LOCAL_ACTION_END_B6":
		return SEG6_LOCAL_ACTION_END_B6
	case "SEG6_LOCAL_ACTION_END_B6_ENCAPS":
		return SEG6_LOCAL_ACTION_END_B6_ENCAPS
	case "SEG6_LOCAL_ACTION_END_BM":
		return SEG6_LOCAL_ACTION_END_BM
	case "SEG6_LOCAL_ACTION_END_S":
		return SEG6_LOCAL_ACTION_END_S
	case "SEG6_LOCAL_ACTION_END_AS":
		return SEG6_LOCAL_ACTION_END_AS
	case "SEG6_LOCAL_ACTION_END_AM":
		return SEG6_LOCAL_ACTION_END_AM
	case "SEG6_LOCAL_ACTION_T_M_GTP4_E":
		return SEG6_LOCAL_ACTION_T_M_GTP4_E
	}
	
	return __SEG6_LOCAL_ACTION_MAX
}
