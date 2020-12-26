package config

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/takehaya/vinbero/pkg/srv6"
	"github.com/takehaya/vinbero/pkg/utils"
)

func (c *Config) Validate() error {
	var err error
	err = c.InternalConfig.Validate()
	if err != nil {
		return errors.WithMessage(err, "failed Internal Config")
	}

	err = c.Setting.Validate()
	if err != nil {
		return errors.WithMessage(err, "failed Setting Config")
	}
	return nil
}

func (c *InternalConfig) Validate() error {
	if len(c.Devices) <= 0 {
		return fmt.Errorf("Device is not registered\n")
	}
	return nil
}

func (c *SettingConfig) Validate() error {
	for _, fn := range c.Functions {
		err := fn.Validate()
		if err != nil {
			return errors.WithMessage(err, "failed Function Config")
		}
	}
	for _, t4 := range c.Transitv4 {
		err := t4.Validate()
		if err != nil {
			return errors.WithMessage(err, "failed Function Config")
		}
	}
	return nil
}

func (c *FunctionsConfig) Validate() error {
	actId, err := srv6.Seg6LocalActionInt(c.Action)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("%v not found", c.Action))
	}

	if c.TriggerAddr == "" {
		return fmt.Errorf("TriggerAddr not found")
	}

	checkSaddr := []int{
		srv6.SEG6_LOCAL_ACTION_END_DX6,
		srv6.SEG6_LOCAL_ACTION_END_DX4,
		srv6.SEG6_LOCAL_ACTION_END_M_GTP6_E,
		srv6.SEG6_LOCAL_ACTION_END_M_GTP4_E,
	}
	if utils.IntArrayContains(checkSaddr, int(actId)) && c.SAddr == "" {
		return fmt.Errorf("actionSrcAddr not found")
	} else if !utils.IntArrayContains(checkSaddr, int(actId)) && c.SAddr != "" {
		return fmt.Errorf("Do not throw in invalid configurations.Is actionSrcAddr")
	}

	checkDaddr := []int{}
	if utils.IntArrayContains(checkDaddr, int(actId)) && c.DAddr == "" {
		return fmt.Errorf("actionDstAddr not found")
	} else if !utils.IntArrayContains(checkDaddr, int(actId)) && c.DAddr != "" {
		return fmt.Errorf("Do not throw in invalid configurations.Is actionDstAddr")
	}

	checkNexthop := []int{
		srv6.SEG6_LOCAL_ACTION_END_DX6,
		srv6.SEG6_LOCAL_ACTION_END_DX4,
	}
	if utils.IntArrayContains(checkNexthop, int(actId)) && c.Nexthop == "" {
		return fmt.Errorf("Nexthop not found")
	} else if !utils.IntArrayContains(checkNexthop, int(actId)) && c.Nexthop != "" {
		return fmt.Errorf("Do not throw in invalid configurations.Is Nexthop")
	}

	checkFlaver := []int{
		srv6.SEG6_LOCAL_ACTION_END,
		srv6.SEG6_LOCAL_ACTION_END_X,
		srv6.SEG6_LOCAL_ACTION_END_T,
	}
	if utils.IntArrayContains(checkFlaver, int(actId)) && c.Flaver == "" {
		return fmt.Errorf("checkFlaver not found")
	} else if !utils.IntArrayContains(checkNexthop, int(actId)) && c.Nexthop != "" {
		return fmt.Errorf("Do not throw in invalid configurations.Is checkFlaver")
	}

	checkV4AddrPos := []int{
		srv6.SEG6_LOCAL_ACTION_END_M_GTP4_E,
	}
	if utils.IntArrayContains(checkV4AddrPos, int(actId)) && c.V4AddrPos == "" {
		return fmt.Errorf("v4AddrPos not found")
	} else if !utils.IntArrayContains(checkV4AddrPos, int(actId)) && c.V4AddrPos != "" {
		return fmt.Errorf("Do not throw in invalid configurations.Is v4AddrPos")
	}

	return nil
}

func (c *Transitv4Config) Validate() error {
	actId, err := srv6.Seg6EncapModeInt(c.Action)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("%v not found", c.Action))
	}
	if c.TriggerAddr == "" {
		return fmt.Errorf("TriggerAddr not found")
	}

	checkSaddr := []int{
		srv6.SEG6_IPTUN_MODE_ENCAP,
		srv6.SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D,
	}
	if utils.IntArrayContains(checkSaddr, int(actId)) && c.SAddr == "" {
		return fmt.Errorf("actionSrcAddr not found")
	}

	checkDaddr := []int{
		srv6.SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D,
	}
	if utils.IntArrayContains(checkDaddr, int(actId)) && c.DAddr == "" {
		return fmt.Errorf("actionDstAddr not found")
	}

	checkSegments := []int{
		srv6.SEG6_IPTUN_MODE_ENCAP,
	}
	if utils.IntArrayContains(checkSegments, int(actId)) && len(c.Segments) == 0 {
		return fmt.Errorf("Segments not found")
	}

	if srv6.MAX_SEGMENTS < len(c.Segments) {
		return fmt.Errorf("Max Segments Entry over. %v/%v", len(c.Segments), srv6.MAX_SEGMENTS)
	} else if len(c.Segments) == 0 && actId != srv6.SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D {
		return fmt.Errorf("Length Entry empty. %v/%v", c.Segments, srv6.MAX_SEGMENTS)
	}

	// reject
	if actId == srv6.SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D {
		if srv6.MAX_SEGMENTS-1 < len(c.Segments) {
			return fmt.Errorf("Max Segments Entry over. SEG6_IPTUN_MODE_ENCAP_H_M_GTP4_D is maxsize(%v) %v", srv6.MAX_SEGMENTS-1, len(c.Segments))
		}
	}

	return nil
}

func (c *Transitv6Config) Validate() error {
	actId, err := srv6.Seg6EncapModeInt(c.Action)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("%v not found", c.Action))
	}
	if c.TriggerAddr == "" {
		return fmt.Errorf("TriggerAddr not found")
	}

	checkSaddr := []int{
		srv6.SEG6_IPTUN_MODE_ENCAP,
		srv6.SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D,
	}
	if utils.IntArrayContains(checkSaddr, int(actId)) && c.SAddr == "" {
		return fmt.Errorf("actionSrcAddr not found")
	}

	checkDaddr := []int{
		srv6.SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D,
	}
	if utils.IntArrayContains(checkDaddr, int(actId)) && c.DAddr == "" {
		return fmt.Errorf("actionDstAddr not found")
	}

	checkSegments := []int{
		srv6.SEG6_IPTUN_MODE_ENCAP,
	}
	if utils.IntArrayContains(checkSegments, int(actId)) && c.SAddr == "" {
		return fmt.Errorf("Segments not found")
	}

	if srv6.MAX_SEGMENTS < len(c.Segments) {
		return fmt.Errorf("Max Segments Entry over. %v/%v", len(c.Segments), srv6.MAX_SEGMENTS)
	} else if len(c.Segments) == 0 &&
		actId != srv6.SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D &&
		actId != srv6.SEG6_IPTUN_MODE_ENCAP_T_M_GTP6_D_Di {
		return fmt.Errorf("Length Entry empty. %v/%v", c.Segments, srv6.MAX_SEGMENTS)
	}
	return nil
}
