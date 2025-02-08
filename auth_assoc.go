package wifi

import (
	"encoding/binary"
	"fmt"
	"net"
)

type AuthResp struct {
	ByteOrder binary.ByteOrder
	// MAC Header
	FC       uint16 // Frame Control - length 2
	Duration uint16 // length 2
	DA       net.HardwareAddr
	SA       net.HardwareAddr
	BSSID    net.HardwareAddr
	SeqCtlr  uint16 // len 2 -> Fragment number (4 bits) + Sequence number (12 bits)

	Algorithm uint16
	Sequence  uint16
	Status    uint16
}

func (b AuthResp) Serialize() []byte {
	data := make([]byte, 0)

	fc := make([]byte, 2)
	b.ByteOrder.PutUint16(fc, b.FC)
	data = append(data, fc...)

	duration := make([]byte, 2)
	b.ByteOrder.PutUint16(duration, b.Duration)
	data = append(data, duration...)

	data = append(data, b.DA...)
	data = append(data, b.SA...)
	data = append(data, b.BSSID...)

	seqCtrl := make([]byte, 2)
	b.ByteOrder.PutUint16(seqCtrl, b.SeqCtlr)
	data = append(data, seqCtrl...)

	algo := make([]byte, 2)
	b.ByteOrder.PutUint16(algo, b.Algorithm)
	data = append(data, algo...)

	seq := make([]byte, 2)
	b.ByteOrder.PutUint16(seq, b.Sequence)
	data = append(data, seq...)

	status := make([]byte, 2)
	b.ByteOrder.PutUint16(status, b.Status)
	data = append(data, status...)

	return data
}

type AssocResp struct {
	ByteOrder binary.ByteOrder
	// MAC Header
	FC       uint16 // Frame Control - length 2
	Duration uint16 // length 2
	DA       net.HardwareAddr
	SA       net.HardwareAddr
	BSSID    net.HardwareAddr
	SeqCtlr  uint16 // len 2 -> Fragment number (4 bits) + Sequence number (12 bits)

	CapabilityInfo uint16
	Status         uint16
	AID            uint16

	SupportedRates         []byte
	ExtendedSupportedRates []byte
	ExtendedCapabilties    []byte
	BSSMaxIdlePeriod       []byte
}

// rate in Mbps
func (b *AssocResp) AppendSupportedRateIE(mandatory bool, rateMbps float64) error {
	if b.SupportedRates == nil {
		b.SupportedRates = make([]byte, 0)
	}

	var mandatoryBit byte = 0
	if mandatory {
		mandatoryBit = 0x80
	}
	val := mandatoryBit | byte(rateMbps*2)

	if len(b.SupportedRates) == 2 {
		return fmt.Errorf("invalid supported rate filed")
	}
	if len(b.SupportedRates) == 0 { // no previous supported rates configured
		b.SupportedRates = append(b.SupportedRates, 0x1, 0x1, val) // element ID, length
		return nil
	}

	if len(b.SupportedRates) != int(b.SupportedRates[1]+2) {
		return fmt.Errorf("invalid supported rate filed - invalid lengths")
	}

	// increase the current length
	b.SupportedRates[1]++
	// append new supported rate
	b.SupportedRates = append(b.SupportedRates, val)

	return nil
}

// rate in Mbps
func (b *AssocResp) AppendExtendedSupportedRateIE(mandatory bool, rateMbps uint) error {
	if b.ExtendedSupportedRates == nil {
		b.ExtendedSupportedRates = make([]byte, 0)
	}

	var mandatoryBit byte = 0
	if mandatory {
		mandatoryBit = 0x80
	}
	val := mandatoryBit | byte(rateMbps*2)

	if len(b.ExtendedSupportedRates) == 2 {
		return fmt.Errorf("invalid supported rate filed")
	}
	if len(b.ExtendedSupportedRates) == 0 { // no previous supported rates configured
		b.ExtendedSupportedRates = append(b.ExtendedSupportedRates, 0x32, 0x1, val) // element ID, length
		return nil
	}

	if len(b.ExtendedSupportedRates) != int(b.ExtendedSupportedRates[1]+2) {
		return fmt.Errorf("invalid supported rate filed - invalid lengths")
	}

	// increase the current length
	b.ExtendedSupportedRates[1]++
	// append new supported rate
	b.ExtendedSupportedRates = append(b.ExtendedSupportedRates, val)

	return nil
}

func (b *AssocResp) SetExtendedCapabilties() error {
	b.ExtendedCapabilties = make([]byte, 0)
	b.ExtendedCapabilties = append(b.ExtendedCapabilties, 0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40) // element ID, length, Extended capabilites
	return nil
}

func (b *AssocResp) SetBSSMaxIdlePeriod() error {
	b.BSSMaxIdlePeriod = make([]byte, 0)
	b.BSSMaxIdlePeriod = append(b.BSSMaxIdlePeriod, 0x5A, 0x3, 0x24, 0x01, 0x00) // element ID, length, BSS Max Idle Period
	return nil
}

func (b AssocResp) Serialize() []byte {
	data := make([]byte, 0)

	fc := make([]byte, 2)
	b.ByteOrder.PutUint16(fc, b.FC)
	data = append(data, fc...)

	duration := make([]byte, 2)
	b.ByteOrder.PutUint16(duration, b.Duration)
	data = append(data, duration...)

	data = append(data, b.DA...)
	data = append(data, b.SA...)
	data = append(data, b.BSSID...)

	seqCtrl := make([]byte, 2)
	b.ByteOrder.PutUint16(seqCtrl, b.SeqCtlr)
	data = append(data, seqCtrl...)

	cap := make([]byte, 2)
	b.ByteOrder.PutUint16(cap, b.CapabilityInfo)
	data = append(data, cap...)

	status := make([]byte, 2)
	b.ByteOrder.PutUint16(status, b.Status)
	data = append(data, status...)

	aid := make([]byte, 2)
	b.ByteOrder.PutUint16(aid, b.AID)
	data = append(data, aid...)

	return data
}
