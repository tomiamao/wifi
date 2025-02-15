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

	data = append(data, b.SupportedRates...)
	data = append(data, b.ExtendedSupportedRates...)
	data = append(data, b.ExtendedCapabilties...)
	data = append(data, b.BSSMaxIdlePeriod...)

	return data
}

// 5GHz VHT
type AssocResp2 struct {
	ByteOrder binary.ByteOrder
	// MAC Header
	FC             uint16 // Frame Control - length 2
	Duration       uint16 // length 2
	DA             net.HardwareAddr
	SA             net.HardwareAddr
	BSSID          net.HardwareAddr
	SeqCtlr        uint16 // len 2 -> Fragment number (4 bits) + Sequence number (12 bits)
	CapabilityInfo uint16
	Status         uint16
	AID            uint16

	SupportedRates         []byte
	ExtendedSupportedRates []byte
	HTCapabilties          []byte
	HTOperation            []byte
	Tag191                 []byte
	Tag192                 []byte
	ExtendedCapabilties    []byte
	Tag90                  []byte
	NinthElement           []byte // ID: 0xdd len: 24
}

// rate in Mbps
func (b *AssocResp2) AppendSupportedRateIE(mandatory bool, rateMbps float64) error {
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

// ExtendedSupportedRates
func (b *AssocResp2) SetExtendedSupportedRates() error {
	b.ExtendedSupportedRates = make([]byte, 0)
	b.ExtendedSupportedRates = append(b.ExtendedSupportedRates, 0x32, 0x02, 0xFF, 0xFE) // element ID, length, params
	return nil
}

func (b *AssocResp2) SetHTCapabilties() error {
	b.HTCapabilties = make([]byte, 0)
	b.HTCapabilties = append(b.HTCapabilties, 0x2D, 0x1A, 0x6e, 0x08, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // element ID, length, params
	return nil
}

func (b *AssocResp2) SetHTOperation() error {
	b.HTOperation = make([]byte, 0)
	b.HTOperation = append(b.HTOperation, 0x3D, 0x16, 0x24, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // element ID, length, params
	return nil
}

func (b *AssocResp2) SetExtendedCapabilties() error {
	b.ExtendedCapabilties = make([]byte, 0)
	b.ExtendedCapabilties = append(b.ExtendedCapabilties, 0x7F, 0x8, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40) // element ID, length, Extended capabilites
	return nil
}

func (b *AssocResp2) SetTag191() error {
	b.Tag191 = make([]byte, 0)
	b.Tag191 = append(b.Tag191, 0xBF, 0x0C, 0xa2, 0x00, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x00) // element ID, length, params
	return nil
}

func (b *AssocResp2) SetTag192() error {
	b.Tag192 = make([]byte, 0)
	b.Tag192 = append(b.Tag192, 0xC0, 0x05, 0x01, 0x2a, 0x00, 0xfc, 0xff) // element ID, length, params
	return nil
}

func (b *AssocResp2) SetTag90() error {
	b.Tag90 = make([]byte, 0)
	b.Tag90 = append(b.Tag90, 0x5A, 0x03, 0x24, 0x1, 0x00) // element ID, length, params
	return nil
}

func (b *AssocResp2) NinthElementIE() error {
	b.NinthElement = make([]byte, 0)
	b.NinthElement = append(b.NinthElement, 0xDD, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x01, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00) // element ID, length, params
	return nil
}

func (b AssocResp2) Serialize() []byte {
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

	data = append(data, b.SupportedRates...)
	data = append(data, b.ExtendedSupportedRates...)
	data = append(data, b.HTCapabilties...)
	data = append(data, b.HTOperation...)
	data = append(data, b.Tag191...)
	data = append(data, b.Tag192...)
	data = append(data, b.ExtendedCapabilties...)
	data = append(data, b.Tag90...)
	data = append(data, b.NinthElement...)

	return data
}
