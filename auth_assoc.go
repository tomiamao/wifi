package wifi

import (
	"encoding/binary"
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
