package ethernet

import (
	"encoding/binary"
	"fmt"
)

type Frame struct {
	DestMac   [6]byte
	SrcMac    [6]byte
	EtherType uint16
}

func Parse(data []byte) (*Frame, error) {
	if len(data) < 14 {
		return nil, fmt.Errorf("data too short to be an Ethernet frame")
	}
	/*
		│ Ethernet Frame (First 14 bytes) [0-13]
		│  - Destination MAC (6 bytes)
		│  - Source MAC (6 bytes)
		│  - EtherType (2 bytes)
	*/
	frame := &Frame{
		DestMac:   [6]byte{data[0], data[1], data[2], data[3], data[4], data[5]},
		SrcMac:    [6]byte{data[6], data[7], data[8], data[9], data[10], data[11]},
		EtherType: binary.BigEndian.Uint16(data[12:14]),
	}
	return frame, nil
}

func (f *Frame) Build() ([]byte, error) {
	data := make([]byte, 14)
	copy(data[0:6], f.DestMac[:])
	copy(data[6:12], f.SrcMac[:])
	binary.BigEndian.PutUint16(data[12:14], f.EtherType)
	return data, nil
}
