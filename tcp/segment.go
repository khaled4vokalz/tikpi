package tcp

import "fmt"

type TCPSegment struct {
	SrcPort    uint16
	DestPort   uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8  // in 32-bit words
	Flags      uint16 // e.g., SYN, ACK, SYN-ACK, FIN
	WindowSize uint16
}

func Parse(data []byte) (*TCPSegment, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short to be a TCP segment")
	}
	/*
		TCP Segment:

		  0                   1                   2                   3
		  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		├─────────────────────────────┬─────────────────────────────────┤
		│         Source Port         │       Destination Port          │  Bytes 0-3
		├─────────────────────────────┴─────────────────────────────────┤
		│                        Sequence Number                        │  Bytes 4-7
		├───────────────────────────────────────────────────────────────┤
		│                     Acknowledgment Number                     │  Bytes 8-11
		├───────┬───────┬─┬─┬─┬─┬─┬─┬───────────────────────────────────┤
		│DataOff│  Res  │C│E│U│A│P│R│S│F│          Window Size          │  Bytes 12-15
		│(4bits)│       │W│C│R│C│S│S│Y│I│                               │
		│       │       │R│E│G│K│H│T│N│N│                               │
		└───────┴───────┴─┴─┴─┴─┴─┴─┴─┴─┴───────────────────────────────┘
	*/
	segment := &TCPSegment{
		// ports -> 2 bytes (each, thus bit shifted by 8,0)
		SrcPort:  uint16(data[0])<<8 | uint16(data[1]),
		DestPort: uint16(data[2])<<8 | uint16(data[3]),
		// sequence/ack number -> 4 bytes (thus bit sfhifted by 24,16,8,0)
		SeqNum:     uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		AckNum:     uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11]),
		DataOffset: data[12] >> 4,
		// NS is the least significant bit of data[12], so we mask all other bits and shift it to the 8th bit position
		// flags -> [ NS ][ CWR ECE URG ACK PSH RST SYN FIN ]
		Flags: uint16(data[12]&0x01)<<8 | uint16(data[13]),
		WindowSize: uint16(data[14])<<8 | uint16(data[15]),
	}
	return segment, nil
}

func Build(segment *TCPSegment) []byte {
	data := make([]byte, 20) // Minimum TCP header size
	// ports -> 2 bytes (each, thus bit shifted by 8,0)
	data[0] = byte(segment.SrcPort >> 8)
	data[1] = byte(segment.SrcPort & 0xFF)
	data[2] = byte(segment.DestPort >> 8)
	data[3] = byte(segment.DestPort & 0xFF)
	// sequence/ack number -> 4 bytes (thus bit sfhifted by 24,16,8,0)
	data[4] = byte(segment.SeqNum >> 24)
	data[5] = byte((segment.SeqNum >> 16) & 0xFF)
	data[6] = byte((segment.SeqNum >> 8) & 0xFF)
	data[7] = byte(segment.SeqNum & 0xFF)
	data[8] = byte(segment.AckNum >> 24)
	data[9] = byte((segment.AckNum >> 16) & 0xFF)
	data[10] = byte((segment.AckNum >> 8) & 0xFF)
	data[11] = byte(segment.AckNum & 0xFF)
	// DataOffset (4 bits) + NS (1 bit, right shift out all the flags keeping only the NS bit)
	data[12] = (segment.DataOffset&0x0F)<<4 | byte((segment.Flags>>8)&0x01)
	// Flags (CWR..FIN)
	data[13] = byte(segment.Flags & 0xFF)
	data[14] = byte(segment.WindowSize >> 8)
	data[15] = byte(segment.WindowSize & 0xFF)
	return data
}
