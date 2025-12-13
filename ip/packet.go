package ip

import "fmt"

type IPProtocol uint8

const (
	IPProtocolICMP IPProtocol = 1
	IPProtocolTCP  IPProtocol = 6
	IPProtocolUDP  IPProtocol = 17
)

type IPPacket struct {
	Version        uint8
	IHL            uint8 // Internet Header Length
	TOS            uint8 // Type of Service
	TotalLen       uint16
	Identification uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8 // Time To Live
	Protocol       IPProtocol
	HeaderChecksum uint16
	SrcIP          [4]byte
	DestIP         [4]byte
}

func Parse(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short to be an IP packet")
	}
	/*
		IPv4 Header Structure (IP Packet):

		  0                   1                   2                   3
		  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		├─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┤
		│Version│  IHL  │    TOS    │          Total Length             │  Bytes 0-3
		├───────┴───────┴───────────┼───────────────────────────────────┤
		│         Identification    │Flags│      Fragment Offset        │  Bytes 4-7
		├───────────────────────────┼─────┴─────────────────────────────┤
		│    TTL        │  Protocol │         Header Checksum           │  Bytes 8-11
		├───────────────┴───────────┴───────────────────────────────────┤
		│                       Source IP Address                       │  Bytes 12-15
		├───────────────────────────────────────────────────────────────┤
		│                    Destination IP Address                     │  Bytes 16-19
		└───────────────────────────────────────────────────────────────┘
	*/
	packet := &IPPacket{
		Version:        data[0] >> 4,   // First 4 bits
		IHL:            data[0] & 0x0F, // Last 4 bits
		TOS:            data[1],
		TotalLen:       uint16(data[2])<<8 | uint16(data[3]),
		Identification: uint16(data[4])<<8 | uint16(data[5]),
		Flags:          data[6] >> 5, // First 3 bits
		FragmentOffset: (uint16(data[6]&0x1F) << 8) | uint16(data[7]),
		TTL:            data[8],
		Protocol:       parseIPProtocol(data[9]),
		HeaderChecksum: uint16(data[10])<<8 | uint16(data[11]),
		SrcIP:          [4]byte{data[12], data[13], data[14], data[15]},
		DestIP:         [4]byte{data[16], data[17], data[18], data[19]},
	}
	return packet, nil
}

func Build(packet *IPPacket) ([]byte, error) {
	data := make([]byte, 20)
	data[0] = (packet.Version << 4) | (packet.IHL & 0x0F)                 // First 4 bits: Version, Last 4 bits: IHL
	data[1] = packet.TOS                                                  // Type of Service
	data[2] = byte(packet.TotalLen >> 8)                                  // High byte
	data[3] = byte(packet.TotalLen & 0xFF)                                // Low byte
	data[4] = byte(packet.Identification >> 8)                            // High byte
	data[5] = byte(packet.Identification & 0xFF)                          // Low byte
	data[6] = (packet.Flags << 5) | byte((packet.FragmentOffset>>8)&0x1F) // First 3 bits: Flags, Last 5 bits: High bits of Fragment Offset
	data[7] = byte(packet.FragmentOffset & 0xFF)                          // Low byte of Fragment Offset
	data[8] = packet.TTL                                                  // Time To Live (8 bits)
	data[9] = byte(packet.Protocol)                                       // Protocol (8 bits)
	data[10] = byte(packet.HeaderChecksum >> 8)                           // High byte
	data[11] = byte(packet.HeaderChecksum & 0xFF)                         // Low byte
	copy(data[12:16], packet.SrcIP[:])                                    // Source IP Address (4 bytes)
	copy(data[16:20], packet.DestIP[:])                                   // Destination IP Address (4 bytes)
	return data, nil
}

func parseIPProtocol(proto byte) IPProtocol {
	return IPProtocol(proto)
}
