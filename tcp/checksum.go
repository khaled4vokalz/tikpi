package tcp

import (
	"github.com/khaled4vokalz/tikpi/utils"
)

func TCPChecksum(srcIP, destIP [4]byte, tcpSegment []byte) uint16 {
	pseudoHeader := make([]byte, 0, 12+len(tcpSegment))

	pseudoHeader = append(pseudoHeader, srcIP[:]...)
	pseudoHeader = append(pseudoHeader, destIP[:]...)
	pseudoHeader = append(pseudoHeader, 0) // reserved
	pseudoHeader = append(pseudoHeader, 6) // TCP protocol
	pseudoHeader = append(pseudoHeader,
		byte(len(tcpSegment)>>8),
		byte(len(tcpSegment)&0xFF),
	)

	cData := make([]byte, 0, len(pseudoHeader)+len(tcpSegment))
	cData = append(cData, pseudoHeader...)
	cData = append(cData, tcpSegment...)

	return utils.ChecksumData(cData)
}
