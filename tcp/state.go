package tcp

import (
	"crypto/rand"
	"encoding/binary"
)

type State int

const (
	STATE_LISTEN State = iota
	STATE_SYN_RECEIVED
	STATE_ESTABLISHED
	STATE_FIN_WAIT_1
	STATE_FIN_WAIT_2
	STATE_CLOSE_WAIT
	STATE_CLOSING
	STATE_LAST_ACK
	STATE_CLOSED
	STATE_SYN_SENT
	STATE_TIME_WAIT
)

type Connection struct {
	State      State
	LocalIP    [4]byte
	LocalPort  uint16
	RemoteIP   [4]byte
	RemotePort uint16
	SendSeq    uint32
	RecvSeq    uint32
	SendAck    uint32
}

func (c *Connection) HandleSyn(segment *TCPSegment, remoteIP [4]byte, remotePort uint16) *TCPSegment {
	if c.State != STATE_LISTEN {
		return nil
	}
	randomSeq, err := randomInitialSeqNum()
	if err != nil {
		panic(err) // let's keep it simple for now
	}
	// Update connection state
	c.State = STATE_SYN_RECEIVED
	c.RecvSeq = segment.SeqNum
	c.SendSeq = randomSeq
	c.SendAck = c.RecvSeq + 1
	c.RemoteIP = remoteIP
	c.RemotePort = remotePort

	// Build SYN-ACK segment
	// Flags: SYN and ACK
	synAckSegment := &TCPSegment{
		SrcPort:    c.LocalPort,
		DestPort:   c.RemotePort,
		SeqNum:     c.SendSeq,
		AckNum:     c.SendAck,
		DataOffset: 5,    // No options
		Flags:      0x12, // SYN (0x02) + ACK (0x10)
	}
	return synAckSegment
}

func (c *Connection) HandleAck(segment *TCPSegment) *TCPSegment {
	if c.State != STATE_SYN_RECEIVED {
		return nil
	}
	// Verify ACK number
	if segment.AckNum != c.SendSeq+1 {
		return nil
	}
	// Update connection state
	c.State = STATE_ESTABLISHED
	c.SendSeq += 1 // SYN consumes one sequence number

	// No response needed for ACK in this simple implementation
	return nil
}

func randomInitialSeqNum() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
