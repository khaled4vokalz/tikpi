package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/khaled4vokalz/tikpi/ethernet"
	"github.com/khaled4vokalz/tikpi/ip"
	"github.com/khaled4vokalz/tikpi/tcp"
)

const (
	IFACE       = "en0"
	LISTEN_PORT = 8080
)

func main() {
	// 1. Open pcap handle for capturing
	snapshotLen := int32(65536)
	promiscuous := true
	timeout := pcap.BlockForever
	pcapHandle, err := pcap.OpenLive(IFACE, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer pcapHandle.Close()

	// 2. Filter only TCP packets to our port
	err = pcapHandle.SetBPFFilter("tcp port 8080")
	if err != nil {
		log.Fatal(err)
	}
	// 3. Create Connection in LISTEN state
	conn := &tcp.Connection{
		State:     tcp.STATE_LISTEN,
		LocalPort: LISTEN_PORT,
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	log.Printf("Listening on %s:%d", IFACE, LISTEN_PORT)

	for packet := range packetSource.Packets() {
		handlePacket(pcapHandle, conn, packet.Data())
	}
}

func handlePacket(pcapHandle *pcap.Handle, conn *tcp.Connection, data []byte) {
	// 1. Parse Ethernet
	ethFrame, err := ethernet.Parse(data)
	if err != nil {
		log.Printf("Failed to parse Ethernet frame: %v", err)
		return
	}

	// 2. Parse IP (start at byte 14)
	ipPacket, err := ip.Parse(data[14:])
	if err != nil {
		log.Printf("Failed to parse IP packet: %v", err)
		return
	}

	// 3. Parse TCP (start at byte 14 + IP Header Length * 4)
	tcpOffset := 14 + int(ipPacket.IHL)*4
	tcpSegment, err := tcp.Parse(data[tcpOffset:])
	if err != nil {
		log.Printf("Failed to parse TCP segment: %v", err)
		return
	}

	// 4. Check if packet is for our connection (port)
	if tcpSegment.DestPort != conn.LocalPort {
		return
	}

	// 5. Handle based on flags
	var response *tcp.TCPSegment

	if tcpSegment.Flags&0x02 != 0 { // SYN flag
		log.Printf("Received SYN from %d.%d.%d.%d:%d", ipPacket.SrcIP[0], ipPacket.SrcIP[1], ipPacket.SrcIP[2], ipPacket.SrcIP[3], tcpSegment.SrcPort)

		conn.RemoteIP = ipPacket.SrcIP
		conn.RemotePort = tcpSegment.SrcPort
		conn.LocalIP = ipPacket.DestIP

		response = conn.HandleSyn(tcpSegment, conn.RemoteIP, conn.RemotePort)
	} else if tcpSegment.Flags&0x10 != 0 { // ACK flag
		log.Printf("Received ACK from %d.%d.%d.%d:%d", ipPacket.SrcIP[0], ipPacket.SrcIP[1], ipPacket.SrcIP[2], ipPacket.SrcIP[3], tcpSegment.SrcPort)
		if conn.State == tcp.STATE_ESTABLISHED {
			log.Print("Connection established!")
		}
	}

	// 6. Send response if any
	if response != nil {
		sendPacket(pcapHandle, conn, ethFrame, ipPacket, response)
	}
}

func sendPacket(pcapHandle *pcap.Handle, conn *tcp.Connection, ethFrame *ethernet.Frame, ipPacket *ip.IPPacket, tcpSegment *tcp.TCPSegment) {
	// Build TCP segment bytes
	tcpData := tcp.Build(tcpSegment)

	// Calculate TCP checksum
	checksum := tcp.TCPChecksum(ipPacket.SrcIP, ipPacket.DestIP, tcpData)
	tcpData[16] = byte(checksum >> 8)
	tcpData[17] = byte(checksum & 0xFF)

	// Build IP packet
	ipResp := &ip.IPPacket{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: ip.IPProtocolTCP,
		SrcIP:    conn.LocalIP,
		DestIP:   conn.RemoteIP,
		TotalLen: uint16(20 + len(tcpData)),
	}
	ipData, _ := ip.Build(ipResp)

	// Calculate IP checksum
	ipChecksum := ip.IPChecksum(ipData)
	ipData[10] = byte(ipChecksum >> 8)
	ipData[11] = byte(ipChecksum & 0xFF)

	linkType := pcapHandle.LinkType()
	log.Printf("Interface %s link type: %v", IFACE, linkType)

	isLoopback := linkType == layers.LinkTypeNull || linkType == layers.LinkTypeLoop

	var packetData []byte
	if isLoopback {
		loopbackHeader := []byte{0x02, 0x00, 0x00, 0x00} // AF_INET
		packetData = append(loopbackHeader, ipData...)
	} else {
		// Build Ethernet frame
		ethResp := &ethernet.Frame{
			DestMac:   ethFrame.SrcMac,
			SrcMac:    ethFrame.DestMac,
			EtherType: 0x0800, // IPv4
		}
		ethData, _ := ethResp.Build()
		packetData = append(ethData, ipData...)
	}

	// Append TCP segment
	packetData = append(packetData, tcpData...)

	// Send packet
	err := pcapHandle.WritePacketData(packetData)
	if err != nil {
		log.Printf("Failed to send packet: %v", err)
	} else {
		log.Printf("Sent packet to %d.%d.%d.%d:%d", conn.RemoteIP[0], conn.RemoteIP[1], conn.RemoteIP[2], conn.RemoteIP[3], conn.RemotePort)
	}
}
