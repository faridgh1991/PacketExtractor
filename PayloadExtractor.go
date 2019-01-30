package packetx

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	snapshotLen int32 = 65536
	promiscuous       = false
	timeout           = 30 * time.Millisecond
)

// PacketExtractor object contains recieve packets channel,handle and send parsedPackets channel
type PacketExtractor struct {
	packets <-chan gopacket.Packet
	handle  *pcap.Handle
	c       chan ParsedPacket
}

// Close PacketExtractor handle
func (e *PacketExtractor) Close() {
	e.handle.Close()
}

func (e *PacketExtractor) packetsToChannel() {
	// listen on packets channel
	if e.packets != nil {
		for packet := range e.packets {
			parsed := parseLayersInfo(packet)
			e.c <- parsed
		}
	}
}

// ParsedPacket is layer separated packed type
type ParsedPacket struct {
	IPLayer  *layers.IPv4
	UDPLayer *layers.UDP
	TCPLayer *layers.TCP
	Payload  gopacket.Payload
}

// parseLayersInfo get packet and parse it to layer separated object
func parseLayersInfo(packet gopacket.Packet) ParsedPacket {

	var parsed ParsedPacket

	if ipv4 := packet.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		parsed.IPLayer = ipv4.(*layers.IPv4)
	}
	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		parsed.TCPLayer = tcp.(*layers.TCP)
		parsed.Payload = parsed.TCPLayer.Payload
	}
	if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		uLayer := udp.(*layers.UDP)
		parsed.UDPLayer = uLayer
		parsed.Payload = uLayer.Payload
	}
	return parsed
}

// Packet method run goroutine to send parsedPackets to channel
func (e *PacketExtractor) Packet() <-chan ParsedPacket {
	if e.c == nil {
		e.c = make(chan ParsedPacket, 1000)
		go e.packetsToChannel()
	}
	return e.c
}

// NewExtractor create a packet extractor and return parsed packets on channel
func NewExtractor(interfaceName string, protocol string, port string) (PacketExtractor, error) {

	fs := FilterSettings{interfaceName, protocol, port}

	extractor := PacketExtractor{}

	// Open device
	h, err := pcap.OpenLive(fs.deviceInterface, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	extractor.handle = h

	// Start Listener
	p, err := listenOnInterface(extractor.handle, fs)
	extractor.packets = p

	if err != nil {
		return PacketExtractor{}, err
	}

	return extractor, nil
}

// FilterSettings is custom filter configurations
type FilterSettings struct {
	deviceInterface string
	protocol        string
	port            string
}

// listen on interface with custom filter settings
func listenOnInterface(handle *pcap.Handle, fs FilterSettings) (chan gopacket.Packet, error) {

	//Set filter
	var filter = fmt.Sprintf("%s and port %s", fs.protocol, fs.port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}
	log.Printf("Only capturing %s port %s packets on %s.\n\n", fs.protocol, fs.port, fs.deviceInterface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := packetSource.Packets()

	return packets, nil
}
