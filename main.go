package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	layers "github.com/gopacket/gopacket/layers"
	pcap "github.com/gopacket/gopacket/pcap"
	netroute "github.com/libp2p/go-netroute"
)

type DNSEntry struct {
	FQDNS  []string
	CNAMES []string
	IP     net.IP
}

func (d DNSEntry) String() string {
	var t string

	if len(d.CNAMES) == 0 {
		return fmt.Sprintf("%s -> %s", d.FQDNS[0], d.IP)
	}
	for _, cn := range d.CNAMES {
		t = fmt.Sprintf(" -> %s", cn)
	}
	return fmt.Sprintf("%s%s -> %s", d.FQDNS[0], t, d.IP)
}

var (
	device       string = "en0"
	selfip       net.IP
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = pcap.BlockForever
	handle       *pcap.Handle
	DNSEntries   map[string]*DNSEntry = make(map[string]*DNSEntry)
	IPEntries    map[string]*DNSEntry = make(map[string]*DNSEntry)
	SeenTraffic  map[string]bool      = make(map[string]bool)
)

func processDNSPacket(p gopacket.Packet) {
	switch a := p.ApplicationLayer().(type) {
	case *layers.DNS:
		if len(a.Questions) == 0 {
			fmt.Printf("[ERR] DNS: no question \n")
			// No question?
			return
		}

		if a.Questions[0].Type != layers.DNSTypeA {
			if a.Questions[0].Type == layers.DNSTypePTR || a.Questions[0].Type == layers.DNSTypeAAAA || a.Questions[0].Type == 65 {
				// Silently consuming PTR, v6 or "65" Mac queries
				return
			}
			fmt.Printf("[ERR] DNS: %s -> not type A query (%d)\n", a.Questions[0].Name, a.Questions[0].Type)
			return
		}

		if _, ok := DNSEntries[string(a.Questions[0].Name)]; !ok {
			// No forward entry yet
			var fq []string

			fq = append(fq, string(a.Questions[0].Name))
			DNSEntries[string(a.Questions[0].Name)] = &DNSEntry{
				FQDNS: fq,
			}
		}

		de := DNSEntries[string(a.Questions[0].Name)]

		// Detecting NXD
		if a.ResponseCode == 3 {
			// NXD indicated by 0.0.0.0
			de.CNAMES = nil
			de.IP = net.IPv4(0, 0, 0, 0)
			fmt.Printf("[DNS] %s -> NXDOMAIN\n", a.Questions[0].Name)
			return
		}

		if len(a.Answers) == 0 {
			fmt.Printf("[ERR] DNS: %s -> no answer: %#v\n", a.Questions[0].Name, a.CanDecode())
			// No answer?
			return
		}

		for _, an := range a.Answers {
			if an.IP != nil {
				// Found the IP!
				de.IP = an.IP
				break
			}
			if an.CNAME != nil {
				// It's a CNAME, add it
				de.CNAMES = append(de.CNAMES, string(an.CNAME))
			}
		}

		// storing IP for reverse lookups
		IPEntries[de.IP.String()] = de
		fmt.Printf("[DNS] %s\n", de)
	}

}

func processPacket(p gopacket.Packet) {
	var (
		srcIP   net.IP
		dstIP   net.IP
		dstPort uint16 = 0
	)

	switch n := p.NetworkLayer().(type) {
	case *layers.IPv4:
		srcIP = n.SrcIP
		dstIP = n.DstIP
	}

	switch t := p.TransportLayer().(type) {
	case *layers.TCP:
		dstPort = uint16(t.DstPort)
		// We are interested in SYNs only
		if !t.SYN || t.ACK {
			return
		}
		if dstPort != 0 {
			trtag := fmt.Sprintf("%s-%s:%d", srcIP, dstIP, dstPort)
			if _, ok := SeenTraffic[trtag]; !ok {
				SeenTraffic[trtag] = true
				if !dstIP.Equal(selfip) {
					if _, ok := IPEntries[dstIP.String()]; ok {
						fmt.Printf("[OUTTCP] S:%s D:%s DP:%d %v\n", srcIP, dstIP, dstPort, IPEntries[dstIP.String()].FQDNS)
						return
					}
					fmt.Printf("[OUTTCP] S:%s D:%s DP:%d\n", srcIP, dstIP, dstPort)
					return
				}
				fmt.Printf("[INTCP] S:%s D:%s DP:%d\n", srcIP, dstIP, dstPort)
			}
		}
		return

	case *layers.UDP:
		// Only interested in DNS responses
		if t.SrcPort == 53 {
			processDNSPacket(p)
		}
	}

}

func sysInit() {
	r, err := netroute.New()
	if err != nil {
		panic(err)
	}
	iface, gw, src, err := r.Route(net.IPv4(0, 0, 0, 0))
	selfip = src
	device = iface.Name
	fmt.Printf("[HOST] Interface: %s IP: %s Gateway: %s\n", device, src, gw)
}

func main() {
	sysInit()
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}
