package main

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	layers "github.com/gopacket/gopacket/layers"
	cache "github.com/patrickmn/go-cache"
)

type DNSEntry struct {
	FQDNS  []string
	CNAMES []string
	IP     net.IP
}

type ConnEntry struct {
	IPLayer   gopacket.NetworkLayer
	TCPLayer  gopacket.TransportLayer
	Timestamp time.Time
	ACKED     bool
	Operation string
	Protocol  string
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
	// Non IPv4 packet?
	default:
		return
	}

	switch t := p.TransportLayer().(type) {
	case *layers.UDP:
		// Only interested in DNS responses
		if t.SrcPort == 53 {
			processDNSPacket(p)
		}
		return

	case *layers.TCP:
		dstPort = uint16(t.DstPort)
		if dstPort != 0 {
			// We have a good TCP Packet
			if t.SYN && !t.ACK {
				// SYN PACKET
				trtag := fmt.Sprintf("%s-%s:%d", srcIP, dstIP, t.DstPort)
				syntag := fmt.Sprintf("%s-%s/%d:%d", srcIP, dstIP, t.SrcPort, t.DstPort)
				if _, ok := SeenTraffic[trtag]; !ok {
					if !allconns {
						SeenTraffic[trtag] = true
					}

					cn := &ConnEntry{
						IPLayer:   p.NetworkLayer(),
						TCPLayer:  p.TransportLayer(),
						Timestamp: time.Now(),
					}
					SYNCache.Set(syntag, cn, cache.DefaultExpiration)
				}
				return
			}

			if !t.SYN && t.ACK {
				// ACK PACKET
				// Let's see if this is in the cache
				revsyntag := fmt.Sprintf("%s-%s/%d:%d", dstIP, srcIP, t.DstPort, t.SrcPort)
				cn, found := SYNCache.Get(revsyntag)
				if !found {
					// Not our ACK
					return
				}
				dstIP = cn.(*ConnEntry).IPLayer.(*layers.IPv4).DstIP
				srcIP = cn.(*ConnEntry).IPLayer.(*layers.IPv4).SrcIP
				dstPort = uint16(cn.(*ConnEntry).TCPLayer.(*layers.TCP).DstPort)
				cn.(*ConnEntry).ACKED = true
				cn.(*ConnEntry).Operation = "ACK"
				if t.RST {
					// Closed port
					cn.(*ConnEntry).Operation = "RST"
				}
				SYNCache.Delete(revsyntag)
				printRecord(cn)
			}
		}
	}

}
