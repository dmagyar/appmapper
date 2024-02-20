package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	layers "github.com/gopacket/gopacket/layers"
	pcap "github.com/gopacket/gopacket/pcap"
	netroute "github.com/libp2p/go-netroute"
	cache "github.com/patrickmn/go-cache"
)

var (
	device       string = "auto"
	selfip       net.IP = net.IPv4(0, 0, 0, 0)
	snapshot_len int32  = 1024
	ack_wait_ms         = 800 * time.Millisecond
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = pcap.BlockForever
	handle       *pcap.Handle
	DNSEntries   map[string]*DNSEntry = make(map[string]*DNSEntry)
	IPEntries    map[string]*DNSEntry = make(map[string]*DNSEntry)
	SeenTraffic  map[string]bool      = make(map[string]bool)
	SYNCache     *cache.Cache
	allconns     bool = false
)

func printRecord(cn interface{}) {
	dstIP := cn.(*ConnEntry).IPLayer.(*layers.IPv4).DstIP
	srcIP := cn.(*ConnEntry).IPLayer.(*layers.IPv4).SrcIP
	dstPort := uint16(cn.(*ConnEntry).TCPLayer.(*layers.TCP).DstPort)
	diffms := time.Now().Sub(cn.(*ConnEntry).Timestamp)
	op := cn.(*ConnEntry).Operation

	if !dstIP.Equal(selfip) {
		if _, ok := IPEntries[dstIP.String()]; ok {
			fmt.Printf("[OUTTCP] %s(%dms) S:%s D:%s DP:%d %v\n", op, diffms.Milliseconds(), srcIP, dstIP, dstPort, IPEntries[dstIP.String()].FQDNS)
			return
		}
		fmt.Printf("[OUTTCP] %s(%dms) S:%s D:%s DP:%d\n", op, diffms.Milliseconds(), srcIP, dstIP, dstPort)
		return
	}
	fmt.Printf("[INTCP] %s(%dms) S:%s D:%s DP:%d\n", op, diffms.Milliseconds(), srcIP, dstIP, dstPort)
}

func sysInit() {
	r, err := netroute.New()
	if err != nil {
		panic(err)
	}
	iface, gw, src, err := r.Route(net.IPv4(0, 0, 0, 0))
	if device == "auto" {
		device = iface.Name
		selfip = src
		fmt.Printf("[HOST] Auto Interface: %s IP: %s Gateway: %s\n", device, src, gw)
		return
	}

	ifaces, err := net.Interfaces()
	for _, i := range ifaces {
		if i.Name == device {
			addrs, _ := i.Addrs()
			sip := "0.0.0.0"
			for _, addr := range addrs {
				sip = strings.Split(addr.String(), "/")[0]
			}

			if net.ParseIP(sip).To4() == nil {
				// v6 address, skip
			}

			selfip = net.ParseIP(sip)
			fmt.Printf("Got interface IP: %s\n", selfip)
		}
	}
	if selfip.Equal(net.IPv4(0, 0, 0, 0)) {
		fmt.Printf("Unable to determine IP address for interface %s. Try auto-detect?\n", device)
		os.Exit(-1)
	}
	fmt.Printf("[HOST] Manual Interface: %s IP: %s\n", device, selfip)
}

func init() {
	flag.StringVar(&device, "interface", "auto", "Manually specify interface [defaults to auto-detect]")
	flag.BoolVar(&allconns, "allconns", false, "Specify to print all connections instead of once")
	flag.Parse()
}

func SYNCacheEvicter(s string, i interface{}) {
	cn := i.(*ConnEntry)
	if !cn.ACKED {
		cn.Operation = "TIMEOUT"
		printRecord(cn)
	}
}

func main() {
	sysInit()
	SYNCache = cache.New(ack_wait_ms, 2*ack_wait_ms)
	SYNCache.OnEvicted(SYNCacheEvicter)
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
