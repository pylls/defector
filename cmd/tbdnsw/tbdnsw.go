/*
Package main implements a worker client to the collection server that attempts
to browse to provided URLs using a specified Tor Browser.  While browsing,
the client collects traffic into a PCAP-file that is returned to the server.
For the DefecTor work we used this client with a Tor Browser that did not
browse over the Tor network, enabling us to collect DNS requests and responses.
*/
package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	pb "github.com/pylls/defector"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"golang.org/x/net/context"

	"flag"
	"log"

	"google.golang.org/grpc"
)

var (
	attempts = flag.Int("a", 5,
		"the number of attempts per browse to launch tb")
	origBrowser = flag.String("b", "tor-browser_en-US",
		"the location of the tb folder")
	display = flag.String("display", "-screen 0 1024x768x24",
		"the xvfb display to use")

	nic        = flag.String("nic", "eth0", "the NIC to listen on for traffic")
	snaplen    = flag.Int("snaplen", 65536, "the snaplen to capture and write")
	trafficAll = flag.Bool("all", false, "collect all traffic")
	trafficTCP = flag.Bool("tcp", false, "collect only TCP traffic")

	tmpDir      = path.Join(os.TempDir(), "hotexp")
	browser     = path.Join(tmpDir, "browser")
	dataDirPath = "Browser/TorBrowser/Data"
	serverIP    = ""
	pcapData    bytes.Buffer
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("need to specify server address")
	}
	os.Remove(tmpDir)
	err := os.MkdirAll(tmpDir, 0755)
	if err != nil {
		return
	}
	defer os.Remove(tmpDir)

	// copy entire browser to a temporary location
	err = os.MkdirAll(browser, 0755)
	if err != nil {
		return
	}
	cp := exec.Command("cp", "-rfT", *origBrowser, browser)
	err = cp.Run()
	if err != nil {
		log.Fatalf("failed to copy to %s (%s)", browser, err)
	}

	conn, err := grpc.Dial(flag.Arg(0), grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewCollectClient(conn)
	serverIP = strings.Split(flag.Arg(0), ":")[0]

	// start traffic capture
	handler, err := pcap.OpenLive(*nic, int32(*snaplen), false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("failed to open capture (%s)", err)
	}
	defer handler.Close()
	source := gopacket.NewPacketSource(handler, layers.LinkTypeEthernet)
	sampleChan := make(chan bool)
	defer close(sampleChan)
	if *trafficAll {
		log.Println("collect all traffic")
		go collectAll(source.Packets(), sampleChan)
	} else if *trafficTCP {
		log.Println("collect TCP traffic")
		go collectTCP(source.Packets(), sampleChan)
	} else {
		log.Println("collect DNS traffic")
		go collectDNS(source.Packets(), sampleChan)
	}

	// base identity reported to server on IPs for easy remote access
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("failed to get network interfaces (%s)", err)
	}
	identity := strconv.Itoa(int(time.Now().UnixNano())) + "\t"
	for i := 0; i < len(addrs); i++ {
		identity += addrs[i].String() + " "
	}

	// we start with no completed work, then get to work
	work := new(pb.Req)
	work.WorkerID = identity
	work.Browse = &pb.Browse{
		ID: "",
	}
	for {
		// report and get work
		browse, err := client.Work(context.Background(), work)
		if err != nil {
			log.Printf("failed to work (%s)", err)
			continue
		}
		work.Browse = browse
		if browse.ID == "" {
			time.Sleep(time.Duration(browse.Timeout) * time.Second)
			log.Printf("no work, sleeping for %d", browse.Timeout)
			continue
		}
		log.Printf("starting work: %s", browse.URL)

		sampleChan <- browse.AllTraffic // overwrites pcap

		err = browseTB(browse.URL, int(browse.Timeout))
		if err != nil {
			log.Printf("failed to browse (%s)", err)
		}
		browse.Data = pcapData.Bytes()
	}
}

func browseTB(url string, seconds int) (err error) {
	for i := 0; i < *attempts; i++ {
		err = nil
		time.Sleep(1 * time.Second)

		// get a fresh copy of the Data dir
		err = os.RemoveAll(path.Join(browser, dataDirPath))
		if err != nil {
			err = fmt.Errorf("failed to remove Data dir at %s (%s)",
				path.Join(browser, dataDirPath), err)
			continue
		}
		cp := exec.Command("cp", "-rfT", path.Join(*origBrowser, dataDirPath),
			path.Join(browser, dataDirPath))
		err = cp.Run()
		if err != nil {
			err = fmt.Errorf("failed to copy Data dir to %s (%s)",
				path.Join(browser, dataDirPath), err)
			continue
		}

		pre := pcapData.Len()
		tb := exec.Command("xvfb-run", "-s", *display, "timeout",
			"-s", "9", strconv.Itoa(seconds), // kill, no need to play nice
			path.Join(browser, "Browser", "start-tor-browser"), url)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		tb.Stdout = &stdout
		tb.Stderr = &stderr

		tb.Run()
		if pre >= pcapData.Len() {
			err = fmt.Errorf("didn't get any data while attempting to browse, stdin (%s) and stderr (%s)",
				stdout.String(), stderr.String())
			continue
		}

		// we need to wait for killing tb and any lagging DNS responses
		time.Sleep(2 * time.Second)
		return
	}
	return
}

func collectDNS(pChan chan gopacket.Packet, sampleChan chan bool) {
	var w *pcapgo.Writer
	var err error
	for {
		select {
		case _ = <-sampleChan:
			// truncate pcap-data
			pcapData.Reset()
			w = pcapgo.NewWriter(&pcapData)
			// new pcap, must do this
			err = w.WriteFileHeader(uint32(*snaplen), layers.LinkTypeEthernet)
			if err != nil {
				log.Fatalf("failed to write pcap header (%s)", err)
			}
		case packet := <-pChan:
			// parse packet
			if w != nil {
				if packet.ApplicationLayer() != nil &&
					packet.ApplicationLayer().LayerType() == layers.LayerTypeDNS {
					err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
					if err != nil {
						log.Fatalf("failed to write packet to pcap (%s)", err)
					}
				}
			}
		}
	}
}

func collectAll(pChan chan gopacket.Packet, sampleChan chan bool) {
	var w *pcapgo.Writer
	var err error
	for {
		select {
		case _ = <-sampleChan:
			// truncate pcap-data
			pcapData.Reset()
			w = pcapgo.NewWriter(&pcapData)
			// new pcap, must do this
			err = w.WriteFileHeader(uint32(*snaplen), layers.LinkTypeEthernet)
			if err != nil {
				log.Fatalf("failed to write pcap header (%s)", err)
			}
		case packet := <-pChan:
			// parse packet
			if w != nil {
				err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				if err != nil {
					log.Fatalf("failed to write packet to pcap (%s)", err)
				}

			}
		}
	}
}

func collectTCP(pChan chan gopacket.Packet, sampleChan chan bool) {
	var w *pcapgo.Writer
	var err error
	for {
		select {
		case _ = <-sampleChan:
			// truncate pcap-data
			pcapData.Reset()
			w = pcapgo.NewWriter(&pcapData)
			// new pcap, must do this
			err = w.WriteFileHeader(uint32(*snaplen), layers.LinkTypeEthernet)
			if err != nil {
				log.Fatalf("failed to write pcap header (%s)", err)
			}
		case packet := <-pChan:
			// parse packet
			if w != nil {
				var src, dst string
				if packet.NetworkLayer() != nil {
					src = packet.NetworkLayer().NetworkFlow().Src().String()
					dst = packet.NetworkLayer().NetworkFlow().Dst().String()
				}
				if packet.TransportLayer() != nil &&
					packet.TransportLayer().LayerType() == layers.LayerTypeTCP &&
					!strings.Contains(src, serverIP) && !strings.Contains(dst, serverIP) {
					err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
					if err != nil {
						log.Fatalf("failed to write packet to pcap (%s)", err)
					}
				}
			}
		}
	}
}
