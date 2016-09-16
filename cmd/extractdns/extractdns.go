/*
Package main implements a tool that extracts from DNS requests and responses in
a pcap the observed domains, TTLs and IP-addresses. The result is written to
".dns" files used by the dnsstats tool.
*/
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	workerFactor = flag.Int("f", 2,
		"the factor to multiply NumCPU with for creating workers")
	output = flag.String("o", "", "folder to store results in")
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("need to specify pcap dir")
	}
	if *output == "" {
		*output = flag.Arg(0)
	}

	files, err := ioutil.ReadDir(flag.Arg(0))
	if err != nil {
		log.Fatalf("failed to read pcap dir (%s)", err)
	}

	work := make(chan string)
	wg := new(sync.WaitGroup)
	wg.Add(runtime.NumCPU() * *workerFactor)
	for i := 0; i < runtime.NumCPU()**workerFactor; i++ {
		go doWork(work, wg)
	}

	log.Printf("starting to extract (%d workers)...",
		runtime.NumCPU()**workerFactor)
	extracted := 0
	for i := 0; i < len(files); i++ {
		if !files[i].IsDir() && strings.HasSuffix(files[i].Name(), ".pcap") {
			fmt.Printf("\rextracted %d", extracted)
			work <- files[i].Name()
			extracted++
		}
	}
	close(work)
	wg.Wait()
	fmt.Printf("\rextracted %d\n", extracted)
	log.Println("done")
}

func doWork(input chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for file := range input {
		extract(file)
	}
}

func extract(file string) {
	domains, err := extractDomains(path.Join(flag.Arg(0), file))
	if err != nil {
		log.Fatalf("failed to extract DNS info (%s)", err)
	}
	f, err := os.Create(path.Join(*output, file[:len(file)-5]+".dns"))
	if err != nil {
		log.Fatalf("failed to create file to store result in (%s)", err)
	}
	for j := 0; j < len(domains); j++ {
		result := fmt.Sprintf("%s,%d", domains[j].domain, domains[j].ttl)
		for k := 0; k < len(domains[j].ips); k++ {
			result += "," + domains[j].ips[k]
		}

		_, err = f.WriteString(fmt.Sprintf("%s\n", result))
		if err != nil {
			log.Fatalf("failed to write result to file (%s)", err)
		}
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("failed to close file (%s)", err)
	}
}

type domain struct {
	domain string
	ttl    int
	ips    []string
}

func extractDomains(pcapfile string) (domains []domain, err error) {
	handle, err := pcap.OpenOffline(pcapfile)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s (%s)", pcapfile, err)
	}
	source := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

	for packet := range source.Packets() {
		if packet.ApplicationLayer() != nil &&
			packet.ApplicationLayer().LayerType() == layers.LayerTypeDNS {
			dns := packet.ApplicationLayer().(*layers.DNS)
			for i := 0; i < len(dns.Questions); i++ {
				index := getIndex(string(dns.Questions[i].Name), domains)
				if index == -1 {
					var d domain
					d.ttl = 0
					d.domain = string(dns.Questions[i].Name)
					domains = append(domains, d)
				}
			}
			for i := 0; i < len(dns.Answers); i++ {
				index := getIndex(string(dns.Answers[i].Name), domains)
				if index == -1 {
					var d domain
					d.ttl = int(dns.Answers[i].TTL)
					d.domain = string(dns.Answers[i].Name)
					domains = append(domains, d)
					index = len(domains) - 1
				}

				if domains[index].ttl == 0 {
					domains[index].ttl = int(dns.Answers[i].TTL)
				}
				if dns.Answers[i].IP.String() != "<nil>" {
					if !exists(dns.Answers[i].IP.String(), domains[index].ips) {
						domains[index].ips = append(domains[index].ips,
							dns.Answers[i].IP.String())
					}
				}
			}
		}
	}
	handle.Close()

	return
}

func getIndex(domain string, domains []domain) int {
	for i, d := range domains {
		if strings.EqualFold(d.domain, domain) {
			return i
		}
	}
	return -1
}

func exists(ip string, ips []string) bool {
	for _, i := range ips {
		if strings.EqualFold(ip, i) {
			return true
		}
	}
	return false
}
