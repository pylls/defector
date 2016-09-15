/*
torlogextract extracts, from ".torlog" files (generated by our data collection):
- .dns files of observed DNS requests (same as the extractdns tool)
- .cells files of celltraces in the go-kNN format (Wang's format)
*/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	workerFactor = flag.Int("f", 2, "the factor to multiply NumCPU with for creating workers")
	output       = flag.String("o", "", "folder to store results in, if left empty, same as input")

	dateFormat = "Jan 2 15:04:05.000"
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("need to specify torlog dir")
	}
	if *output == "" {
		*output = flag.Arg(0)
	}

	files, err := ioutil.ReadDir(flag.Arg(0))
	if err != nil {
		log.Fatalf("failed to read torlog dir (%s)", err)
	}

	work := make(chan string)
	wg := new(sync.WaitGroup)
	wg.Add(runtime.NumCPU() * *workerFactor)
	for i := 0; i < runtime.NumCPU()**workerFactor; i++ {
		go doWork(work, wg)
	}

	log.Printf("starting to extract (%d workers)...", runtime.NumCPU()**workerFactor)
	extracted := 0
	for i := 0; i < len(files); i++ {
		if !files[i].IsDir() && strings.HasSuffix(files[i].Name(), ".torlog") {
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
	domains, cells, err := parse(path.Join(flag.Arg(0), file))
	if err != nil {
		log.Fatalf("failed to parse file (%s)", err)
	}

	// write .dns file
	f, err := os.Create(path.Join(*output, file[:len(file)-7]+".dns"))
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

	// write .cells file
	f, err = os.Create(path.Join(*output, file[:len(file)-7]+".cells"))
	if err != nil {
		log.Fatalf("failed to create file to store result in (%s)", err)
	}
	_, err = f.WriteString(cells)
	if err != nil {
		log.Fatalf("failed to write result to file (%s)", err)
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

func parse(torlogfile string) (domains []domain, cells string, err error) {
	f, err := os.Open(torlogfile)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(f)
	bootstrapped := false
	var first *time.Time
	for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), " ")

		if strings.Contains(scanner.Text(), "Bootstrapped 100%: Done") {
			bootstrapped = true
		}

		if bootstrapped && strings.Contains(scanner.Text(), "DATA(2)") {
			if first == nil {
				first = new(time.Time)
				*first = getTime(tokens)
			}
			if strings.Contains(scanner.Text(), "OUTGOING") {
				cells += fmt.Sprintf("%.3f\t1\n", getTime(tokens).Sub(*first).Seconds())
			} else {
				cells += fmt.Sprintf("%.3f\t-1\n", getTime(tokens).Sub(*first).Seconds())
			}
		}

		if bootstrapped && strings.Contains(scanner.Text(), "DNSRESOLVED") {
			ttl, err := strconv.Atoi(tokens[9])
			if err != nil {
				return nil, "", err
			}
			domains = append(domains, domain{
				domain: tokens[5],
				ips:    []string{tokens[7]},
				ttl:    ttl,
			})

		}
	}

	return
}

func getTime(tokens []string) time.Time {
	t, _ := time.Parse(dateFormat, fmt.Sprintf("%s %s %s", tokens[0], tokens[1], tokens[2]))
	return t
}