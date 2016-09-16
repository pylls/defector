/*
Package main implements a worker client for the collection server that attempts
to browse to provided URLs using a specified Tor Browser.  While browsing,
the client collects all data from stdout and sends it to the server.
For the DefecTor work, we used this client together with a patched Tor (as part
of the Tor Browser) that logged cells and DNS-related events to stdout, enabling
us to build a website fingerprinting dataset.
*/
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	pb "github.com/pylls/defector"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	attempts = flag.Int("a", 5,
		"the number of attempts per browse to launch tb")
	origBrowser = flag.String("b", "tor-browser_en-US",
		"the 	location of the TB folder")
	display = flag.String("display", "-screen 0 1024x768x24",
		"the xvfb display to use")

	tmpDir         = path.Join(os.TempDir(), "hotexp")
	browser        = path.Join(tmpDir, "browser")
	dataBrowserDir = "Browser/TorBrowser/Data/Browser"
	dataTorDir     = "Browser/TorBrowser/Data/Tor"
	okTorData      = []string{"torrc",
		"geoip",
		"cached-microdesc",
		"cached-certs"}
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

		data, err := browseTB(browse.URL, int(browse.Timeout))
		if err != nil {
			log.Printf("failed to browse (%s)", err)
			data = []byte("none")
		}
		browse.Data = data
	}
}

func browseTB(url string, seconds int) (data []byte, err error) {
	for i := 0; i < *attempts; i++ {
		err = nil
		time.Sleep(1 * time.Second)

		err = clean()
		if err != nil {
			log.Printf("%s", err)
			continue
		}

		tb := exec.Command("xvfb-run", "-s", *display, "timeout",
			"-s", "9", strconv.Itoa(seconds), // kill, no need to play nice
			path.Join(browser, "Browser", "start-tor-browser"), "--debug", url)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		tb.Stdout = &stdout
		tb.Stderr = &stderr

		// fills stdout and stderr
		tb.Run()

		if !gotData(stdout) {
			err = fmt.Errorf("didn't get enough data while attempting to browse, stdout (%s), stderr (%s)",
				stdout.String(), stderr.String())
			continue
		}

		// we need to wait for killing tb and any lagging data
		time.Sleep(2 * time.Second)
		return stdout.Bytes(), nil
	}
	return
}

func clean() (err error) {
	// get a fresh copy of the temporary data browser dir
	err = os.RemoveAll(path.Join(browser, dataBrowserDir))
	if err != nil {
		return fmt.Errorf("failed to remove Browser directory at %s (%s)",
			path.Join(browser, dataBrowserDir), err)
	}
	cp := exec.Command("cp", "-rfT", path.Join(*origBrowser, dataBrowserDir),
		path.Join(browser, dataBrowserDir))
	err = cp.Run()
	if err != nil {
		return fmt.Errorf("failed to copy Browser directory to %s (%s)",
			path.Join(browser, dataBrowserDir), err)
	}

	// delete files for Tor in the data dir we do not want to keep
	files, err := ioutil.ReadDir(path.Join(browser, dataTorDir))
	if err != nil {
		return fmt.Errorf("failed to read data dir (%s)", err)
	}
	for _, f := range files {
		if !f.IsDir() {
			ok := false
			for _, name := range okTorData {
				if strings.Contains(f.Name(), name) {
					ok = true
					break
				}
			}
			if !ok {
				os.RemoveAll(path.Join(browser, dataTorDir, f.Name()))
				if err != nil {
					return fmt.Errorf("failed to remove Tor data file %s (%s)",
						path.Join(dataTorDir, f.Name()), err)
				}
			}
		}
	}
	return
}

func gotData(in bytes.Buffer) bool {
	domain := false
	begin := false
	bootstrapped := false
	scanner := bufio.NewScanner(bytes.NewReader(in.Bytes()))
	for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), " ")
		if len(tokens) > 5 {
			switch tokens[4] {
			case "OUTGOING":
				if len(tokens) > 10 && tokens[10] == "BEGIN(1)" {
					begin = true
				}
			case "DNSRESOLVED":
				domain = true
			case "Bootstrapped":
				if len(tokens) > 6 && tokens[5] == "100%:" {
					bootstrapped = true
				}
			}
		}
		if begin && domain && bootstrapped {
			return true
		}
	}
	return false
}
