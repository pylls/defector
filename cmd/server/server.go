/*
Package main implements a simple server to distribute URLs to browse to for clients and collect the
resulting PCAPs and screenshots. Uses locks excessively but should be negligle for hundreds of
clients at least.
*/
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/pylls/defector"

	"google.golang.org/grpc"

	"golang.org/x/net/context"
)

const (
	port = ":55555"
)

type item struct {
	ID  string
	URL string
}

var (
	timeout      = flag.Int("t", 15, "the timeout (seconds) for each page load")
	samples      = flag.Int("s", 1, "the number of samples to get for each page")
	datadir      = flag.String("f", "data", "the folder to store data in")
	scheme       = flag.String("scheme", "http", "the scheme for pages where not specified")
	alltraffic   = flag.Bool("a", false, "request that clients collect all traffic")
	minDataLen   = flag.Int("m", 25, "the minimum number of bytes to accept as a data from a client")
	outputSuffix = flag.String("o", ".pcap", "the suffix for the output files")

	lock    sync.Mutex
	work    map[string]*item
	workers map[string]string
	done    int
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("need to specify file with pages as argument")
	}

	// make sure we can write to datadir
	err := os.MkdirAll(*datadir, 0700)
	if err != nil {
		log.Fatalf("failed to create datadir (%s)", err)
	}

	// read pages and validate as URLs
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatalf("failed to read file with pages (%s)", err)
	}
	r := csv.NewReader(f)
	pages, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < len(pages); i++ {
		_, err = url.Parse(pages[i][1])
		if err != nil {
			log.Fatalf("failed to parse page as URL (%s)", err)
		}
	}
	workers = make(map[string]string)

	// create work
	work = make(map[string]*item)
	for s := 0; s < *samples; s++ {
		for i := 0; i < len(pages); i++ {
			page, _ := url.Parse(pages[i][1])
			if page.Scheme == "" {
				page.Scheme = *scheme
			}
			id := pages[i][0] + "-" + strconv.Itoa(s)
			if _, err = os.Stat(outputFileName(id)); os.IsNotExist(err) {
				// only perform work if we have to
				work[id] = &item{
					ID:  id,
					URL: page.String(),
				}
			} else {
				done++
			}
		}
	}

	log.Printf("collecting %d sample(s) of %d sites over %s",
		*samples, len(pages), *scheme)
	if *alltraffic {
		log.Printf("%d seconds timeout, results in \"%s\", full capture in PCAPs",
			*timeout, *datadir)
	} else {
		log.Printf("%d seconds timeout, results in \"%s\", only capturing DNS in PCAPs",
			*timeout, *datadir)
	}

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("listening on %s", lis.Addr())

	// progress function
	go func() {
		total := len(pages) * *samples
		for {
			lock.Lock()
			if done == total {
				fmt.Println("")
				log.Printf("finished")
				os.Exit(0)
			}
			fmt.Printf("\r %8d done (%3.1f%%), %8d left to distribute (%3d workers)",
				done, float64(done)/float64(total)*100, len(work), len(workers))
			lock.Unlock()
			time.Sleep(1 * time.Second)
		}
	}()

	s := grpc.NewServer()
	pb.RegisterCollectServer(s, &server{})
	s.Serve(lis)
}

type server struct{}

func (s *server) Work(c context.Context,
	in *pb.Req) (out *pb.Browse, err error) {
	lock.Lock()
	defer lock.Unlock()

	// keep tabs on number of workers
	_, exists := workers[in.WorkerID]
	if !exists {
		workers[in.WorkerID] = in.WorkerID
		fmt.Println("")
		log.Printf("worker reporting for work: %s\n", in.WorkerID)
	}

	// completed work?
	if in.Browse.ID != "" {
		if len(in.Browse.Data) >= *minDataLen {
			err = store(in.Browse)
			if err != nil {
				return
			}

			_, exists := work[in.Browse.ID]
			if exists {
				// we restarted the server and a worker didn't
				// report a completed work in time
				delete(work, in.Browse.ID)
			}
		} else {
			// put back work, toggling www. prefix
			url := in.Browse.URL
			if strings.HasPrefix(url, "www.") {
				url = url[4:]
			} else {
				url = "www." + url
			}

			work[in.Browse.ID] = &item{
				ID:  in.Browse.ID,
				URL: url,
			}
		}

	}

	// find work
	for id, item := range work {
		defer delete(work, id)
		return &pb.Browse{
			ID:         item.ID,
			URL:        item.URL,
			Timeout:    int64(*timeout),
			AllTraffic: *alltraffic,
		}, nil
	}

	// no work right now
	return &pb.Browse{
		ID:      "",
		Timeout: int64(*timeout),
	}, nil
}

func store(in *pb.Browse) (err error) {
	if len(in.Data) > 0 {
		err = ioutil.WriteFile(outputFileName(in.ID), in.Data, 0666)
		if err != nil {
			return
		}
	}
	done++

	return nil
}

func outputFileName(id string) string {
	return path.Join(*datadir, path.Clean(id)+*outputSuffix)
}
