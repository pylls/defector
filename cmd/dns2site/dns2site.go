/*
Package main implements a naive dns2site classifier and evalutes it.  Observing
DNS requests is surprisingly useful for determining visited websites.
The tool operates on ".dns" files from the extractdns tool.
*/
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"runtime"
	"sync"
	"time"
)

type sample struct {
	requests []request
}

type request struct {
	domain string
	ttl    int
	ips    []string
}

type fingerprints struct {
	uniqueDomainToSite map[string]int
	commonDomains      map[int][]string
}

type metrics struct {
	// see http://www.cs.kau.se/pulls/hot/measurements/
	tp  int // true positive
	fpp int // false-positive-to-positive
	fnp int // false-negative-to-positive
	fn  int // false negative
	tn  int // true negative
}

type work struct {
	reqs []request
	site int
}

const (
	torMinTTL = 60
	torMaxTTL = 30 * 60
)

var (
	torTTL    = flag.Bool("t", true, "set the DNS TTL to Tor [min,max]")
	sites     = flag.Int("sites", 1000, "max sites to load")
	instances = flag.Int("instances", 0, "number of instances per site")
	open      = flag.Int("open", -1, "number of open-world sites")
	k         = flag.Int("k", 1, "the number of votes for classification")

	useCommon = flag.Bool("common", false,
		"use common domains in classification")
	sampleCount int
)

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("need to specify data dir")
	}
	log.Printf("getting list of files in %s", flag.Arg(0))
	files, er := ioutil.ReadDir(flag.Arg(0))
	if er != nil {
		log.Fatalf("failed to read data dir (%s)", er)
	}

	log.Printf("mapping: unique domains and common domains [%v] with %d votes",
		*useCommon, *k)

	if *open == -1 {
		log.Printf("estimating open-world to match powerlaw and %dx%d monitored",
			*sites, *instances)
		estimateOpenSize()
		log.Printf("estimated open-world %d", *open)
	}

	log.Printf("attempting to read %dx%d+%d sites", *sites, *instances, *open)
	data := readData(files)
	if len(data) < *sites+*open {
		log.Fatalf("expected to read %d sites, got %d", *sites, len(data))
	}

	// k-fold cross validation of data
	log.Printf("performing %d-fold cross-validation", sampleCount)
	results := make([]metrics, sampleCount)

	unmonitored := func(site int) bool { // unmonitored function
		return site > *sites
	}

	for fold := 0; fold < sampleCount; fold++ {
		log.Printf("starting fold %d", fold+1)
		forTesting := func(site, sampl int) bool {
			return (!unmonitored(site) && sampl == fold) ||
				(unmonitored(site) && site%sampleCount == fold)
		}
		log.Printf("\ttraining...")
		fps := training(data, forTesting, unmonitored)
		log.Printf("\ttesting...")
		results[fold] = testing(data, fps, forTesting, unmonitored)
	}
	log.Printf("%.3f recall, %.3f precision, %.3f FPR, %.3f accuracy",
		recall(results), precision(results), fpr(results), accuracy(results))
	for i := 0; i < len(results); i++ {
		log.Printf("\ttp%d,fpp%d,fnp%d,fn%d,tn%d\n",
			results[i].tp, results[i].fpp, results[i].fnp,
			results[i].fn, results[i].tn)
	}

}

func training(data map[int][]sample,
	forTesting func(int, int) bool,
	unmonitored func(int) bool) (fps fingerprints) {
	uniqueDomainToSite, siteHasUnique := getUniqueDomainsToSite(data,
		forTesting, unmonitored)
	fps.uniqueDomainToSite = uniqueDomainToSite
	if *useCommon {
		fps.commonDomains = getCommonDomains(data, siteHasUnique,
			forTesting, unmonitored)
	}
	return
}

func testing(data map[int][]sample, fps fingerprints,
	forTesting func(int, int) bool,
	unmonitoredSite func(int) bool) (result metrics) {
	// create workers
	wIn := make(chan work)
	wOut := make(chan metrics, len(data)*sampleCount)
	wg := new(sync.WaitGroup)
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range wIn {
				wOut <- outcome(work.site,
					classify(getDomains(work.reqs), fps), unmonitoredSite)
			}
		}()
	}
	log.Printf("\t\tspawned %d testing workers", runtime.NumCPU())

	// give out work
	testing := 0
	for site, samples := range data {
		for si, sampl := range samples {
			if forTesting(site, si) {
				wIn <- work{
					reqs: sampl.requests,
					site: site,
				}
				testing++
				fmt.Printf("\r\t\t testing %d", testing)
			}
		}
	}
	fmt.Println("")

	// wait and put together result
	close(wIn)
	wg.Wait()
	close(wOut)
	for res := range wOut {
		addResult(&result, res)
	}

	return
}

func classify(domains map[string]bool, fps fingerprints) (class int) {
	votes := make(map[int]int)
	// any unqiue domains?
	for domain := range domains {
		site, exists := fps.uniqueDomainToSite[domain]
		if exists {
			votes[site]++
		}
	}

	// all common domains for a site? only if we didn't find _one_ unique site
	if *useCommon && len(votes) != 1 {
		for site, common := range fps.commonDomains {
			allFound := true
			for _, d := range common {
				_, exists := domains[d]
				if !exists {
					allFound = false
					break
				}
			}
			if allFound {
				votes[site]++
			}
		}
	}

	return getClass(votes)
}

func getClass(votes map[int]int) int {
	maxVote := -1
	maxSite := -1
	for site, vote := range votes {
		if vote > maxVote {
			maxSite = site
			maxVote = vote
		}
	}
	if maxSite == -1 || maxVote < *k {
		return -1
	}
	return maxSite
}

func outcome(trueclass, output int,
	unmonitoredSite func(int) bool) (m metrics) {
	if unmonitoredSite(trueclass) {
		trueclass = -1
	}

	if output == trueclass {
		if trueclass > 0 {
			// found the right monitored site
			m.tp++
		} else {
			// correctly identified an unmonitored site
			m.tn++
		}
	} else { // wrong :(
		if output == -1 {
			// false negative: said unmonitored for a monitored
			m.fn++
		} else {
			if trueclass == -1 {
				// classifier said an unmonitored site was monitored
				m.fnp++
			} else {
				// classifier said the wrong monitored site
				m.fpp++
			}
		}
	}
	return
}
