package main

import (
	"bufio"
	"flag"
	"log"
	"math"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/deckarep/golang-set"
)

func readData(files []os.FileInfo) (data map[int][]sample) {
	data = make(map[int][]sample)
	for i := 0; i < len(files); i++ {
		if !files[i].IsDir() && strings.HasSuffix(files[i].Name(), ".dns") {
			site, err := strconv.Atoi(files[i].Name()[:strings.Index(files[i].Name(),
				"-")])
			if err != nil {
				log.Fatalf("failed to parse site index from file %s (%s)",
					files[i].Name(), err)
			}
			if site > *sites+*open || // max sites to read
				(site <= *sites && len(data[site]) >= *instances) ||
				(site > *sites && len(data[site]) > 0) {
				continue
			}

			f, err := os.Open(path.Join(flag.Arg(0), files[i].Name()))
			if err != nil {
				log.Fatalf("failed to open file (%s)", err)
			}

			scanner := bufio.NewScanner(f)
			var sam sample
			for scanner.Scan() {
				// format is: domain,ttl<,ip>
				// where there are 0 or more ",ip"
				tokens := strings.Split(scanner.Text(), ",")
				ttl, err := strconv.Atoi(tokens[1])
				if err != nil {
					log.Fatalf("failed to parse TTL (%s)", err)
				}
				if *torTTL && ttl < torMinTTL {
					ttl = torMinTTL
				} else if *torTTL && ttl > torMaxTTL {
					ttl = torMaxTTL
				}
				var ips []string
				for j := 2; j < len(tokens); j++ {
					ips = append(ips, tokens[j])
				}
				sam.requests = append(sam.requests, request{
					domain: tokens[0],
					ttl:    ttl,
					ips:    ips,
				})
			}
			data[site] = append(data[site], sam)
			if len(data[site]) > sampleCount {
				sampleCount = len(data[site])
			}
			f.Close()
		}
	}
	return
}

func getSeenSites(data map[int][]sample,
	forTesting func(int, int) bool) (seen map[string][]int) {
	// domain -> sites seen on
	seen = make(map[string][]int)
	for site, samples := range data {
		for samp, s := range samples {
			for _, req := range s.requests {
				if !forTesting(site, samp) {
					seen[req.domain] = append(seen[req.domain], site)
				}
			}
		}
	}
	return
}

func getUniqueDomainsToSite(data map[int][]sample,
	forTesting func(int, int) bool,
	unmonitored func(int) bool) (uniqueDomainToSite map[string]int,
	siteHasUnique map[int]bool) {
	// domain -> sites seen on
	seen := getSeenSites(data, forTesting)

	// determine if each domain is unique or not
	uniqueDomainToSite = make(map[string]int)
	for domain, sites := range seen {
		if !unmonitored(sites[0]) { // no need to map unmonitored sites
			isUnique := true
			for _, site := range sites {
				if sites[0] != site {
					isUnique = false
					break
				}
			}
			if isUnique {
				uniqueDomainToSite[domain] = sites[0]
			}
		}
	}

	siteHasUnique = make(map[int]bool)
	for _, site := range uniqueDomainToSite {
		siteHasUnique[site] = true
	}
	return
}

func getCommonDomains(data map[int][]sample,
	hasUnique map[int]bool,
	forTesting func(int, int) bool,
	unmonitored func(int) bool) (common map[int][]string) {
	// site -> list of domains found in all samples
	common = make(map[int][]string)
	for site, samples := range data {
		_, unique := hasUnique[site]
		if !unmonitored(site) && !unique { // only care about monitored w/o unique
			first := true
			c := mapset.NewSet()
			for samp, s := range samples {
				if !forTesting(site, samp) {
					domains := mapset.NewSet()
					for _, req := range s.requests {
						domains.Add(req.domain)
					}
					if first {
						c = domains
						first = false
					} else {
						domains = domains.Intersect(c)
					}
				}
			}
			for domain := range c.Iter() {
				common[site] = append(common[site], domain.(string))
			}
		}
	}

	return
}

func addResult(base *metrics, result metrics) {
	base.fn += result.fn
	base.fnp += result.fnp
	base.fpp += result.fpp
	base.tn += result.tn
	base.tp += result.tp
}

// recall = TPR = TP / (TP + FN + FPP)
func recall(data []metrics) float64 {
	var p float64
	for i := 0; i < len(data); i++ {
		d := float64(data[i].tp) / float64(data[i].tp+data[i].fn+data[i].fpp)
		if !math.IsNaN(d) {
			p += d
		}
	}
	return p / float64(len(data))
}

// precision = TP / (TP + FPP + FNP)
func precision(data []metrics) float64 {
	var p float64
	for i := 0; i < len(data); i++ {
		d := float64(data[i].tp) / float64(data[i].tp+data[i].fpp+data[i].fnp)
		if !math.IsNaN(d) {
			p += d
		}
	}
	return p / float64(len(data))
}

func getDomains(req []request) (domains map[string]bool) {
	domains = make(map[string]bool)
	for _, r := range req {
		domains[r.domain] = true
	}
	return
}

func estimateOpenSize() {
	samples := 100
	total := 0
	for i := 0; i < samples; i++ {
		n := 0
		monitored := 0
		for monitored < *sites**instances {
			if powerlawRand() <= *sites {
				monitored++
			}
			n++
		}
		total += n - monitored
	}
	*open = total / samples
}

func powerlawRand() int {
	// parameters for xmin=0.01, a conservative choice to fit out data
	alpha := 1.13487087527372
	oneOverOneMinusAlpha := -7.414499223575910
	r := rand.Float64()
	for r > 0.9999999999999999 {
		//avoid input values that would lead to outputs above maxint
		r = rand.Float64()
	}

	return int(math.Ceil(math.Pow(alpha*(1.0-r), oneOverOneMinusAlpha)))
}

// FPR = FP / non-monitored elements = (FPP + FNP) / (TN + FNP)
func fpr(data []metrics) float64 {
	var p float64
	for i := 0; i < len(data); i++ {
		d := float64(data[i].fpp+data[i].fnp) / float64(data[i].tn+data[i].fnp)
		if !math.IsNaN(d) {
			p += d
		}
	}
	return p / float64(len(data))
}

// accuracy = (TP + TN) / (everything)
func accuracy(data []metrics) float64 {
	var p float64
	for i := 0; i < len(data); i++ {
		d := float64(data[i].tp+data[i].tn) /
			float64(data[i].fn+data[i].fnp+data[i].fpp+data[i].tn+data[i].tp)
		if !math.IsNaN(d) {
			p += d
		}
	}
	return p / float64(len(data))
}
