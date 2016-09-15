package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/montanaflynn/stats"
)

type sample struct {
	requests []request
}

type request struct {
	domain string
	ttl    int
	ips    []string
}

const (
	torMinTTL = 60
	torMaxTTL = 30 * 60
)

var (
	maxShow = flag.Int("m", 5,
		"the maximum number of most frequently domains to show")
	alexa = flag.String("alexa", "top-1m.csv",
		"the Alexa top-1m file with domain names")
	cloudflare = flag.String("cloudflare", "ips-v4", "the Cloudflare ipv4 blocks")
	maxSamples = flag.Int("s", -1, "set a maximum number of samples to load")
	torTTL     = flag.Bool("t", true, "set the DNS TTL to Tor [min,max]")

	families = map[string][]string{
		"CloudFlare": {"cloudflare"},
		"Amazon":     {"amazon", "aws", "s3", "cloudfront", "ec2"},
		"Google": {"google", "doubleclick", "gstatic", "android.com", "2mdn.net",
			"cc-dt.com", "gvt1.com", "gvt2.com", "urchin.com", "youtube-nocookie.com",
			"youtube.com", "youtubeeducation.com", "ytimg.com", "g.co", "goo.gl"},
		"Facebook": {"facebook", "fbcdn"},
		"Akamai":   {"akamai", "edgesuite", "edgekey", "srip", "akadns"},
	}
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("need to specify data dir")
	}

	log.Printf("getting list of files in %s", flag.Arg(0))
	files, er := ioutil.ReadDir(flag.Arg(0))
	if er != nil {
		log.Fatalf("failed to read data dir (%s)", er)
	}

	log.Printf("OK, starting to read data from files...")

	// read data
	data := make(map[int][]sample)
	for i := 0; i < len(files); i++ {
		if !files[i].IsDir() && strings.HasSuffix(files[i].Name(), ".dns") {
			site, err := strconv.Atoi(files[i].Name()[:strings.Index(files[i].Name(),
				"-")])
			if err != nil {
				log.Fatalf("failed to parse site index from file %s (%s)",
					files[i].Name(), err)
			}
			// only load as many samples as specified
			if *maxSamples != -1 && len(data[site]) >= *maxSamples {
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
			f.Close()
		}
	}

	log.Println("reading Alexa and CloudFlare files")
	// the primary sites in the data dir
	sites, err := readAlexa(*alexa, len(data))
	if err != nil {
		log.Fatalf("failed to read Alexa file (%s)", err)
	}
	// cloudflare networks
	networks, err := readCloudflare(*cloudflare)
	if err != nil {
		log.Fatalf("failed to read CloudFlare IPv4 blocks (%s)", err)
	}

	log.Println("computing data structures seen, ttlmap, and domainsPerSite")
	var domainCountPerSite, domainTTLs []int
	var mostSeenCount, sampleCount int
	// for a domain, a list of sites where this domain was requested
	seen := make(map[string][]int)
	ttlmap := make(map[string][]int) // for a domain, a list of observed TTLs
	domainsPerSite := make(map[int]map[string]bool)

	for site, samples := range data {
		if len(samples) > sampleCount {
			sampleCount = len(samples)
		}
		domains := make(map[string]bool)
		for _, sample := range samples {
			domainCount := 0
			for _, request := range sample.requests {
				seen[request.domain] = appendIfNew(seen[request.domain], site)
				domainCount++
				domains[request.domain] = true
				if len(seen[request.domain]) > mostSeenCount {
					// how many times did we see the most visited domain
					mostSeenCount = len(seen[request.domain])
				}

				domainTTLs = append(domainTTLs, request.ttl)
				ttlmap[request.domain] = append(ttlmap[request.domain], request.ttl)
			}
			domainCountPerSite = append(domainCountPerSite, domainCount)
		}
		domainsPerSite[site] = domains
	}

	log.Println("computing primaryDomainTTLs and missingPrimaryDomain")
	// primary domains stats
	var primaryDomainTTLs []int
	var missingPrimaryDomain int
	for i := 0; i < len(sites); i++ {
		t, exists := ttlmap[sites[i][1]]
		if exists {
			primaryDomainTTLs = append(primaryDomainTTLs, t...)
		} else {
			missingPrimaryDomain++
		}
	}

	log.Println("computing uniqueDomains and uniqueDomainsTTL")
	uniqueDomains := make(map[int][]string)
	uniqueDomainsTTL := make(map[int][]int)
	var uniqueTTLs []int
	for site, samples := range data {
		counted := make(map[string]bool)
		for _, sample := range samples {
			for _, request := range sample.requests {
				seenSites, _ := seen[request.domain]
				unique := true
				for _, s := range seenSites {
					if s != site {
						unique = false
						break
					}
				}
				if unique {
					_, done := counted[request.domain]
					if !done {
						counted[request.domain] = true
						uniqueDomains[site] = append(uniqueDomains[site], request.domain)
					}
					uniqueTTLs = append(uniqueTTLs, request.ttl)
					uniqueDomainsTTL[site] = append(uniqueDomainsTTL[site], request.ttl)
				}
			}
		}
	}

	log.Println("computing more uniquestats")
	var uniqueCount []int  // count the number of unique domains for each site
	var uniqueMinTTL []int // the lowest TTL for a unique domain for each site
	var uniqueMinBelowTorMinTTL int
	var uniqueMinAboveTorMaxTTL int
	for i := 0; i < len(sites); i++ {
		uniqueCount = append(uniqueCount, len(uniqueDomains[i+1]))

		minTTL := -1
		ttls, exists := uniqueDomainsTTL[i+1]
		if exists {
			for _, ttl := range ttls {
				if minTTL == -1 || ttl < minTTL {
					minTTL = ttl
				}
			}
		}

		if minTTL > -1 {
			uniqueMinTTL = append(uniqueMinTTL, minTTL)

			if minTTL < torMinTTL {
				uniqueMinBelowTorMinTTL++
			}
			if minTTL > torMaxTTL {
				uniqueMinAboveTorMaxTTL++
			}
		}
	}
	// for common (non-unique) domains, how many sites are they on?
	var commonDomainSiteCount []int
	for _, seenSites := range seen {
		if len(seenSites) > 1 {
			commonDomainSiteCount = append(commonDomainSiteCount, len(seenSites))
		}
	}
	umean, ustd, umedian, usum, umin, umax := miscStats(uniqueCount)

	log.Println("looking for CloudFlare IPs")
	// look for CloudFlare IPs
	primarySitesWithCF := make(map[int]bool)
	sitesWithCF := make(map[int]bool)
	for site, samples := range data {
		for _, s := range samples {
			for _, r := range s.requests {
				for _, p := range r.ips {
					ip := net.ParseIP(p)
					for _, n := range networks {
						if n.Contains(ip) {
							if strings.EqualFold(r.domain, sites[site-1][1]) {
								primarySitesWithCF[site] = true
							}
							sitesWithCF[site] = true
						}
					}
				}
			}
		}
	}

	log.Println("writing graphdata")
	var csvdata []byte
	csvdata = append(csvdata, []byte("site,uniqueCount\n")...)
	for i := 0; i < len(data); i++ {
		count := len(uniqueDomains[i+1])
		csvdata = append(csvdata, []byte(fmt.Sprintf("%d,%d\n", i+1, count))...)
	}

	err = ioutil.WriteFile("uniquePerDomain.csv", csvdata, 0666)
	if err != nil {
		log.Fatalf("failed to write uniquePerDomain.csv (%s)", err)
	}

	log.Println("done, time for results!")

	dmean, dstd, dmedian, dsum, dmin, dmax := miscStats(domainCountPerSite)
	tmean, tstd, tmedian, _, tmin, tmax := miscStats(domainTTLs)
	pmean, pstd, pmedian, _, pmin, pmax := miscStats(primaryDomainTTLs)
	uTTLmean, uTTLstd, uTTLmedian, _, uTTLmin, uTTLmax := miscStats(uniqueTTLs)
	uminTTLmean, uminTTLstd, uminTTLmedian, _, uminTTLmin, uminTTLmax := miscStats(uniqueMinTTL)
	cmean, cstd, cmedian, _, cmin, cmax := miscStats(commonDomainSiteCount)

	log.Printf("parsed %d sites with %d samples each, total of %.0f DNS requests and %d domains",
		len(data), sampleCount, dsum, len(seen))
	log.Printf("the dataset has %d incomplete pcaps out of %d",
		missingPrimaryDomain, len(data)*sampleCount)
	if *torTTL {
		log.Printf("DNS TTLs are set as over Tor [%d,%d]", torMinTTL, torMaxTTL)
	} else {
		log.Printf("DNS TTLs are as returned by the DNS server")
	}
	log.Printf("primary sites DNS records TTL mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		pmean, pstd, pmedian, pmin, pmax)
	log.Printf("number of DNS requests per site mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		dmean, dstd, dmedian, dmin, dmax)
	log.Printf("DNS records TTL mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		tmean, tstd, tmedian, tmin, tmax)
	log.Println("for WF-attacks on Tor using DNS:")
	log.Printf("\t%d unique domains, per site mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		int(usum), umean, ustd, umedian, umin, umax)
	log.Printf("\tthere are %d sites with unique domains (%.1f%% of all sites)",
		len(uniqueMinTTL), float64(len(uniqueMinTTL))/float64(len(data))*100)
	log.Printf("\tunique domain TTL mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		uTTLmean, uTTLstd, uTTLmedian, uTTLmin, uTTLmax)
	log.Printf("\tunique domain _min_ TTL mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		uminTTLmean, uminTTLstd, uminTTLmedian, uminTTLmin, uminTTLmax)
	if !*torTTL {
		// can only compute this if we don't run on Tor TTLs
		log.Printf("\t%d sites with unique domain TTLs below Tor's min TTL (%.2f%% of all sites)",
			uniqueMinBelowTorMinTTL, float64(uniqueMinBelowTorMinTTL)/float64(len(data))*100)
		log.Printf("\t%d sites with unique domain TTLs above Tor's max TTL (%.2f%% of all sites)",
			uniqueMinAboveTorMaxTTL, float64(uniqueMinAboveTorMaxTTL)/float64(len(data))*100)
	}
	log.Printf("\tcommon domains appear on sites mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		cmean, cstd, cmedian, cmin, cmax)

	log.Printf("IP-addresses that belong to CloudFlare")
	log.Printf("\tseen at %d primary sites (%.2f%% of all sites)",
		len(primarySitesWithCF), float64(len(primarySitesWithCF))/float64(len(data))*100)
	log.Printf("\tseen at %d sites in total (%.2f%% of all sites)",
		len(sitesWithCF), float64(len(sitesWithCF))/float64(len(data))*100)
	log.Printf("\t%d non-primary sites (%.2f%% of all sites)",
		len(sitesWithCF)-len(primarySitesWithCF),
		float64(len(sitesWithCF)-len(primarySitesWithCF))/float64(len(data))*100)

	seenList := make([][]string, mostSeenCount+1)
	for site, c := range seen {
		seenList[len(c)] = append(seenList[len(c)], site)
	}
	log.Println("")
	log.Printf("the %d most frequently requested domains", *maxShow)
	maxIndex := len(seenList) - 1
	shown := 0
	maxSum := 0
	for i := 0; shown < *maxShow; i++ {
		if len(seenList[maxIndex-i]) > 0 {
			shown++
			out := ""
			for j := 0; j < len(seenList[maxIndex-i]); j++ {
				mean, std, median, _, min, max := miscStats(ttlmap[seenList[maxIndex-i][j]])
				out = fmt.Sprintf("%s (TTL mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f)",
					seenList[maxIndex-i][j], mean, std, median, min, max)
			}
			log.Printf("\t %d:\t %d\t %s", shown, maxIndex-i, out)
			maxSum += maxIndex - i
		}
	}
	log.Printf("the top %d domains have %d requests (%.2f%% of total)",
		*maxShow, maxSum, float64(maxSum)/dsum*100)

	for family, keywords := range families {
		log.Println("")
		log.Printf("%s stats, keywords %s", family, keywords)
		printFamily(seen, domainsPerSite, ttlmap, dsum, keywords)
	}
}

func miscStats(d []int) (mean, std, median, sum, min, max float64) {
	data := stats.LoadRawData(d)
	std, _ = data.StandardDeviation()
	mean, _ = data.Mean()
	median, _ = data.Median()
	min, _ = data.Min()
	max, _ = data.Max()
	sum, _ = data.Sum()
	return
}

func printFamily(seen map[string][]int, domainsPerSite map[int]map[string]bool,
	ttlmap map[string][]int, totalRequests float64, keywords []string) {
	seesCount := 0
	for _, domains := range domainsPerSite {
		sees := false
		for domain := range domains {
			for _, name := range keywords {
				if strings.Contains(domain, name) {
					if !strings.Contains(domain, "ocsp") {
						// ignore OCSP requests (here be dragons)
						sees = true
						break
					}
				}
			}
			if sees {
				break
			}
		}
		if sees {
			seesCount++
		}
	}

	var seenAtDomains []string
	var requests int
	for domain, c := range seen {
		for _, name := range keywords {
			if strings.Contains(domain, name) {
				seenAtDomains = append(seenAtDomains, domain)
				requests += len(c)
				break
			}
		}
	}
	var ttls []int
	for _, domain := range seenAtDomains {
		ttls = append(ttls, ttlmap[domain]...)
	}
	log.Printf("\tfound on %d sites (%.2f%% of all sites)",
		seesCount, float64(seesCount)/float64(len(domainsPerSite))*100)
	log.Printf("\t%d unique domains with %d requests (%.2f%% of total)",
		len(seenAtDomains), requests, float64(requests)/totalRequests*100)
	mean, std, median, _, min, max := miscStats(ttls)
	log.Printf("\tTTL mean %.1f, std %.1f, median %.1f, min %.1f, max %.1f",
		mean, std, median, min, max)
}

func readAlexa(alexafile string, count int) (sites [][]string, err error) {
	f, err := os.Open(alexafile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file with alexa sites (%s)", err)
	}
	r := csv.NewReader(f)
	sites, err = r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read file with alexa sites (%s)", err)
	}

	return sites[:count], nil
}

func readCloudflare(cloudflarefile string) (networks []net.IPNet, err error) {
	f, err := os.Open(cloudflarefile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file with cloudflare ipv4 blocks (%s)", err)
	}
	r := csv.NewReader(f)
	lines, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read file with cloudflare ipv4 blocks (%s)", err)
	}

	for _, l := range lines {
		_, n, err := net.ParseCIDR(l[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse cloudflare ipv CIDR (%s)", err)
		}
		networks = append(networks, *n)
	}

	return
}

func appendIfNew(data []int, item int) []int {
	for _, i := range data {
		if i == item {
			return data
		}
	}
	return append(data, item)
}

func getUniqueDomains(data map[int][]sample,
	forTesting func(int, int) bool) (siteUniqueDomains map[int][]string) {
	// domain -> sites seen on
	seen := make(map[string][]int)
	for site, samples := range data {
		for samp, s := range samples {
			for _, req := range s.requests {
				if !forTesting(site, samp) {
					seen[req.domain] = append(seen[req.domain], site)
				}
			}
		}
	}

	// determine if each domain is unique or not
	uniqueDomain := make(map[string]bool)
	for domain, sites := range seen {
		uniqueDomain[domain] = true
		s := sites[0]
		for _, site := range sites {
			if s != site {
				uniqueDomain[domain] = false
				break
			}
		}
	}

	// build site -> list of unique domains
	siteUniqueDomains = make(map[int][]string)
	for domain := range uniqueDomain {
		site := seen[domain][0] // unique domain -> all on same site
		siteUniqueDomains[site] = append(siteUniqueDomains[site], domain)
	}

	return
}

func getDomainCount(data map[int][]sample,
	forTesting func(int, int) bool) (domains map[string]int) {
	domains = make(map[string]int)
	for site, samples := range data {
		for samp, s := range samples {
			for _, req := range s.requests {
				if forTesting(site, samp) {
					domains[req.domain]++
				}
			}
		}
	}

	return
}
