package main

import (
	"math"
	"math/rand"
)

func simTorNetwork(obsPct, seconds int,
	getSite func() int) (observed map[int]bool) {
	observed = make(map[int]bool)
	obsFrac := float64(obsPct) / float64(100)
	n := siteCount(seconds, obsFrac)

	if *useDNS2site {
		// precision is primarly false-negative-to-positive, resulting in extra
		// monitored (identified) sites
		// and we assume we monitor most websites in DNS-to-Site FP
		n += int(float64(n) * (1 - *dnsPrecision))
	}

	for i := 0; i < n; i++ {
		site := getSite() // [1, infinity)

		if *useDNS2site {
			// recall: the client visited a site, but we didn't detect it
			if rand.Float64() >= *dnsRecall {
				continue
			}
		}

		// only append site that is monitored
		if *alexaRank <= site && site < *sites+*alexaRank {
			observed[site-*alexaRank] = true // sites are indexed from 0
		}
	}

	return
}

func genSeenFunc(i, obsPct int, observed map[int]bool) func(int) bool {
	visitedSite := (i / *instances)
	if visitedSite >= *sites {
		visitedSite = -1 // unmonitored
	}

	// flip based on pct if we should include our site or not
	visited := (rand.Intn(100) < obsPct && visitedSite >= 0) &&
		(!*useDNS2site || rand.Float64() < *dnsRecall) // perfect or dns2site

	return func(site int) bool {
		_, obs := observed[site]
		// we observed the site in the network due to someone else browsing it
		// at the same time OR due to observing our target visiting the site
		return obs || (visited && site == visitedSite)
	}
}

func siteCount(seconds int, obsFrac float64) int {
	// this is based on 700k active web circuits / 10 min from Jansen and Johnson,
	// which should be an upper limit for the number of different websites visited
	// over Tor in the same timeframe.
	return int(math.Ceil(1166.67*float64(seconds)*obsFrac) * *scaleTor)
}

func genPowerLawRand(alpha float64) func() int {
	oneOverOneMinusAlpha := 1 / (1 - alpha)
	return func() int {
		r := rand.Float64()
		for r > 0.9999999999999999 {
			//avoid input values that would lead to outputs above maxint
			r = rand.Float64()
		}

		return int(math.Ceil(math.Pow(alpha*(1.0-r), oneOverOneMinusAlpha)))
	}
}

func getUniformRand(max int) func() int {
	return func() int {
		return rand.Intn(max) + 1
	}
}
