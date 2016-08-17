/*
 fpt runs two FingerprinTor attacks using:
 - the Wa-kNN website fingerprinting attack, and
 - a map of observed websites from a simulated Tor network.

 For the Tor network simulation, given:
 - an estimate of the size of the Tor network,
 - a percentage of observed exit traffic by the attacker,
 - a website popularity distribution,
 - metrics for dns2site mapping, and
 - the starting Alexa rank of the monitored sites,
 we get a number of observed monitored sites in the DNS traffic from the Tor
 network.
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

type metrics struct { // see http://www.cs.kau.se/pulls/hot/measurements/
	tp  int // true positive
	fpp int // false-positive-to-positive
	fnp int // false-negative-to-positive
	fn  int // false negative
	tn  int // true negative
}

const (
	// FeatNum is the number of extracted features to consider in kNN.
	FeatNum int = 1225
	// FeatureSuffix is the suffix of files containing features.
	FeatureSuffix = ".feat"
	// RecoPointsNum is the number of neighbours for distance learning.
	RecoPointsNum int = 5
)

var (
	// data to experiment on
	mfolder = flag.String("mfolder", "alexa9kx100+900k-feat/",
		"folder with cell traces for monitored sites")
	ofolder = flag.String("ofolder", "alexa9kx100+900k-feat/",
		"folder with cell traces for open world")
	sites     = flag.Int("sites", 0, "number of sites")
	instances = flag.Int("instances", 0, "number of instances")
	open      = flag.Int("open", 0, "number of open-world sites")
	roffset   = flag.Int("roffset", 0, "the offset to read monitored sites from")

	// Wa-kNN-related
	weightRounds = flag.Int("r", 2500, "rounds for WLLCC weight learning in kNN")
	wKmin        = flag.Int("wKmin", 1, "the smallest k to test for with Wa-kNN")
	wKmax        = flag.Int("wKmax", 2, "the biggest k to test for with Wa-kNN")
	wKstep       = flag.Int("wKstep", 1, "the step size between wKmin and wKmax")

	// experiment tweaks
	workerFactor = flag.Int("f", 1,
		"the factor to multiply NumCPU with for creating workers")
	folds = flag.Int("folds", 10,
		"we perform k-fold cross-validation")
	verboseOutput = flag.Bool("verbose", true, "print detailed result output")
	lazy          = flag.Bool("lazy", true,
		"don't recalculate kNN-weights for the close-the-world attack")
	quiet = flag.Bool("quiet", false,
		"don't print detailed progress (useful for not spamming docker log)")

	// arguments for Tor simulation
	pctMin = flag.Int("pmin", 0,
		"the minimum percentage of Tor exit bandwidth to compute for")
	pctMax = flag.Int("pmax", 100,
		"the maximum percentage of Tor exit bandwidth to compute for")
	pctStep = flag.Int("pstep", 25,
		"the step of percentage between pmin and pmax")
	dnsRecall = flag.Float64("dnsrecall", 0.947, // from 500kx5 run +common
		"recall of mapping DNS requests to sites")
	dnsPrecision = flag.Float64("dnsprecision", 0.984, // from 500kx5 run +common
		"precision of mapping DNS requests to sites")
	useDNS2site = flag.Bool("usedns2site", true,
		"use DNS mapping (fp) to site metrics in Tor simulation")
	alexaRank = flag.Int("alexa", 1,
		"the Alexa rank of the first monitored site")
	window = flag.Int("window", 60,
		"the size of the sliding window for observing DNS requests at exits (s)")
	scaleTor = flag.Float64("scaletor", 1.0,
		"simulate a bigger Tor network")
	simdist = flag.String("simdist", "conpl",
		"distribution for sim. site visits in Tor: {con,real}pl or {con,real}uni")
)

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()
	if *sites == 0 || *instances == 0 {
		log.Println("missing sites and instances")
		flag.Usage()
		return
	}

	// can traces be split into k samples?
	if *instances%*folds != 0 || *open%*folds != 0 {
		log.Fatalf("error: k (%d) has to fold instances (%d) and open (%d) evenly",
			*folds, *instances, *open)
	}

	var simfunc func() int
	switch *simdist {
	case "conpl":
		// parameter for xmin=0.01, a conservative choice  we
		// manually fitted to Alexa data such that popular sites are less popular
		// than they actually are (this hurts our attacks)
		simfunc = genPowerLawRand(1.13487087527372)
	case "realpl":
		// parameter for xmin=13.74, what the powerlaw package tells us is a best
		// fit to the Alexa data
		simfunc = genPowerLawRand(1.98331802607295)
	case "conuni":
		// for whatever reason, only 1M active sites on the Internet
		// "people don't browse for ponies over Tor (only pwnies)"
		simfunc = getUniformRand(1000 * 1000)
	case "realuni":
		// the real number of active sites on the Internet in July 2016 according
		// to netcraft: http://news.netcraft.com/archives/2016/07/19/july-2016-web-server-survey.html
		simfunc = getUniformRand(173676692)

	default:
		log.Fatalf("invalid simdist argument")
	}

	// pctPoints is the percentage of Tor exit bandwidth the attacker observes
	var pctPoints []int
	for i := *pctMin; i <= *pctMax; i += *pctStep {
		pctPoints = append(pctPoints, i)
	}
	log.Printf("computing for %d percentage of Tor exit bandwidth", pctPoints)

	// read cells from datadir
	log.Println("attempting to read WF features...")
	feat, openfeat := readFeatures()
	log.Printf("read %d sites with %d instances (in total %d points)",
		*sites, *instances, len(feat))
	log.Printf("read %d sites for open world", len(openfeat))

	testPerFold := (*sites**instances + *open) / *folds

	// calculate global weights for kNN in parallel (they don't change per fold)
	globalWeights := make([][]float64, *folds)
	wg := new(sync.WaitGroup)
	for fold := 0; fold < *folds; fold++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			globalWeights[i] = wllcc(feat, openfeat, i, func(int) bool {
				return false // ignore nothing
			})
		}(fold)
	}
	wg.Wait()
	log.Printf("determined global kNN-weights for each fold")

	// results is pctPoint -> map["attack"] -> [folds]metrics
	results := make([]map[string][]metrics, len(pctPoints))
	for pctIndex := 0; pctIndex < len(pctPoints); pctIndex++ {
		results[pctIndex] = make(map[string][]metrics)
		for fold := 0; fold < *folds; fold++ {
			log.Printf("starting fold %d/%d for x-axis point %d/%d",
				fold+1, *folds, pctIndex+1, len(pctPoints))

			// simulate the Tor network and get observed sites
			observed := simTorNetwork(pctPoints[pctIndex], *window, simfunc)
			log.Printf("\tsimulated Tor network (has %.2f of monitored sites)",
				float64(len(observed))/float64(*sites))

			// start workers
			workerIn := make(chan int)
			workerOut := make(chan map[string]metrics,
				(*sites**instances+*open) / *folds + 1000)
			wg := new(sync.WaitGroup)
			for i := 0; i < runtime.NumCPU()**workerFactor; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := range workerIn {
						workerOut <- test(j, genSeenFunc(j, pctPoints[pctIndex], observed),
							fold, globalWeights[fold],
							feat, openfeat)
					}
				}()
			}
			log.Printf("\tspawned %d testing workers", runtime.NumCPU()**workerFactor)

			// for each testing instance
			testing := 0
			for i := 0; i < *sites**instances+*open; i++ {
				if instanceForTesting(i, fold) {
					workerIn <- i
					testing++
					if !*quiet {
						fmt.Printf("\r\t\t\ttesting %d/%d", testing, testPerFold)
					}
				}
			}
			if !*quiet {
				fmt.Println("")
			}

			close(workerIn)
			wg.Wait()
			close(workerOut)

			// save results
			for res := range workerOut {
				for attack, m := range res {
					_, exists := results[pctIndex][attack]
					if !exists {
						results[pctIndex][attack] = make([]metrics, *folds)
					}
					addResult(&results[pctIndex][attack][fold], &m)
				}
			}
		}
	}

	// results
	output := make(map[string]string)
	var attacks []string
	for attack := range results[0] {
		attacks = append(attacks, attack)
		output[attack] = "pct,recall,precision,f1score,fpr,accuracy\n"
	}
	sort.Strings(attacks) // for deterministic output

	for i := 0; i < len(pctPoints); i++ {
		for attack, m := range results[i] {
			output[attack] += fmt.Sprintf("%d,%.3f,%.3f,%.3f,%.3f,%.3f\n",
				pctPoints[i], recall(m), precision(m), f1score(m), fpr(m), accuracy(m))
			if *verboseOutput {
				for j := 0; j < len(m); j++ {
					output[attack] += fmt.Sprintf("\ttp%d,fpp%d,fnp%d,fn%d,tn%d\n",
						m[j].tp, m[j].fpp, m[j].fnp, m[j].fn, m[j].tn)
				}
			}
		}
	}

	fout := fmt.Sprintf("%s: wfdns for %dx%d+%d with a%d w%d r%d s%.2f\n\n",
		time.Now().String(), *sites, *instances, *open,
		*alexaRank, *window, *weightRounds, *scaleTor)
	for i := 0; i < len(attacks); i++ {
		log.Printf("%s attack", attacks[i])
		fmt.Printf("%s\n", output[attacks[i]])

		fout += fmt.Sprintf("%s attack\n%s\n", attacks[i], output[attacks[i]])
	}
	simmode := "perfect"
	if *useDNS2site {
		simmode = "dns2site"
	}
	writeResults(fout,
		fmt.Sprintf("%dx%d+%d-%s-a%d-w%d-r%d-s%.1f-%s.log",
			*sites, *instances, *open, simmode,
			*alexaRank, *window, *weightRounds, *scaleTor, *simdist))

	writeTorpctCSV(recall,
		fmt.Sprintf("%dx%d+%d-%s-a%d-w%d-r%d-s%.1f-%s-%s.csv",
			*sites, *instances, *open, simmode,
			*alexaRank, *window, *weightRounds, *scaleTor, *simdist, "recall"),
		results, attacks, pctPoints)
	writeTorpctCSV(precision,
		fmt.Sprintf("%dx%d+%d-%s-a%d-w%d-r%d-s%.1f-%s-%s.csv",
			*sites, *instances, *open, simmode,
			*alexaRank, *window, *weightRounds, *scaleTor, *simdist, "precision"),
		results, attacks, pctPoints)
}

func test(i int, seenSite func(int) bool, // test-specific
	fold int, globalWeight []float64, // fold-specific
	feat, openfeat [][]float64) (result map[string]metrics) {
	result = make(map[string]metrics)

	// kNN classification
	wKclasses, trueclass := classify(i, feat, openfeat,
		globalWeight, *wKmax, fold, func(int) bool { return false })

	// close the world classification
	ctwIgnoreFunc := func(s int) bool {
		return s < *sites && !seenSite(s) // ignore monitored sites we didn't see
	}
	ctwWeights := globalWeight
	if !*lazy {
		ctwWeights = wllcc(feat, openfeat, fold, ctwIgnoreFunc)
	}
	ctwClasses, _ := classify(i, feat, openfeat,
		ctwWeights, *folds, fold, ctwIgnoreFunc)

	for k := *wKmin; k <= *wKmax; k += *wKstep {
		n := fmt.Sprintf("k%s-", strconv.Itoa(k))

		// kNN
		classkNN := getkNNClass(wKclasses, trueclass, k)
		result[n+"wf"] = getResult(classkNN, trueclass)

		// ctw
		classCTW := getkNNClass(ctwClasses, trueclass, k)
		result[n+"ctw"] = getResult(classCTW, trueclass)

		// for getting higher precision (HP),
		// if kNN says a trace is a monitored site, then confirm that we
		// observed the site in the DNS data. If not, set as unmonitored.
		// This trades reduced FNP for increased FN.
		hpClass := classkNN
		if classkNN < *sites {
			if !seenSite(hpClass) {
				hpClass = *sites
			}
		}
		result[n+"hp"] = getResult(hpClass, trueclass)
	}

	return
}
