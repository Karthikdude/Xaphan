package runner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Karthikdude/Xaphan/pkg/core"
	"github.com/Karthikdude/Xaphan/pkg/fetcher"
	"github.com/Karthikdude/Xaphan/pkg/reporter"
	"github.com/Karthikdude/Xaphan/pkg/scanner"
	"github.com/Karthikdude/Xaphan/pkg/utils"
)

// Process worker handles domains
func Worker(id int, cfg *core.Config, jobs <-chan string, results chan<- map[string]interface{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range jobs {
		if cfg.UrlFlag != "" {
			fmt.Printf("\n  %s Processing domain: %s\n", utils.ColorizeText("▶", "cyan"), utils.ColorizeText(domain, "white"))
		}
		xssURLs := RunPipeline(cfg, domain)
		if len(xssURLs) == 0 {
			results <- map[string]interface{}{
				"domain":  domain,
				"details": []map[string]interface{}{},
				"error": fmt.Sprintf("\n  %s No XSS vulnerabilities found for %s\n",
					utils.ColorizeText("✓", "green"),
					utils.ColorizeText(domain, "white")),
			}
		} else {
			xssDetails := reporter.ExtractXSSDetails(cfg, xssURLs)
			results <- map[string]interface{}{
				"domain":  domain,
				"details": xssDetails,
			}
		}
		atomic.AddInt64(&cfg.ProcessedDomains, 1)
	}
}

// RunPipeline runs the entire fetching and scanning pipeline for a domain
func RunPipeline(cfg *core.Config, domain string) []string {
	var urls []string
	var err error

	scanType := ""
	scanTypeColor := ""
	fetchMethod := "GAU"

	if cfg.AllFlag {
		fetchMethod = "All Tools"
		scanType = "COMPREHENSIVE SCAN"
		scanTypeColor = "magenta"
	} else if cfg.WaybackFlag || cfg.GauFlag || cfg.UrlfindFlag {
		scanType = "PASSIVE SCAN"
		scanTypeColor = "green"
		if cfg.WaybackFlag {
			fetchMethod = "Wayback Machine"
		} else if cfg.UrlfindFlag {
			fetchMethod = "URLFinder"
		}
	} else if cfg.KatanaFlag || cfg.ArjunFlag || cfg.GospiderFlag || cfg.HakrawlerFlag {
		scanType = "ACTIVE SCAN"
		scanTypeColor = "red"
		if cfg.KatanaFlag {
			fetchMethod = "Katana"
		} else if cfg.ArjunFlag {
			fetchMethod = "Arjun"
		} else if cfg.GospiderFlag {
			fetchMethod = "Gospider"
		} else if cfg.HakrawlerFlag {
			fetchMethod = "Hakrawler"
		}
	}

	if scanType != "" {
		fmt.Printf("  %s %s %s\n",
			utils.ColorizeText("[", scanTypeColor),
			utils.ColorizeText(scanType, scanTypeColor),
			utils.ColorizeText("]", scanTypeColor))
	}

	fmt.Printf("  %s Fetching URLs for %s using %s...\n",
		utils.ColorizeText("⟳", "cyan"),
		utils.ColorizeText(domain, "white"),
		utils.ColorizeText(fetchMethod, "yellow"))

	timeout := time.After(time.Duration(cfg.TimeoutFlag) * time.Second)
	done := make(chan bool)

	go func() {
		if cfg.AllFlag {
			var allUrls []string
			var wg sync.WaitGroup
			urlChan := make(chan []string, 7)
			errChan := make(chan error, 7)

			fetchFunc := func(fetcherFunc func(*core.Config, string) ([]string, error), toolName string) {
				defer wg.Done()
				fmt.Printf("  %s Running %s for %s...\n",
					utils.ColorizeText("⟳", "cyan"),
					utils.ColorizeText(toolName, "yellow"),
					utils.ColorizeText(domain, "white"))

				toolUrls, err := fetcherFunc(cfg, domain)
				if err != nil {
					fmt.Printf("  %s %s failed for %s: %v\n",
						utils.ColorizeText("✗", "red"), toolName, utils.ColorizeText(domain, "white"), err)
					errChan <- err
					urlChan <- []string{}
					return
				}

				fmt.Printf("  %s %s found %s URLs\n",
					utils.ColorizeText("✓", "green"), toolName, utils.ColorizeText(fmt.Sprintf("%d", len(toolUrls)), "white"))
				urlChan <- toolUrls
			}

			wg.Add(7)
			go fetchFunc(fetcher.FetchWaybackURLs, "Wayback Machine")
			go fetchFunc(fetcher.FetchGauURLs, "GAU")
			go fetchFunc(fetcher.FetchKatanaURLs, "Katana")
			go fetchFunc(fetcher.FetchUrlfinderURLs, "URLFinder")
			go fetchFunc(fetcher.FetchArjunParams, "Arjun")
			go fetchFunc(fetcher.FetchGospiderURLs, "Gospider")
			go fetchFunc(fetcher.FetchHakrawlerURLs, "Hakrawler")

			go func() {
				wg.Wait()
				close(urlChan)
				close(errChan)
			}()

			for toolUrls := range urlChan {
				allUrls = append(allUrls, toolUrls...)
			}

			if len(allUrls) == 0 {
				if len(errChan) > 0 {
					fmt.Printf("  %s All tools failed to fetch URLs for %s\n",
						utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"))
				} else {
					fmt.Printf("  %s No URLs found for %s with any tool\n",
						utils.ColorizeText("!", "yellow"), utils.ColorizeText(domain, "white"))
				}
				done <- true
				return
			}

			urlMap := make(map[string]bool)
			for _, url := range allUrls {
				urlMap[url] = true
			}

			urls = make([]string, 0, len(urlMap))
			for url := range urlMap {
				urls = append(urls, url)
			}

			fmt.Printf("  %s Combined and deduplicated to %s unique URLs\n",
				utils.ColorizeText("✓", "green"), utils.ColorizeText(fmt.Sprintf("%d", len(urls)), "white"))

			done <- true
			return
		}

		if cfg.WaybackFlag {
			urls, err = fetcher.FetchWaybackURLs(cfg, domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"), err)
				done <- true
				return
			}
		} else if cfg.GauFlag {
			urls, err = fetcher.FetchGauURLs(cfg, domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"), err)
				done <- true
				return
			}
		} else if cfg.KatanaFlag {
			urls, err = fetcher.FetchKatanaURLs(cfg, domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"), err)
				done <- true
				return
			}
		} else if cfg.UrlfindFlag {
			urls, err = fetcher.FetchUrlfinderURLs(cfg, domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"), err)
				done <- true
				return
			}
		} else if cfg.ArjunFlag {
			urls, err = fetcher.FetchArjunParams(cfg, domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch parameters for %s: %v\n", utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"), err)
				done <- true
				return
			}
		} else if cfg.GospiderFlag {
			urls, err = fetcher.FetchGospiderURLs(cfg, domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"), err)
				done <- true
				return
			}
		} else if cfg.HakrawlerFlag {
			urls, err = fetcher.FetchHakrawlerURLs(cfg, domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", utils.ColorizeText("✗", "red"), utils.ColorizeText(domain, "white"), err)
				done <- true
				return
			}
		}
		done <- true
	}()

	select {
	case <-done:
		if len(urls) == 0 {
			fmt.Printf("  %s No URLs found for %s\n", utils.ColorizeText("!", "yellow"), utils.ColorizeText(domain, "white"))
			return []string{}
		}
		fmt.Printf("  %s Found %s URLs for %s\n", utils.ColorizeText("✓", "green"), utils.ColorizeText(fmt.Sprintf("%d", len(urls)), "white"), utils.ColorizeText(domain, "white"))
	case <-timeout:
		fmt.Printf("  %s URL collection for %s timed out after %d seconds. Using collected URLs.\n", utils.ColorizeText("⚠", "yellow"), utils.ColorizeText(domain, "white"), cfg.TimeoutFlag)
	}

	if cfg.SaveFlag != "" {
		if err := scanner.SaveURLsToFile(urls, cfg.SaveFlag, domain+"-raw"); err != nil {
			fmt.Printf("  %s Failed to save raw URLs: %v\n", utils.ColorizeText("✗", "red"), err)
		}
	}

	// 1. GF
	filteredGfURLs := scanner.RunGfXss(cfg, urls, domain)
	if len(filteredGfURLs) == 0 {
		return []string{}
	}

	// 2. URO
	filteredUroURLs := scanner.RunUro(cfg, filteredGfURLs, domain)

	// 3. Batches with Gxss and Kxss
	batchSize := scanner.DetermineBatchSize(len(filteredUroURLs))
	batches := scanner.SplitIntoBatches(filteredUroURLs, batchSize)

	fmt.Printf("  %s Testing endpoints in %s batches...\n", utils.ColorizeText("⟳", "cyan"), utils.ColorizeText(fmt.Sprintf("%d", len(batches)), "white"))
	fmt.Printf("  %s Processing batches: %d/%d completed", utils.ColorizeText("⟳", "cyan"), 0, len(batches))

	var finalURLs []string
	batchResults := make(chan []string, len(batches))
	concurrencyLimit := 3
	if len(batches) < concurrencyLimit {
		concurrencyLimit = len(batches)
	}

	sem := make(chan bool, concurrencyLimit)
	var wg sync.WaitGroup

	for i, batch := range batches {
		wg.Add(1)
		go func(batchNum int, bUrls []string) {
			defer wg.Done()
			sem <- true
			defer func() { <-sem }()

			gxssURLs := scanner.ProcessBatchWithGxss(bUrls)
			kxssURLs := scanner.ProcessBatchWithKxss(gxssURLs)
			batchResults <- kxssURLs

			fmt.Printf("\r  %s Processing batches: %d/%d completed", utils.ColorizeText("⟳", "cyan"), batchNum+1, len(batches))
		}(i, batch)
	}

	go func() {
		wg.Wait()
		close(batchResults)
	}()

	for result := range batchResults {
		finalURLs = append(finalURLs, result...)
	}

	fmt.Printf("\r  %s All batches processed successfully           \n", utils.ColorizeText("✓", "green"))
	fmt.Printf("  %s Found %s potential XSS vulnerabilities in %s\n\n",
		utils.ColorizeText("✓", "green"),
		utils.ColorizeText(fmt.Sprintf("%d", len(finalURLs)), func() string {
			if len(finalURLs) > 0 {
				return "red"
			}
			return "green"
		}()),
		utils.ColorizeText(domain, "white"))

	return finalURLs
}
