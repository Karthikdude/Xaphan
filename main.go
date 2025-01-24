package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

var (
	urlFlag      string
	listFlag     string
	waybackFlag  bool
	gauFlag      bool
	verboseFlag  bool
	responseFlag bool
	detailedFlag string
	jsonFlag     string
	helpFlag     bool
	thread       int
	processedDomains int64 // Counter for processed domains
	urlCache       *cache.Cache
)

func init() {
	flag.StringVar(&urlFlag, "url", "", "Scan a single domain.")
	flag.StringVar(&listFlag, "list", "", "File containing a list of domains to scan.")
	flag.BoolVar(&waybackFlag, "wayback", false, "Use Wayback Machine to fetch URLs.")
	flag.BoolVar(&gauFlag, "gau", false, "Use gau to fetch URLs.")
	flag.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output.")
	flag.BoolVar(&responseFlag, "response", false, "Display HTTP response status codes.")
	flag.StringVar(&detailedFlag, "detailed", "", "Save detailed report to a file.")
	flag.StringVar(&jsonFlag, "json", "", "Save results in JSON format.")
	flag.BoolVar(&helpFlag, "help", false, "Show this help message and exit.")
	flag.IntVar(&thread, "t", 50, "Number of threads to use for concurrent processing.")

	// Initialize the cache
	urlCache = cache.New(5*time.Minute, 10*time.Minute)
}

func displayBanner() {
	banner := `
[31m██╗  ██╗ █████╗ ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗
╚██╗██╔╝██╔══██╗██╔══██╗██║  ██║██╔══██╗████╗  ██║
 ╚███╔╝ ███████║██████╔╝███████║███████║██╔██╗ ██║
 ██╔██╗ ██╔══██║██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║
██╔╝ ██╗██║  ██║██║     ██║  ██║██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝[0m
[32m-----------------------------------------------------
           Developed by Karthik S Sathyan
-----------------------------------------------------[0m
[34mLinkedIn: https://www.linkedin.com/in/karthik-s-sathyan/[0m
`
	fmt.Println(banner)
}


func fetchWaybackURLs(domain string) ([]string, error) {
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch Wayback URLs")
	}
	defer resp.Body.Close()

	var urls []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	return urls, scanner.Err()
}

func fetchGauURLs(domain string) ([]string, error) {
	cmd := exec.Command("gau", domain)
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch Gau URLs")
	}
	return strings.Split(string(output), "\n"), nil
}

func checkURLStatus(url string) (int, error) {
	client := &http.Client{
		Timeout: 10 * time.Second, // Configurable timeout
	}
	resp, err := client.Head(url)
	if err != nil {
		return 0, errors.Wrap(err, "failed to check URL status")
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func determineSeverity(unfilteredSymbols []string) (string, string) {
	criticalSymbols := []string{`"`, `<`, `>`, `'`}
	mediumSymbols := []string{`$`, `|`, `:`, `;`}
	lowSymbols := []string{`[`, `]`}

	for _, symbol := range criticalSymbols {
		if contains(unfilteredSymbols, symbol) {
			return "\033[31m[CRITICAL]\033[0m", "\033[31m"
		}
	}
	for _, symbol := range mediumSymbols {
		if contains(unfilteredSymbols, symbol) {
			return "\033[33m[MEDIUM]\033[0m", "\033[33m"
		}
	}
	for _, symbol := range lowSymbols {
		if contains(unfilteredSymbols, symbol) {
			return "\033[34m[LOW]\033[0m", "\033[34m"
		}
	}
	return "\033[32m[SAFE]\033[0m", "\033[32m"
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func extractXSSDetails(urls []string, verbose bool, checkStatus bool) []map[string]interface{} {
	var xssDetails []map[string]interface{}
	for _, url := range urls {
		if strings.Contains(url, "Unfiltered: [") {
			unfilteredSymbols := strings.Split(strings.Trim(strings.Split(url, "Unfiltered: [")[1], "]"), " ")
			severity, severityColor := determineSeverity(unfilteredSymbols)
			statusCode := 0
			if checkStatus {
				var err error
				statusCode, err = checkURLStatus(url)
				if err != nil {
					fmt.Printf("\033[31m[ERROR] Failed to check status for %s: %v\033[0m\n", url, err)
				}
			}
			status := fmt.Sprintf("[Status: %d]", statusCode)
			timestamp := time.Now().Format("[04:01:02:2006]")
			xssDetails = append(xssDetails, map[string]interface{}{
				"url":           url,
				"severity":      severity,
				"status":        status,
				"timestamp":     timestamp,
				"severity_color": severityColor,
			})
			if verbose {
				fmt.Printf("\033[36m[INFO] Processed: %s\033[0m\n", url)
				fmt.Printf("\033[36m[INFO] Unfiltered Symbols: %v\033[0m\n", unfilteredSymbols)
				fmt.Printf("\033[36m[INFO] Severity: %s\033[0m\n", severity)
				if checkStatus {
					fmt.Printf("\033[36m[INFO] Status: %s\033[0m\n", status)
				}
				fmt.Printf("\033[36m[INFO] Timestamp: %s\033[0m\n", timestamp)
				fmt.Printf("\033[36m%s\033[0m\n", strings.Repeat("-", 50))
			}
		}
	}
	return xssDetails
}

func displayResults(xssDetails []map[string]interface{}, verbose bool, checkStatus bool) {
	if len(xssDetails) == 0 {
		fmt.Printf("\033[32m[INFO] No XSS vulnerabilities found.\033[0m\n")
		return
	}
	for _, detail := range xssDetails {
		fmt.Printf("\033[32m[INFO] %s %s %s\033[0m\n", detail["timestamp"], detail["severity"], detail["url"])
		if responseFlag {
			fmt.Printf("\033[32m[INFO] %s\033[0m\n", detail["status"])
		}
		fmt.Println()
		if verbose {
			fmt.Printf("\033[36m[INFO] Unfiltered Symbols: %v\033[0m\n", strings.Split(strings.Trim(strings.Split(detail["url"].(string), "Unfiltered: [")[1], "]"), " "))
			fmt.Printf("\033[36m[INFO] Severity: %s\033[0m\n", detail["severity"])
			if responseFlag {
				fmt.Printf("\033[36m[INFO] Status: %s\033[0m\n", detail["status"])
			}
			fmt.Printf("\033[36m[INFO] Timestamp: %s\033[0m\n", detail["timestamp"])
			fmt.Printf("\033[36m%s\033[0m\n", strings.Repeat("-", 50))
		}
	}
}

func saveDetailedReport(xssDetails []map[string]interface{}, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return errors.Wrap(err, "failed to create detailed report file")
	}
	defer file.Close()

	for _, detail := range xssDetails {
		file.WriteString(fmt.Sprintf("Timestamp: %s\nURL: %s\nSeverity: %s\nStatus: %s\n%s\n", detail["timestamp"], detail["url"], detail["severity"], detail["status"], strings.Repeat("-", 50)))
	}
	fmt.Printf("\033[32m[INFO] Detailed report saved to %s\033[0m\n", outputFile)
	return nil
}

func saveJSONOutput(xssDetails []map[string]interface{}, outputFile string) error {
	data, err := json.MarshalIndent(xssDetails, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON output")
	}
	return ioutil.WriteFile(outputFile, data, 0644)
}

func runPipeline(domain string, useWayback bool, useGau bool) []string {
	var urls []string
	var err error

	// Set a timeout for URL collection
	timeout := time.After(3 * time.Minute)
	done := make(chan bool)

	go func() {
		if useWayback {
			urls, err = fetchWaybackURLs(domain)
			if err != nil {
				fmt.Printf("\033[31m[ERROR] Failed to fetch URLs for %s: %v\033[0m\n", domain, err)
				done <- true
				return
			}
		} else if useGau {
			urls, err = fetchGauURLs(domain)
			if err != nil {
				fmt.Printf("\033[31m[ERROR] Failed to fetch URLs for %s: %v\033[0m\n", domain, err)
				done <- true
				return
			}
		}
		done <- true
	}()

	select {
	case <-done:
		if len(urls) == 0 {
			return []string{}
		}
	case <-timeout:
		fmt.Printf("\033[33m[WARN] URL collection for %s is taking too long. Using collected URLs.\033[0m\n", domain)
	}

	// Run gf xss
	cmd := exec.Command("gf", "xss")
	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n"))
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("\033[31m[ERROR] Failed to run gf xss: %v\033[0m\n", err)
		return []string{}
	}
	gfXssURLs := strings.Split(string(output), "\n")

	// Run uro
	cmd = exec.Command("uro")
	cmd.Stdin = strings.NewReader(strings.Join(gfXssURLs, "\n"))
	output, err = cmd.Output()
	if err != nil {
		fmt.Printf("\033[31m[ERROR] Failed to run uro: %v\033[0m\n", err)
		return []string{}
	}
	uroURLs := strings.Split(string(output), "\n")

	// Determine batch size based on the number of URLs after uro
	batchSize := determineBatchSize(len(uroURLs))

	// Split URLs into batches
	batches := splitIntoBatches(uroURLs, batchSize)

	// Channel to collect results
	resultChan := make(chan []string, len(batches))

	// Process batches concurrently
	var wg sync.WaitGroup
	for _, batch := range batches {
		wg.Add(1)
		go func(batch []string) {
			defer wg.Done()
			gxssURLs := processBatchWithGxss(batch)
			kxssURLs := processBatchWithKxss(gxssURLs)
			resultChan <- kxssURLs
		}(batch)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var finalURLs []string
	for result := range resultChan {
		finalURLs = append(finalURLs, result...)
	}

	return finalURLs
}

func determineBatchSize(urlCount int) int {
	if urlCount <= 10 {
		return 1
	}
	// Calculate batch size as 10% of the URL count
	return urlCount / 10
}

func splitIntoBatches(urls []string, batchSize int) [][]string {
	var batches [][]string
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		batches = append(batches, urls[i:end])
	}
	return batches
}

func processBatchWithGxss(batch []string) []string {
	cmd := exec.Command("Gxss")
	cmd.Stdin = strings.NewReader(strings.Join(batch, "\n"))
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("\033[31m[ERROR] Failed to run Gxss: %v\033[0m\n", err)
		return []string{}
	}
	return strings.Split(string(output), "\n")
}

func processBatchWithKxss(batch []string) []string {
	cmd := exec.Command("kxss")
	cmd.Stdin = strings.NewReader(strings.Join(batch, "\n"))
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("\033[31m[ERROR] Failed to run kxss: %v\033[0m\n", err)
		return []string{}
	}
	return strings.Split(string(output), "\n")
}

func worker(id int, jobs <-chan string, results chan<- map[string]interface{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range jobs {
		if urlFlag != "" {
			fmt.Printf("\033[32m[INFO] Processing domain: %s\033[0m\n", domain)
		}
		xssURLs := runPipeline(domain, waybackFlag, gauFlag)
		if len(xssURLs) == 0 {
			results <- map[string]interface{}{
				"domain": domain,
				"details": []map[string]interface{}{},
				"error": fmt.Sprintf("\033[33m[WARNING]\033[0m No XSS vulnerabilities found for %s.\n", domain),
			}
		} else {
			xssDetails := extractXSSDetails(xssURLs, verboseFlag, responseFlag)
			results <- map[string]interface{}{
				"domain": domain,
				"details": xssDetails,
			}
		}
		atomic.AddInt64(&processedDomains, 1) // Increment the counter
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU()) // Use all available CPU cores
	displayBanner()
	flag.Parse()

	if helpFlag || (urlFlag == "" && listFlag == "") {
		flag.Usage()
		return
	}

	var domains []string
	if urlFlag != "" {
		domains = append(domains, urlFlag)
	} else if listFlag != "" {
		data, err := ioutil.ReadFile(listFlag)
		if err != nil {
			fmt.Printf("\033[31m[ERROR] File %s not found: %v\033[0m\n", listFlag, err)
			return
		}
		domains = strings.Split(strings.TrimSpace(string(data)), "\n")
		fmt.Printf("\033[32m[INFO] Total domains to scan: %d\033[0m\n", len(domains))
	}

	if len(domains) == 0 {
		fmt.Printf("\033[31m[ERROR] No domains to scan. Use -u or -l.\033[0m\n")
		return
	}

	if !waybackFlag && !gauFlag {
		fmt.Printf("\033[31m[ERROR] No tool specified to collect URLs. Use --wayback or --gau.\033[0m\n")
		flag.Usage()
		return
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(domains))
	results := make(chan map[string]interface{}, len(domains))

	// Determine the number of workers based on the number of domains
	numWorkers := thread
	if len(domains) > 5 {
		numWorkers = 100
	}

	// Rate limit delay for Wayback Machine
	rateLimitDelay := 5 * time.Second

	// Display rate limit message once
	if waybackFlag {
		fmt.Printf("\033[32m[INFO] Rate limit detected for webarchive.org. Delaying request by %s.\033[0m\n", rateLimitDelay)
	}

	// Create workers
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg)
	}

	// Send jobs with rate limiting for Wayback Machine
	for _, domain := range domains {
		jobs <- domain
		if waybackFlag {
			time.Sleep(rateLimitDelay)
		}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []map[string]interface{}
	for result := range results {
		domain := result["domain"].(string)
		xssDetails := result["details"].([]map[string]interface{})
		fmt.Printf("\033[32m[INFO] Results for domain: %s\033[0m\n", domain)
		displayResults(xssDetails, verboseFlag, responseFlag)
		allResults = append(allResults, xssDetails...)
	}

	if detailedFlag != "" {
		saveDetailedReport(allResults, detailedFlag)
	}

	if jsonFlag != "" {
		saveJSONOutput(allResults, jsonFlag)
	}

	// Print the total number of processed domains
	fmt.Printf("\033[32m[INFO] Total processed domains: %d\033[0m\n", atomic.LoadInt64(&processedDomains))
}
