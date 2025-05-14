package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	// Command line flags
	urlFlag             string
	listFlag            string
	waybackFlag         bool
	gauFlag             bool
	verboseFlag         bool
	responseFlag        bool
	detailedFlag        string
	jsonFlag            string
	helpFlag            bool
	thread              int
	proxyFlag           string
	scanDepthFlag       int
	htmlReportFlag      string
	excludeFlag         string
	timeoutFlag         int
	retryFlag           int

	// Internal variables
	processedDomains    int64 // Counter for processed domains
	urlCache            *cache.Cache
	log                 *logrus.Logger
	ctx                 context.Context
	cancel              context.CancelFunc
	userAgents          []string
	excludedPatterns    []string
)

// Configuration constants
const (
	DefaultTimeout        = 30
	DefaultRetryAttempts  = 3
	DefaultRetryDelay     = 5 * time.Second
	DefaultScanDepth      = 2
	DefaultBatchSize      = 50
	DefaultCacheExpiry    = 5 * time.Minute
	DefaultCacheCleanup   = 10 * time.Minute
	DefaultRateLimitDelay = 5 * time.Second
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
	flag.StringVar(&proxyFlag, "proxy", "", "Use a proxy for HTTP requests.")
	flag.IntVar(&scanDepthFlag, "depth", DefaultScanDepth, "Maximum depth for crawling.")
	flag.StringVar(&htmlReportFlag, "html", "", "Save HTML report to a file.")
	flag.StringVar(&excludeFlag, "exclude", "", "Exclude specific patterns from crawling.")
	flag.IntVar(&timeoutFlag, "timeout", DefaultTimeout, "Timeout for URL collection.")
	flag.IntVar(&retryFlag, "retry", DefaultRetryAttempts, "Number of retry attempts for failed requests.")

	// Initialize the logger
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	// Initialize the cache
	urlCache = cache.New(DefaultCacheExpiry, DefaultCacheCleanup)

	// Initialize context with cancellation
	ctx, cancel = context.WithCancel(context.Background())

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		fmt.Println("\nReceived interrupt signal. Gracefully shutting down...")
		cancel()
		os.Exit(0)
	}()

	// Initialize user agents for randomization
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())
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

// getRandomUserAgent returns a random user agent from the predefined list
func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// createHTTPClient creates an HTTP client with the specified timeout and proxy (if any)
func createHTTPClient() (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}

	// Add proxy if specified
	if proxyFlag != "" {
		proxyURL, err := url.Parse(proxyFlag)
		if err != nil {
			return nil, errors.Wrap(err, "invalid proxy URL")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeoutFlag) * time.Second,
	}

	return client, nil
}

// fetchWithRetry fetches a URL with retry logic
func fetchWithRetry(url string) ([]byte, error) {
	var (
		resp *http.Response
		err  error
		body []byte
	)

	client, err := createHTTPClient()
	if err != nil {
		return nil, err
	}

	// Try to fetch the URL with retries
	for attempt := 0; attempt < retryFlag; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return nil, errors.New("operation cancelled")
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create request")
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			defer resp.Body.Close()
			body, err = ioutil.ReadAll(resp.Body)
			if err == nil {
				return body, nil
			}
		}

		if err != nil {
			log.Debugf("Attempt %d failed: %v", attempt+1, err)
		} else {
			log.Debugf("Attempt %d failed with status code: %d", attempt+1, resp.StatusCode)
			resp.Body.Close()
		}

		// Wait before retrying
		time.Sleep(DefaultRetryDelay)
	}

	return nil, errors.Errorf("failed after %d attempts", retryFlag)
}

func fetchWaybackURLs(domain string) ([]string, error) {
	// Check cache first
	if cachedURLs, found := urlCache.Get("wayback_" + domain); found {
		return cachedURLs.([]string), nil
	}

	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original", domain)
	
	body, err := fetchWithRetry(url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch Wayback URLs")
	}

	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		// Apply exclusion patterns if any
		if excludeFlag != "" && shouldExcludeURL(line) {
			continue
		}
		urls = append(urls, line)
	}

	// Store in cache
	urlCache.Set("wayback_"+domain, urls, cache.DefaultExpiration)

	return urls, scanner.Err()
}

func fetchGauURLs(domain string) ([]string, error) {
	// Check cache first
	if cachedURLs, found := urlCache.Get("gau_" + domain); found {
		return cachedURLs.([]string), nil
	}

	cmd := exec.Command("gau", domain)
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch Gau URLs")
	}

	lines := strings.Split(string(output), "\n")
	var urls []string
	
	// Apply exclusion patterns if any
	for _, line := range lines {
		if line == "" {
			continue
		}
		if excludeFlag != "" && shouldExcludeURL(line) {
			continue
		}
		urls = append(urls, line)
	}

	// Store in cache
	urlCache.Set("gau_"+domain, urls, cache.DefaultExpiration)

	return urls, nil
}

// shouldExcludeURL checks if a URL should be excluded based on the patterns
func shouldExcludeURL(urlStr string) bool {
	if excludedPatterns == nil && excludeFlag != "" {
		excludedPatterns = strings.Split(excludeFlag, ",")
	}
	
	for _, pattern := range excludedPatterns {
		if strings.Contains(urlStr, pattern) {
			return true
		}
	}
	return false
}

func checkURLStatus(url string) (int, error) {
	// Check cache first
	if cachedStatus, found := urlCache.Get("status_" + url); found {
		return cachedStatus.(int), nil
	}

	client, err := createHTTPClient()
	if err != nil {
		return 0, err
	}

	// Try to check the URL status with retries
	for attempt := 0; attempt < retryFlag; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return 0, errors.New("operation cancelled")
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			return 0, errors.Wrap(err, "failed to create request")
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := client.Do(req)
		if err == nil {
			statusCode := resp.StatusCode
			resp.Body.Close()
			
			// Store in cache
			urlCache.Set("status_"+url, statusCode, cache.DefaultExpiration)
			
			return statusCode, nil
		}

		if verboseFlag {
			log.Infof("Attempt %d to check URL status failed: %v", attempt+1, err)
		}

		// Wait before retrying
		time.Sleep(DefaultRetryDelay)
	}

	return 0, errors.Errorf("failed to check URL status after %d attempts", retryFlag)
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

func saveHTMLReport(xssDetails []map[string]interface{}, outputFile string) error {
	// Count severity levels
	var criticalCount, mediumCount, lowCount, safeCount int
	for _, detail := range xssDetails {
		severity := detail["severity"].(string)
		if strings.Contains(severity, "CRITICAL") {
			criticalCount++
		} else if strings.Contains(severity, "MEDIUM") {
			mediumCount++
		} else if strings.Contains(severity, "LOW") {
			lowCount++
		} else {
			safeCount++
		}
	}

	// Generate HTML
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xaphan XSS Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        .banner { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        h1 { color: #d9534f; }
        .summary { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat { flex: 1; padding: 15px; border-radius: 5px; color: white; }
        .critical { background-color: #d9534f; }
        .medium { background-color: #f0ad4e; }
        .low { background-color: #5bc0de; }
        .safe { background-color: #5cb85c; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #f5f5f5; }
        tr.severity-critical td { background-color: #ffebee; }
        tr.severity-medium td { background-color: #fff8e1; }
        tr.severity-low td { background-color: #e3f2fd; }
        tr.severity-safe td { background-color: #e8f5e9; }
    </style>
</head>
<body>
    <div class="banner">
        <h1>Xaphan XSS Scan Report</h1>
        <p>Generated on: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
    </div>
    
    <div class="summary">
        <div class="stat critical">
            <h2>Critical</h2>
            <p>` + fmt.Sprintf("%d", criticalCount) + `</p>
        </div>
        <div class="stat medium">
            <h2>Medium</h2>
            <p>` + fmt.Sprintf("%d", mediumCount) + `</p>
        </div>
        <div class="stat low">
            <h2>Low</h2>
            <p>` + fmt.Sprintf("%d", lowCount) + `</p>
        </div>
        <div class="stat safe">
            <h2>Safe</h2>
            <p>` + fmt.Sprintf("%d", safeCount) + `</p>
        </div>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>URL</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
`

	// Add table rows
	for _, detail := range xssDetails {
		severity := detail["severity"].(string)
		severityClass := "severity-safe"
		
		if strings.Contains(severity, "CRITICAL") {
			severityClass = "severity-critical"
		} else if strings.Contains(severity, "MEDIUM") {
			severityClass = "severity-medium"
		} else if strings.Contains(severity, "LOW") {
			severityClass = "severity-low"
		}
		
		// Strip ANSI color codes from severity
		plainSeverity := strings.Replace(strings.Replace(strings.Replace(severity, "\033[31m", "", -1), "\033[33m", "", -1), "\033[0m", "", -1)
		plainSeverity = strings.Replace(strings.Replace(plainSeverity, "\033[34m", "", -1), "\033[32m", "", -1)
		
		html += `        <tr class="` + severityClass + `">
            <td>` + detail["timestamp"].(string) + `</td>
            <td>` + plainSeverity + `</td>
            <td>` + detail["url"].(string) + `</td>
            <td>` + detail["status"].(string) + `</td>
        </tr>
`
	}

	html += `        </tbody>
    </table>
    
    <footer style="margin-top: 50px; color: #777; text-align: center;">
        <p>Generated by Xaphan - Developed by Karthik S Sathyan</p>
    </footer>
</body>
</html>`

	return ioutil.WriteFile(outputFile, []byte(html), 0644)
}

// showProgress displays a progress bar in the terminal
func showProgress(current, total int64) {
	if total <= 0 {
		return
	}
	
	width := 40
	percentage := float64(current) / float64(total) * 100
	completed := int(float64(width) * float64(current) / float64(total))
	
	fmt.Printf("\r[%-40s] %.2f%% (%d/%d)", strings.Repeat("=", completed), percentage, current, total)
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

	// Parse excluded patterns if provided
	if excludeFlag != "" {
		excludedPatterns = strings.Split(excludeFlag, ",")
		log.Infof("Excluding URLs containing: %v", excludedPatterns)
	}

	// Set log level based on verbose flag
	if verboseFlag {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}

	var domains []string
	if urlFlag != "" {
		domains = append(domains, urlFlag)
	} else if listFlag != "" {
		data, err := ioutil.ReadFile(listFlag)
		if err != nil {
			log.Fatalf("\033[31m[ERROR] File %s not found: %v\033[0m\n", listFlag, err)
			return
		}
		domains = strings.Split(strings.TrimSpace(string(data)), "\n")
		log.Infof("\033[32m[INFO] Total domains to scan: %d\033[0m\n", len(domains))
	}

	if len(domains) == 0 {
		log.Fatalf("\033[31m[ERROR] No domains to scan. Use -u or -l.\033[0m\n")
		return
	}

	if !waybackFlag && !gauFlag {
		log.Fatalf("\033[31m[ERROR] No tool specified to collect URLs. Use --wayback or --gau.\033[0m\n")
		flag.Usage()
		return
	}

	// Create results directory if it doesn't exist
	if jsonFlag != "" || detailedFlag != "" || htmlReportFlag != "" {
		resultsDir := filepath.Dir(jsonFlag)
		if resultsDir == "." {
			resultsDir = "results"
		}
		if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
			if err := os.MkdirAll(resultsDir, 0755); err != nil {
				log.Fatalf("\033[31m[ERROR] Failed to create results directory: %v\033[0m\n", err)
				return
			}
		}
	}

	var wg sync.WaitGroup
	jobs := make(chan string, len(domains))
	results := make(chan map[string]interface{}, len(domains))

	// Determine the number of workers based on the number of domains
	numWorkers := thread
	if len(domains) < numWorkers {
		numWorkers = len(domains)
	}

	// Rate limit delay for Wayback Machine
	rateLimitDelay := DefaultRateLimitDelay

	// Display rate limit message once
	if waybackFlag {
		log.Infof("\033[32m[INFO] Rate limit detected for webarchive.org. Delaying request by %s.\033[0m\n", rateLimitDelay)
	}

	// Create workers
	log.Infof("\033[32m[INFO] Starting %d workers.\033[0m\n", numWorkers)
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg)
	}

	// Display initial progress
	totalDomains := int64(len(domains))
	fmt.Printf("\033[32m[INFO] Processing domains: 0/%d (0%%)\033[0m\n", totalDomains)

	// Send jobs with rate limiting for Wayback Machine
	for _, domain := range domains {
		jobs <- domain
		if waybackFlag {
			time.Sleep(rateLimitDelay)
		}
	}
	close(jobs)

	// Start a goroutine to display progress
	if len(domains) > 1 {
		ticker := time.NewTicker(1 * time.Second)
		go func() {
			for {
				select {
				case <-ticker.C:
					processed := atomic.LoadInt64(&processedDomains)
					showProgress(processed, totalDomains)
				case <-ctx.Done():
					ticker.Stop()
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []map[string]interface{}
	for result := range results {
		domain := result["domain"].(string)
		if details, ok := result["details"].([]map[string]interface{}); ok {
			fmt.Printf("\n\033[32m[INFO] Results for domain: %s\033[0m\n", domain)
			displayResults(details, verboseFlag, responseFlag)
			allResults = append(allResults, details...)
		} else if errMsg, ok := result["error"].(string); ok {
			fmt.Println(errMsg)
		}
	}

	// Clear progress line
	if len(domains) > 1 {
		fmt.Println()
	}

	if detailedFlag != "" {
		err := saveDetailedReport(allResults, detailedFlag)
		if err != nil {
			log.Fatalf("\033[31m[ERROR] Failed to save detailed report: %v\033[0m\n", err)
		} else {
			log.Infof("\033[32m[INFO] Detailed report saved to %s\033[0m\n", detailedFlag)
		}
	}

	if jsonFlag != "" {
		err := saveJSONOutput(allResults, jsonFlag)
		if err != nil {
			log.Fatalf("\033[31m[ERROR] Failed to save JSON report: %v\033[0m\n", err)
		} else {
			log.Infof("\033[32m[INFO] JSON report saved to %s\033[0m\n", jsonFlag)
		}
	}

	if htmlReportFlag != "" {
		err := saveHTMLReport(allResults, htmlReportFlag)
		if err != nil {
			log.Fatalf("\033[31m[ERROR] Failed to save HTML report: %v\033[0m\n", err)
		} else {
			log.Infof("\033[32m[INFO] HTML report saved to %s\033[0m\n", htmlReportFlag)
		}
	}

	// Print the total number of processed domains
	log.Infof("\033[32m[INFO] Total processed domains: %d\033[0m\n", atomic.LoadInt64(&processedDomains))
	log.Infof("\033[32m[INFO] Total XSS vulnerabilities found: %d\033[0m\n", len(allResults))
}
