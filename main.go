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
	saveFlag            string
	saveGfFlag          string
	saveUroFlag         string
	// New tool flags
	katanaFlag          bool
	urlfindFlag         bool
	arjunFlag           bool
	gospiderFlag        bool
	hakrawlerFlag       bool
	allFlag             bool

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
	flag.StringVar(&saveFlag, "save", "", "Save raw URLs collected from Wayback/GAU to a file.")
	flag.StringVar(&saveGfFlag, "save-gf", "", "Save URLs after GF XSS filtering to a file.")
	flag.StringVar(&saveUroFlag, "save-uro", "", "Save URLs after URO optimization to a file.")
	// New tool flags
	flag.BoolVar(&katanaFlag, "katana", false, "Use Katana crawler to fetch URLs.")
	flag.BoolVar(&urlfindFlag, "urlfinder", false, "Use urlfinder to extract URLs from JavaScript files.")
	flag.BoolVar(&arjunFlag, "arjun", false, "Use Arjun to find query parameters.")
	flag.BoolVar(&gospiderFlag, "gospider", false, "Use Gospider for web crawling.")
	flag.BoolVar(&hakrawlerFlag, "hakrawler", false, "Use Hakrawler for web crawling.")
	flag.BoolVar(&allFlag, "all", false, "Use all URL extractor tools (only for single domain scan).")

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
	version := "v3.0.0"
	
	fmt.Println()
	fmt.Println("  " + colorizeText("✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧", "cyan"))
	fmt.Println()
	fmt.Println("      " + colorizeText("██╗  ██╗ █████╗ ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗", "red"))
	fmt.Println("      " + colorizeText("╚██╗██╔╝██╔══██╗██╔══██╗██║  ██║██╔══██╗████╗  ██║", "red"))
	fmt.Println("       " + colorizeText("╚███╔╝ ███████║██████╔╝███████║███████║██╔██╗ ██║", "red"))
	fmt.Println("       " + colorizeText("██╔██╗ ██╔══██║██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║", "red"))
	fmt.Println("      " + colorizeText("██╔╝ ██╗██║  ██║██║     ██║  ██║██║  ██║██║ ╚████║", "red"))
	fmt.Println("      " + colorizeText("╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝", "red"))
	fmt.Println()
	fmt.Println("      " + colorizeText("✦", "yellow") + " " + colorizeText("XSS Vulnerability Scanner", "white") + " " + colorizeText(version, "green") + " " + colorizeText("✦", "yellow"))
	fmt.Println("      " + colorizeText("Developed by Karthik S Sathyan", "green"))
	fmt.Println()
	fmt.Println("  " + colorizeText("✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧", "cyan"))
	fmt.Println()
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

	// Fetch URLs using gau command
	fmt.Printf("  %s Executing: gau %s\n", colorizeText("⟳", "cyan"), domain)
	cmd := exec.Command("gau", domain)
	output, err := cmd.CombinedOutput()
	
	// If gau fails or returns no results, log a warning
	urls := strings.Split(string(output), "\n")
	if err != nil {
		fmt.Printf("  %s GAU error for %s: %v\n", 
			colorizeText("!", "yellow"),
			colorizeText(domain, "white"),
			err)
		fmt.Printf("  %s GAU output: %s\n", 
			colorizeText("!", "yellow"),
			string(output))
		return []string{}, nil
	}
	
	if len(urls) <= 1 {
		fmt.Printf("  %s GAU returned no results for %s\n", 
			colorizeText("!", "yellow"),
			colorizeText(domain, "white"))
		return []string{}, nil
	}
	
	// Filter and clean URLs
	var filteredURLs []string
	for _, line := range urls {
		if line == "" {
			continue
		}
		
		// Ensure URL has proper scheme
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}
		
		// Check if URL should be excluded
		if excludeFlag != "" && shouldExcludeURL(line) {
			continue
		}
		
		// Make sure the URL belongs to the target domain
		if strings.Contains(line, domain) {
			filteredURLs = append(filteredURLs, line)
		}
	}

	fmt.Printf("  %s GAU found %d URLs for %s\n", 
		colorizeText("✓", "green"),
		len(filteredURLs),
		colorizeText(domain, "white"))

	// Store in cache
	urlCache.Set("gau_"+domain, filteredURLs, cache.DefaultExpiration)

	return filteredURLs, nil
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
	// XSS-specific characters that are high risk
	criticalSymbols := []string{`"`, `'`, `<`, `>`, `%3c`, `%3e`, `%22`, `%27`, `script`, `onerror`, `onload`}
	mediumSymbols := []string{`$`, `|`, `:`, `;`, `(`, `)`, `{`, `}`, `=`, `alert`, `eval`}
	lowSymbols := []string{`[`, `]`, `/`, `\\`, `*`, `+`}

	// Make sure we treat all symbols case-insensitively
	for i, symbol := range unfilteredSymbols {
		unfilteredSymbols[i] = strings.ToLower(symbol)
	}

	for _, symbol := range criticalSymbols {
		if contains(unfilteredSymbols, strings.ToLower(symbol)) {
			return "\033[31m[CRITICAL]\033[0m", "\033[31m"
		}
	}
	for _, symbol := range mediumSymbols {
		if contains(unfilteredSymbols, strings.ToLower(symbol)) {
			return "\033[33m[MEDIUM]\033[0m", "\033[33m"
		}
	}
	for _, symbol := range lowSymbols {
		if contains(unfilteredSymbols, strings.ToLower(symbol)) {
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
	
	if len(urls) == 0 {
		return xssDetails
	}
	
	// Show progress message
	fmt.Printf("  %s Analyzing %s potential vulnerabilities...\n", 
		colorizeText("⟳", "cyan"),
		colorizeText(fmt.Sprintf("%d", len(urls)), "white"))
	
	for i, url := range urls {
		// Show progress percentage
		if len(urls) > 10 && i % 5 == 0 {
			percentage := float64(i) / float64(len(urls)) * 100
			fmt.Printf("\r  %s Analysis progress: %.1f%% (%d/%d)  ", 
				colorizeText("⟳", "cyan"),
				percentage, i, len(urls))
		}
		
		// Extract the unfiltered symbols from the URL if they exist
		var unfilteredSymbols []string
		
		if strings.Contains(url, "Unfiltered: [") {
			unfilteredSymbols = strings.Split(strings.Trim(strings.Split(url, "Unfiltered: [")[1], "]"), " ")
		} else if strings.Contains(url, "kxss") {
			// Handle kxss format - typically shows "kxss: found ... in parameter X"
			unfilteredSymbols = []string{"<", ">", "\"", "'", "script"}
		} else {
			// Default case - try to extract special characters from the URL
			possibleSymbols := []string{"<", ">", "\"", "'", "script", "onerror", "onload"}
			for _, symbol := range possibleSymbols {
				if strings.Contains(strings.ToLower(url), strings.ToLower(symbol)) {
					unfilteredSymbols = append(unfilteredSymbols, symbol)
				}
			}
		}
		
		severity, severityColor := determineSeverity(unfilteredSymbols)
		statusCode := 0
		if checkStatus {
			var err error
			statusCode, err = checkURLStatus(url)
			if err != nil && verbose {
				fmt.Printf("\n  %s Failed to check status for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(url, "white"), 
					err)
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
			// Print with enhanced UI if verbose is enabled
			fmt.Printf("\n  %s %s\n", colorizeText("Found:", "cyan"), url)
			fmt.Printf("  %s %v\n", colorizeText("Unfiltered:", "cyan"), unfilteredSymbols)
			fmt.Printf("  %s %s\n", colorizeText("Severity:", "cyan"), severity)
			if checkStatus {
				fmt.Printf("  %s %s\n", colorizeText("Status:", "cyan"), status)
			}
			fmt.Printf("  %s %s\n", colorizeText("Timestamp:", "cyan"), timestamp)
			fmt.Println(strings.Repeat("─", 80))
		}
	}
	
	// Clear progress line and print summary
	if len(urls) > 10 {
		fmt.Printf("\r\033[K  %s Analysis complete: Found %s vulnerabilities\n", 
			colorizeText("✓", "green"),
			colorizeText(fmt.Sprintf("%d", len(xssDetails)), 
				func() string {
					if len(xssDetails) > 0 {
						return "red"
					}
					return "green"
				}()))
	}
	
	return xssDetails
}

func displayResults(xssDetails []map[string]interface{}, verbose bool, checkStatus bool) {
	if len(xssDetails) == 0 {
		fmt.Printf("\n  %s No XSS vulnerabilities found\n\n", colorizeText("✓", "green"))
		return
	}

	// Count vulnerability types
	var criticalCount, mediumCount, lowCount int
	for _, detail := range xssDetails {
		severity := detail["severity"].(string)
		if strings.Contains(severity, "CRITICAL") {
			criticalCount++
		} else if strings.Contains(severity, "MEDIUM") {
			mediumCount++
		} else if strings.Contains(severity, "LOW") {
			lowCount++
		}
	}
	
	// Print summary header
	fmt.Println()
	printBoxedHeader("XSS SCAN RESULTS")
	fmt.Printf("\n  Found:  %s Critical: %d  %s Medium: %d  %s Low: %d\n\n",
		colorizeText("⚠", "red"), criticalCount,
		colorizeText("⚠", "yellow"), mediumCount,
		colorizeText("⚠", "blue"), lowCount)
	
	fmt.Println(strings.Repeat("─", 80))
	
	// Print results in a clean tabular format
	for _, detail := range xssDetails {
		timestamp := detail["timestamp"].(string)
		severity := detail["severity"].(string)
		url := detail["url"].(string)
		status := detail["status"].(string)
		
		severityIcon := "✓"
		if strings.Contains(severity, "CRITICAL") {
			severityIcon = "⚠"
		} else if strings.Contains(severity, "MEDIUM") {
			severityIcon = "⚠"
		} else if strings.Contains(severity, "LOW") {
			severityIcon = "⚠"
		}
		
		// Strip ANSI color codes from severity
		plainSeverity := strings.Replace(strings.Replace(strings.Replace(severity, "\033[31m", "", -1), "\033[33m", "", -1), "\033[0m", "", -1)
		plainSeverity = strings.Replace(strings.Replace(plainSeverity, "\033[34m", "", -1), "\033[32m", "", -1)
		
		// Print the timestamp and severity
		fmt.Printf("  %s  %s  %s\n", timestamp, colorizedSeverity(plainSeverity, severityIcon), status)
		
		// Print the URL with proper indentation
		fmt.Printf("  %s %s\n", colorizeText("URL:", "cyan"), url)
		
		// Extract potential XSS payloads from the URL
		var unfilteredSymbols []string
		if strings.Contains(url, "Unfiltered: [") {
			unfilteredSymbols = strings.Split(strings.Trim(strings.Split(url, "Unfiltered: [")[1], "]"), " ")
		} else if strings.Contains(url, "kxss") {
			// Handle kxss format - typically shows "kxss: found ... in parameter X"
			unfilteredSymbols = []string{"<", ">", "\"", "'", "script"}
		} else {
			// Default case - try to extract special characters from the URL
			possibleSymbols := []string{"<", ">", "\"", "'", "script", "onerror", "onload"}
			for _, symbol := range possibleSymbols {
				if strings.Contains(strings.ToLower(url), strings.ToLower(symbol)) {
					unfilteredSymbols = append(unfilteredSymbols, symbol)
				}
			}
		}
		
		if len(unfilteredSymbols) > 0 {
			fmt.Printf("  %s %s\n", colorizeText("Unfiltered:", "cyan"), strings.Join(unfilteredSymbols, ", "))
		}
		
		fmt.Println(strings.Repeat("─", 80))
	}
	
	// Print footer
	fmt.Printf("\n  Total vulnerabilities found: %d\n\n", len(xssDetails))
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
	
	// Clear the line and position cursor at beginning
	fmt.Printf("\r\033[K")
	
	// Display progress with color and symbols
	progressBar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)
	fmt.Printf("  %s [%s] %.1f%% (%d/%d)", 
		colorizeText("Progress:", "cyan"),
		colorizeText(progressBar, "cyan"), 
		percentage, current, total)
}

// saveURLsToFile saves a list of URLs to a file
func saveURLsToFile(urls []string, filename string, suffix string) error {
	if filename == "" {
		return nil
	}
	
	// Add suffix to filename if provided
	outputFile := filename
	if suffix != "" {
		// Check if the filename already has an extension
		ext := filepath.Ext(filename)
		if ext != "" {
			// Insert suffix before extension
			outputFile = filename[:len(filename)-len(ext)] + "-" + suffix + ext
		} else {
			// Just append suffix
			outputFile = filename + "-" + suffix
		}
	}
	
	file, err := os.Create(outputFile)
	if err != nil {
		return errors.Wrap(err, "failed to create file")
	}
	defer file.Close()
	
	for _, url := range urls {
		if url != "" {
			file.WriteString(url + "\n")
		}
	}
	
	fmt.Printf("  %s Saved %d URLs to %s\n", 
		colorizeText("✓", "green"),
		len(urls),
		colorizeText(outputFile, "green"))
	
	return nil
}

// fetchKatanaURLs uses Katana crawler to fetch URLs from a domain
func fetchKatanaURLs(domain string) ([]string, error) {
	// Create a temporary file to store the output
	tmpFile, err := ioutil.TempFile("", "katana-output-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	// Construct the katana command with correct flags
	var cmd *exec.Cmd
	if proxyFlag != "" {
		cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-jc", "-proxy", proxyFlag, "-o", tmpFile.Name(), "-silent")
	} else {
		cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-jc", "-o", tmpFile.Name(), "-silent")
	}
	
	log.Debugf("Running command: %s", cmd.String())
	
	// Run the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("katana command output: %s", string(output))
		
		// Try alternative command format without -silent flag
		if proxyFlag != "" {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-jc", "-proxy", proxyFlag, "-o", tmpFile.Name())
		} else {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-jc", "-o", tmpFile.Name())
		}
		
		output, err = cmd.CombinedOutput()
		if err != nil {
			log.Debugf("alternative katana command output: %s", string(output))
			return nil, fmt.Errorf("failed to run katana: %v (output: %s)", err, string(output))
		}
	}
	
	// Read the output file
	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read katana output: %v", err)
	}
	
	// If the file is empty, try to get output directly
	if len(data) == 0 {
		// Try direct execution
		if proxyFlag != "" {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-jc", "-proxy", proxyFlag)
		} else {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-jc")
		}
		
		data, err = cmd.CombinedOutput()
		if err != nil {
			log.Debugf("direct katana command output: %s", string(data))
			return nil, fmt.Errorf("failed to run direct katana: %v", err)
		}
	}
	
	// Split the output into lines
	urls := strings.Split(string(data), "\n")
	
	// Filter out empty lines and apply exclusion patterns
	var filteredURLs []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !shouldExcludeURL(url) {
			// Check if this is a JSON line (katana can output JSONL)
			if strings.HasPrefix(url, "{") && strings.HasSuffix(url, "}") {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(url), &result); err == nil {
					if urlStr, ok := result["url"].(string); ok && urlStr != "" && !shouldExcludeURL(urlStr) {
						filteredURLs = append(filteredURLs, urlStr)
					}
				}
			} else {
				filteredURLs = append(filteredURLs, url)
			}
		}
	}
	
	return filteredURLs, nil
}

// fetchUrlfinderURLs uses urlfinder to extract URLs from JavaScript files
func fetchUrlfinderURLs(domain string) ([]string, error) {
	// Create a temporary file to store the output
	tmpFile, err := ioutil.TempFile("", "urlfinder-output-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	// Construct the urlfinder command
	var cmd *exec.Cmd
	if proxyFlag != "" {
		cmd = exec.Command("urlfinder", "-d", domain, "-proxy", proxyFlag, "-o", tmpFile.Name())
	} else {
		cmd = exec.Command("urlfinder", "-d", domain, "-o", tmpFile.Name())
	}
	
	log.Debugf("Running command: %s", cmd.String())
	
	// Run the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("urlfinder command output: %s", string(output))
		return nil, fmt.Errorf("failed to run urlfinder: %v", err)
	}
	
	// Read the output file
	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read urlfinder output: %v", err)
	}
	
	// Split the output into lines
	urls := strings.Split(string(data), "\n")
	
	// Filter out empty lines and apply exclusion patterns
	var filteredURLs []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !shouldExcludeURL(url) {
			filteredURLs = append(filteredURLs, url)
		}
	}
	
	return filteredURLs, nil
}

// fetchArjunParams uses Arjun to find query parameters
func fetchArjunParams(domain string) ([]string, error) {
	// Create a temporary file to store the output
	tmpFile, err := ioutil.TempFile("", "arjun-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	// Construct the arjun command with correct syntax
	var cmd *exec.Cmd
	if proxyFlag != "" {
		cmd = exec.Command("arjun", "-u", "https://"+domain, "-m", "GET", "-o", tmpFile.Name(), "--headers", "User-Agent: "+getRandomUserAgent())
	} else {
		cmd = exec.Command("arjun", "-u", "https://"+domain, "-m", "GET", "-o", tmpFile.Name())
	}
	
	log.Debugf("Running command: %s", cmd.String())
	
	// Run the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("arjun command output: %s", string(output))
		return nil, fmt.Errorf("failed to run arjun: %v (output: %s)", err, string(output))
	}
	
	// Read the output file
	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read arjun output: %v", err)
	}
	
	// Process the JSON output to extract parameters
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse arjun output: %v (raw data: %s)", err, string(data))
	}
	
	// Extract parameters and construct URLs
	var urls []string
	if params, ok := result["params"].([]interface{}); ok {
		for _, param := range params {
			if paramStr, ok := param.(string); ok {
				url := fmt.Sprintf("https://%s/?%s=xss", domain, paramStr)
				urls = append(urls, url)
			}
		}
	} else {
		// Try alternative parameter extraction if the expected format is not found
		for key := range result {
			if key != "params" && key != "url" && key != "method" {
				url := fmt.Sprintf("https://%s/?%s=xss", domain, key)
				urls = append(urls, url)
			}
		}
	}
	
	return urls, nil
}

// fetchGospiderURLs uses Gospider for web crawling
func fetchGospiderURLs(domain string) ([]string, error) {
	// Create a temporary directory to store the output
	tmpDir, err := ioutil.TempDir("", "gospider-output-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	
	// Construct the gospider command with correct flags
	var cmd *exec.Cmd
	if proxyFlag != "" {
		cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-c", "10", "-t", "5", "-a", "-r", "--sitemap", "--robots", "--other-source", "--include-subs", "--proxy", proxyFlag, "-o", tmpDir)
	} else {
		cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-c", "10", "-t", "5", "-a", "-r", "--sitemap", "--robots", "--other-source", "--include-subs", "-o", tmpDir)
	}
	
	log.Debugf("Running command: %s", cmd.String())
	
	// Run the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("gospider command output: %s", string(output))
		
		// Try alternative command format
		if proxyFlag != "" {
			cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-c", "10", "--proxy", proxyFlag)
		} else {
			cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", scanDepthFlag), "-c", "10")
		}
		
		output, err = cmd.CombinedOutput()
		if err != nil {
			log.Debugf("alternative gospider command output: %s", string(output))
			return nil, fmt.Errorf("failed to run gospider: %v (output: %s)", err, string(output))
		}
		
		// Process direct output
		return processGospiderOutput(string(output))
	}
	
	// Read all files in the output directory
	files, err := ioutil.ReadDir(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read gospider output directory: %v", err)
	}
	
	// Combine all output files
	var allData string
	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(tmpDir, file.Name())
			data, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Debugf("Failed to read gospider output file %s: %v", filePath, err)
				continue
			}
			allData += string(data) + "\n"
		}
	}
	
	// If no files were found or all were empty, try direct output
	if allData == "" {
		return processGospiderOutput(string(output))
	}
	
	return processGospiderOutput(allData)
}

// Helper function to process Gospider output and extract URLs
func processGospiderOutput(output string) ([]string, error) {
	// Split the output into lines
	lines := strings.Split(output, "\n")
	
	// Extract URLs from the output
	var urls []string
	for _, line := range lines {
		// Try different Gospider output formats
		
		// Format 1: [url] - [found_url]
		parts := strings.Split(line, " - ")
		if len(parts) >= 2 {
			url := strings.TrimSpace(parts[1])
			if url != "" && !shouldExcludeURL(url) {
				urls = append(urls, url)
			}
			continue
		}
		
		// Format 2: [found_url]
		// Look for http:// or https:// in the line
		if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
			// Extract URL using regex
			urlPattern := `https?://[^\s"']+`
			re := regexp.MustCompile(urlPattern)
			matches := re.FindAllString(line, -1)
			
			for _, match := range matches {
				if !shouldExcludeURL(match) {
					urls = append(urls, match)
				}
			}
		}
	}
	
	return urls, nil
}

// fetchHakrawlerURLs uses Hakrawler for web crawling
func fetchHakrawlerURLs(domain string) ([]string, error) {
	// Create a temporary file to store the output
	tmpFile, err := ioutil.TempFile("", "hakrawler-output-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	// Create a temporary file with the domain
	domainFile, err := ioutil.TempFile("", "hakrawler-domain-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create domain file: %v", err)
	}
	defer os.Remove(domainFile.Name())
	
	// Write domain to the file
	_, err = domainFile.WriteString("https://" + domain)
	if err != nil {
		return nil, fmt.Errorf("failed to write to domain file: %v", err)
	}
	domainFile.Close()
	
	// Hakrawler expects input from stdin or a pipe
	// We'll use cat/type to pipe the domain into hakrawler
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if proxyFlag != "" {
			cmd = exec.Command("powershell", "-Command", "Get-Content "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", scanDepthFlag)+" -u -t 8 -proxy "+proxyFlag+" > "+tmpFile.Name())
		} else {
			cmd = exec.Command("powershell", "-Command", "Get-Content "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", scanDepthFlag)+" -u -t 8 > "+tmpFile.Name())
		}
	} else {
		if proxyFlag != "" {
			cmd = exec.Command("bash", "-c", "cat "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", scanDepthFlag)+" -u -t 8 -proxy "+proxyFlag+" > "+tmpFile.Name())
		} else {
			cmd = exec.Command("bash", "-c", "cat "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", scanDepthFlag)+" -u -t 8 > "+tmpFile.Name())
		}
	}
	
	log.Debugf("Running command: %s", cmd.String())
	
	// Run the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("hakrawler command output: %s", string(output))
		return nil, fmt.Errorf("failed to run hakrawler: %v (output: %s)", err, string(output))
	}
	
	// Read the output file
	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read hakrawler output: %v", err)
	}
	
	// If the file is empty, try to get output directly
	if len(data) == 0 {
		// Try direct execution
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", "echo https://"+domain+" | hakrawler -d "+fmt.Sprintf("%d", scanDepthFlag)+" -u -t 8")
		} else {
			cmd = exec.Command("bash", "-c", "echo https://"+domain+" | hakrawler -d "+fmt.Sprintf("%d", scanDepthFlag)+" -u -t 8")
		}
		
		data, err = cmd.CombinedOutput()
		if err != nil {
			log.Debugf("direct hakrawler command output: %s", string(data))
			return nil, fmt.Errorf("failed to run direct hakrawler: %v", err)
		}
	}
	
	// Split the output into lines
	urls := strings.Split(string(data), "\n")
	
	// Filter out empty lines and apply exclusion patterns
	var filteredURLs []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !shouldExcludeURL(url) {
			filteredURLs = append(filteredURLs, url)
		}
	}
	
	return filteredURLs, nil
}

func runPipeline(domain string, useWayback bool, useGau bool) []string {
	var urls []string
	var err error

	// Determine scan type (Passive vs Active)
	scanType := ""
	scanTypeColor := ""
	
	// Determine fetch method for display
	fetchMethod := "GAU"
	if allFlag {
		fetchMethod = "All Tools"
		scanType = "COMPREHENSIVE SCAN"
		scanTypeColor = "magenta"
	} else if useWayback || useGau || urlfindFlag {
		// Passive tools
		scanType = "PASSIVE SCAN"
		scanTypeColor = "green"
		if useWayback {
			fetchMethod = "Wayback Machine"
		} else if urlfindFlag {
			fetchMethod = "URLFinder"
		}
	} else if katanaFlag || arjunFlag || gospiderFlag || hakrawlerFlag {
		// Active tools
		scanType = "ACTIVE SCAN"
		scanTypeColor = "red"
		if katanaFlag {
			fetchMethod = "Katana"
		} else if arjunFlag {
			fetchMethod = "Arjun"
		} else if gospiderFlag {
			fetchMethod = "Gospider"
		} else if hakrawlerFlag {
			fetchMethod = "Hakrawler"
		}
	}
	
	// Display scan type
	if scanType != "" {
		fmt.Printf("  %s %s %s\n", 
			colorizeText("[", scanTypeColor),
			colorizeText(scanType, scanTypeColor),
			colorizeText("]", scanTypeColor))
	}
	
	fmt.Printf("  %s Fetching URLs for %s using %s...\n", 
		colorizeText("⟳", "cyan"), 
		colorizeText(domain, "white"),
		colorizeText(fetchMethod, "yellow"))

	// Set a timeout for URL collection
	timeout := time.After(time.Duration(timeoutFlag) * time.Second)
	done := make(chan bool)

	go func() {
		// For the -all flag, collect URLs from all tools and combine them
		if allFlag {
			var allUrls []string
			var wg sync.WaitGroup
			urlChan := make(chan []string, 7) // Channel to collect URLs from all tools
			errChan := make(chan error, 7)    // Channel to collect errors
			
			// Function to fetch URLs with a specific tool and send to channel
			fetchURLs := func(fetcher func(string) ([]string, error), toolName string) {
				defer wg.Done()
				fmt.Printf("  %s Running %s for %s...\n", 
					colorizeText("⟳", "cyan"),
					colorizeText(toolName, "yellow"),
					colorizeText(domain, "white"))
				
				toolUrls, err := fetcher(domain)
				if err != nil {
					fmt.Printf("  %s %s failed for %s: %v\n", 
						colorizeText("✗", "red"),
						toolName,
						colorizeText(domain, "white"),
						err)
					errChan <- err
					urlChan <- []string{} // Send empty slice on error
					return
				}
				
				fmt.Printf("  %s %s found %s URLs\n", 
					colorizeText("✓", "green"),
					toolName,
					colorizeText(fmt.Sprintf("%d", len(toolUrls)), "white"))
				
				urlChan <- toolUrls
			}
			
			// Start goroutines for each tool
			wg.Add(7)
			go fetchURLs(fetchWaybackURLs, "Wayback Machine")
			go fetchURLs(fetchGauURLs, "GAU")
			go fetchURLs(fetchKatanaURLs, "Katana")
			go fetchURLs(fetchUrlfinderURLs, "URLFinder")
			go fetchURLs(fetchArjunParams, "Arjun")
			go fetchURLs(fetchGospiderURLs, "Gospider")
			go fetchURLs(fetchHakrawlerURLs, "Hakrawler")
			
			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(urlChan)
				close(errChan)
			}()
			
			// Collect all URLs
			for toolUrls := range urlChan {
				allUrls = append(allUrls, toolUrls...)
			}
			
			// Check if we have any URLs
			if len(allUrls) == 0 {
				// Check if we have any errors
				if len(errChan) > 0 {
					fmt.Printf("  %s All tools failed to fetch URLs for %s\n", 
						colorizeText("✗", "red"),
						colorizeText(domain, "white"))
				} else {
					fmt.Printf("  %s No URLs found for %s with any tool\n", 
						colorizeText("!", "yellow"),
						colorizeText(domain, "white"))
				}
				done <- true
				return
			}
			
			// Remove duplicates
			urlMap := make(map[string]bool)
			for _, url := range allUrls {
				urlMap[url] = true
			}
			
			urls = make([]string, 0, len(urlMap))
			for url := range urlMap {
				urls = append(urls, url)
			}
			
			fmt.Printf("  %s Combined and deduplicated to %s unique URLs\n", 
				colorizeText("✓", "green"),
				colorizeText(fmt.Sprintf("%d", len(urls)), "white"))
			
			done <- true
			return
		}
		
		// Original single-tool logic
		if useWayback {
			urls, err = fetchWaybackURLs(domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(domain, "white"), 
					err)
				done <- true
				return
			}
		} else if useGau {
			urls, err = fetchGauURLs(domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(domain, "white"), 
					err)
				done <- true
				return
			}
		} else if katanaFlag {
			urls, err = fetchKatanaURLs(domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(domain, "white"), 
					err)
				done <- true
				return
			}
		} else if urlfindFlag {
			urls, err = fetchUrlfinderURLs(domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(domain, "white"), 
					err)
				done <- true
				return
			}
		} else if arjunFlag {
			urls, err = fetchArjunParams(domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch parameters for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(domain, "white"), 
					err)
				done <- true
				return
			}
		} else if gospiderFlag {
			urls, err = fetchGospiderURLs(domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(domain, "white"), 
					err)
				done <- true
				return
			}
		} else if hakrawlerFlag {
			urls, err = fetchHakrawlerURLs(domain)
			if err != nil {
				fmt.Printf("  %s Failed to fetch URLs for %s: %v\n", 
					colorizeText("✗", "red"), 
					colorizeText(domain, "white"), 
					err)
				done <- true
				return
			}
		}
		done <- true
	}()

	select {
	case <-done:
		if len(urls) == 0 {
			fmt.Printf("  %s No URLs found for %s\n", 
				colorizeText("!", "yellow"), 
				colorizeText(domain, "white"))
			return []string{}
		}
		fmt.Printf("  %s Found %s URLs for %s\n", 
			colorizeText("✓", "green"), 
			colorizeText(fmt.Sprintf("%d", len(urls)), "white"),
			colorizeText(domain, "white"))
	case <-timeout:
		fmt.Printf("  %s URL collection for %s timed out after %d seconds. Using collected URLs.\n", 
			colorizeText("⚠", "yellow"), 
			colorizeText(domain, "white"),
			timeoutFlag)
	}
	
	// Save raw URLs if requested
	if saveFlag != "" {
		if err := saveURLsToFile(urls, saveFlag, domain+"-raw"); err != nil {
			fmt.Printf("  %s Failed to save raw URLs: %v\n", 
				colorizeText("✗", "red"), 
				err)
		}
	}

	// Create temporary file for gf xss
	tmpFile, err := ioutil.TempFile("", "xaphan-urls-*.txt")
	if err != nil {
		fmt.Printf("  %s Failed to create temp file: %v\n", colorizeText("✗", "red"), err)
		return []string{}
	}
	defer os.Remove(tmpFile.Name())
	
	// Write URLs to temporary file
	for _, url := range urls {
		if url != "" {
			tmpFile.WriteString(url + "\n")
		}
	}
	tmpFile.Close()
	
	// Run gf xss
	fmt.Printf("  %s Running GF XSS pattern matcher...\n", colorizeText("⟳", "cyan"))
	// Use gf directly with file as argument (gf xss works this way)
	cmd := exec.Command("gf", "xss", tmpFile.Name())
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		fmt.Printf("  %s Failed to run gf xss: %v\n", colorizeText("✗", "red"), err)
		fmt.Printf("  %s Output: %s\n", colorizeText("!", "yellow"), string(output))
		
		// Try alternative method with cat and pipeline
		fmt.Printf("  %s Trying alternative gf method...\n", colorizeText("⟳", "cyan"))
		
		if runtime.GOOS == "windows" {
			// On Windows try with PowerShell
			cmd = exec.Command("powershell", "-Command", "Get-Content "+tmpFile.Name()+" | gf xss")
		} else {
			// On Unix-like systems use bash
			cmd = exec.Command("bash", "-c", "cat "+tmpFile.Name()+" | gf xss")
		}
		
		output, err = cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("  %s Alternative gf method failed: %v\n", colorizeText("✗", "red"), err)
			return []string{}
		}
	}
	
	gfXssURLs := strings.Split(string(output), "\n")
	var filteredGfURLs []string
	for _, url := range gfXssURLs {
		if url != "" {
			filteredGfURLs = append(filteredGfURLs, url)
		}
	}
	
	fmt.Printf("  %s GF found %s potential XSS endpoints\n", 
		colorizeText("✓", "green"),
		colorizeText(fmt.Sprintf("%d", len(filteredGfURLs)), "white"))
		
	if len(filteredGfURLs) == 0 {
		fmt.Printf("  %s No potential XSS endpoints found, skipping further processing\n", 
			colorizeText("!", "yellow"))
		return []string{}
	}
	
	// Save GF results if requested
	if saveGfFlag != "" {
		if err := saveURLsToFile(filteredGfURLs, saveGfFlag, domain+"-gf"); err != nil {
			fmt.Printf("  %s Failed to save GF URLs: %v\n", 
				colorizeText("✗", "red"), 
				err)
		}
	}

	// Create temporary file for uro
	uroTmpFile, err := ioutil.TempFile("", "xaphan-uro-*.txt")
	if err != nil {
		fmt.Printf("  %s Failed to create uro temp file: %v\n", colorizeText("✗", "red"), err)
		return filteredGfURLs
	}
	defer os.Remove(uroTmpFile.Name())
	
	// Write gf results to uro input file
	for _, url := range filteredGfURLs {
		if url != "" {
			uroTmpFile.WriteString(url + "\n")
		}
	}
	uroTmpFile.Close()

	// Run uro
	fmt.Printf("  %s Running URO for URL optimization...\n", colorizeText("⟳", "cyan"))
	// URO doesn't support -file flag, it expects input to be piped in or specified with -i
	cmd = exec.Command("bash", "-c", "cat "+uroTmpFile.Name()+" | uro")
	output, err = cmd.CombinedOutput()
	
	if err != nil {
		fmt.Printf("  %s Failed to run uro: %v\n", colorizeText("✗", "red"), err)
		fmt.Printf("  %s Output: %s\n", colorizeText("!", "yellow"), string(output))
		
		// Try alternative method for Windows
		if runtime.GOOS == "windows" {
			fmt.Printf("  %s Trying Windows method for uro...\n", colorizeText("⟳", "cyan"))
			cmd = exec.Command("powershell", "-Command", "Get-Content "+uroTmpFile.Name()+" | uro")
			output, err = cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("  %s Windows method for uro failed: %v\n", colorizeText("✗", "red"), err)
				// Try using uro with -i flag
				cmd = exec.Command("uro", "-i", uroTmpFile.Name())
				output, err = cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("  %s All uro methods failed, using original GF results\n", 
						colorizeText("!", "yellow"))
					return filteredGfURLs
				}
			}
		} else {
			// Try using uro with -i flag for Unix
			cmd = exec.Command("uro", "-i", uroTmpFile.Name())
			output, err = cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("  %s All uro methods failed, using original GF results\n", 
					colorizeText("!", "yellow"))
				return filteredGfURLs
			}
		}
	}
	
	uroURLs := strings.Split(string(output), "\n")
	var filteredUroURLs []string
	for _, url := range uroURLs {
		if url != "" {
			filteredUroURLs = append(filteredUroURLs, url)
		}
	}
	
	fmt.Printf("  %s URO optimized to %s unique endpoints\n", 
		colorizeText("✓", "green"),
		colorizeText(fmt.Sprintf("%d", len(filteredUroURLs)), "white"))
		
	if len(filteredUroURLs) == 0 {
		fmt.Printf("  %s URO returned no results, using original GF results\n", 
			colorizeText("!", "yellow"))
		filteredUroURLs = filteredGfURLs
	}
	
	// Save URO results if requested
	if saveUroFlag != "" {
		if err := saveURLsToFile(filteredUroURLs, saveUroFlag, domain+"-uro"); err != nil {
			fmt.Printf("  %s Failed to save URO URLs: %v\n", 
				colorizeText("✗", "red"), 
				err)
		}
	}

	// Determine batch size based on the number of URLs after uro
	batchSize := determineBatchSize(len(filteredUroURLs))
	
	// Split URLs into batches
	batches := splitIntoBatches(filteredUroURLs, batchSize)
	fmt.Printf("  %s Testing endpoints in %s batches...\n", 
		colorizeText("⟳", "cyan"),
		colorizeText(fmt.Sprintf("%d", len(batches)), "white"))

	// Initialize progress
	fmt.Printf("  %s Processing batches: %d/%d completed", 
		colorizeText("⟳", "cyan"),
		0,
		len(batches))
	
	// Process batches with limited concurrency to ensure orderly progress
	var finalURLs []string
	batchResults := make(chan []string, len(batches))
	concurrencyLimit := 3 // Limit concurrent processing
	if len(batches) < concurrencyLimit {
		concurrencyLimit = len(batches)
	}
	
	sem := make(chan bool, concurrencyLimit)
	var wg sync.WaitGroup
	
	// Process batches with controlled concurrency
	for i, batch := range batches {
		wg.Add(1)
		go func(batchNum int, urls []string) {
			defer wg.Done()
			
			// Get semaphore
			sem <- true
			defer func() { <-sem }()
			
			// Process the batch
			gxssURLs := processBatchWithGxss(urls)
			kxssURLs := processBatchWithKxss(gxssURLs)
			batchResults <- kxssURLs
			
			// Update progress display
			fmt.Printf("\r  %s Processing batches: %d/%d completed", 
				colorizeText("⟳", "cyan"),
				batchNum+1, 
				len(batches))
		}(i, batch)
	}
	
	// Close results channel when all batches are processed
	go func() {
		wg.Wait()
		close(batchResults)
	}()
	
	// Collect batch results
	for result := range batchResults {
		finalURLs = append(finalURLs, result...)
	}

	// Clear the progress line and print the final result
	fmt.Printf("\r  %s All batches processed successfully           \n", 
		colorizeText("✓", "green"))
		
	fmt.Printf("  %s Found %s potential XSS vulnerabilities in %s\n\n", 
		colorizeText("✓", "green"),
		colorizeText(fmt.Sprintf("%d", len(finalURLs)), 
			func() string {
				if len(finalURLs) > 0 {
					return "red"
				}
				return "green"
			}()),
		colorizeText(domain, "white"))

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
	if len(batch) == 0 {
		return []string{}
	}
	
	// Create temporary file with batch URLs
	tmpFile, err := ioutil.TempFile("", "gxss-urls-*.txt")
	if err != nil {
		return []string{}
	}
	defer os.Remove(tmpFile.Name())
	
	for _, url := range batch {
		if url != "" {
			tmpFile.WriteString(url + "\n")
		}
	}
	tmpFile.Close()
	
	// Run Gxss tool without verbose output
	cmd := exec.Command("bash", "-c", "cat "+tmpFile.Name()+" | Gxss")
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		// Try alternative method without verbose output
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", "Get-Content "+tmpFile.Name()+" | Gxss")
			output, err = cmd.CombinedOutput()
			
			if err != nil {
				return batch
			}
		} else {
			return batch
		}
	}
	
	// Process Gxss output
	results := strings.Split(string(output), "\n")
	
	// Filter out empty lines
	var filtered []string
	for _, line := range results {
		if line != "" {
			filtered = append(filtered, line)
		}
	}
	
	return filtered
}

func processBatchWithKxss(batch []string) []string {
	if len(batch) == 0 {
		return []string{}
	}
	
	// Create temporary file with batch URLs
	tmpFile, err := ioutil.TempFile("", "kxss-urls-*.txt")
	if err != nil {
		return batch
	}
	defer os.Remove(tmpFile.Name())
	
	for _, url := range batch {
		if url != "" {
			tmpFile.WriteString(url + "\n")
		}
	}
	tmpFile.Close()
	
	// Run kxss tool without verbose output
	cmd := exec.Command("bash", "-c", "cat "+tmpFile.Name()+" | kxss")
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		// Try alternative method without verbose output
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", "Get-Content "+tmpFile.Name()+" | kxss")
			output, err = cmd.CombinedOutput()
			
			if err != nil {
				return batch
			}
		} else {
			return batch
		}
	}
	
	// Process kxss output
	results := strings.Split(string(output), "\n")
	
	// Filter out empty lines
	var filtered []string
	for _, line := range results {
		if line != "" {
			filtered = append(filtered, line)
		}
	}
	
	return filtered
}

func worker(id int, jobs <-chan string, results chan<- map[string]interface{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range jobs {
		if urlFlag != "" {
			fmt.Printf("\n  %s Processing domain: %s\n", colorizeText("▶", "cyan"), colorizeText(domain, "white"))
		}
		xssURLs := runPipeline(domain, waybackFlag, gauFlag)
		if len(xssURLs) == 0 {
			results <- map[string]interface{}{
				"domain": domain,
				"details": []map[string]interface{}{},
				"error": fmt.Sprintf("\n  %s No XSS vulnerabilities found for %s\n", 
					colorizeText("✓", "green"), 
					colorizeText(domain, "white")),
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
		fmt.Println("\nExample usage:")
		fmt.Println("  ./Xaphan -url example.com -gau")
		fmt.Println("  ./Xaphan -url example.com -wayback -verbose")
		fmt.Println("  ./Xaphan -list domains.txt -gau -t 10")
		fmt.Println("  ./Xaphan -url example.com -gau -save urls.txt")
		fmt.Println("  ./Xaphan -url example.com -gau -save-gf gf-results.txt -save-uro uro-results.txt")
		fmt.Println("  ./Xaphan -list domains.txt -wayback -gau -response -html report.html")
		return
	}

	// Parse excluded patterns if provided
	if excludeFlag != "" {
		excludedPatterns = strings.Split(excludeFlag, ",")
		log.Infof("%s Excluding URLs containing: %v", colorizeText("[INFO]", "green"), excludedPatterns)
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
			log.Fatalf("%s File %s not found: %v", colorizeText("[ERROR]", "red"), listFlag, err)
			return
		}
		domains = strings.Split(strings.TrimSpace(string(data)), "\n")
		log.Infof("%s Total domains to scan: %d", colorizeText("[INFO]", "green"), len(domains))
	}

	if len(domains) == 0 {
		log.Fatalf("%s No domains to scan. Use -url or -list.", colorizeText("[ERROR]", "red"))
		return
	}

	// Check if -all flag is used
	if allFlag {
		// Ensure -all is only used with a single domain
		if listFlag != "" {
			log.Fatalf("%s The -all flag can only be used with a single domain (-url). It is not compatible with -list.", colorizeText("[ERROR]", "red"))
			return
		}
		
		// Enable all URL collection methods
		waybackFlag = true
		gauFlag = true
		katanaFlag = true
		urlfindFlag = true
		arjunFlag = true
		gospiderFlag = true
		hakrawlerFlag = true
		
		fmt.Printf("%s Using all URL collection methods for comprehensive scanning.\n", 
			colorizeText("[INFO]", "green"))
	} else if !waybackFlag && !gauFlag && !katanaFlag && !urlfindFlag && !arjunFlag && !gospiderFlag && !hakrawlerFlag {
		// Enable gau by default if no tool is specified
		fmt.Printf("%s No URL collection method specified. Using GAU by default.\n", 
			colorizeText("[INFO]", "yellow"))
		gauFlag = true
	}

	// Check if required tools are installed
	requiredTools := []string{"gf", "uro", "Gxss", "kxss"}
	if gauFlag {
		requiredTools = append(requiredTools, "gau")
	}
	if katanaFlag {
		requiredTools = append(requiredTools, "katana")
	}
	if urlfindFlag {
		requiredTools = append(requiredTools, "urlfinder")
	}
	if arjunFlag {
		requiredTools = append(requiredTools, "arjun")
	}
	if gospiderFlag {
		requiredTools = append(requiredTools, "gospider")
	}
	if hakrawlerFlag {
		requiredTools = append(requiredTools, "hakrawler")
	}
	
	// Check for each tool
	fmt.Printf("  %s Checking for required tools...\n", colorizeText("⟳", "cyan"))
	missingTools := []string{}
	for _, tool := range requiredTools {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("where", tool)
		} else {
			cmd = exec.Command("which", tool)
		}
		if err := cmd.Run(); err != nil {
			missingTools = append(missingTools, tool)
		}
	}
	
	if len(missingTools) > 0 {
		fmt.Printf("  %s Missing required tools: %s\n", 
			colorizeText("✗", "red"),
			strings.Join(missingTools, ", "))
		fmt.Println("\nPlease install the missing tools before running Xaphan.")
		fmt.Println("For installation instructions, visit: https://github.com/KarthikS-Sathyan/Xaphan")
		os.Exit(1)
	}
	fmt.Printf("  %s All required tools found\n", colorizeText("✓", "green"))

	// Create results directory if it doesn't exist
	if jsonFlag != "" || detailedFlag != "" || htmlReportFlag != "" {
		resultsDir := filepath.Dir(jsonFlag)
		if resultsDir == "." {
			resultsDir = "results"
		}
		if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
			if err := os.MkdirAll(resultsDir, 0755); err != nil {
				log.Fatalf("%s Failed to create results directory: %v", colorizeText("[ERROR]", "red"), err)
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
		log.Infof("%s Rate limit detected for webarchive.org. Delaying request by %s.", 
			colorizeText("[INFO]", "green"), rateLimitDelay)
	}

	// Create workers
	log.Infof("%s Starting %d workers", colorizeText("[INFO]", "green"), numWorkers)
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, results, &wg)
	}

	// Display initial progress
	totalDomains := int64(len(domains))
	fmt.Println()
	printBoxedHeader("SCAN PROGRESS")
	fmt.Printf("\n  Processing domains: 0/%d (0%%)\n\n", totalDomains)

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
			fmt.Printf("\n%s Results for domain: %s\n", colorizeText("[INFO]", "green"), domain)
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

	// Print summary of scan results
	fmt.Println()
	printBoxedHeader("SCAN SUMMARY")
	fmt.Printf("\n  %s Total domains scanned: %d\n", colorizeText("▶", "cyan"), atomic.LoadInt64(&processedDomains))
	fmt.Printf("  %s Total vulnerabilities found: %d\n\n", colorizeText("▶", "cyan"), len(allResults))

	if detailedFlag != "" {
		err := saveDetailedReport(allResults, detailedFlag)
		if err != nil {
			log.Fatalf("%s Failed to save detailed report: %v", colorizeText("[ERROR]", "red"), err)
		} else {
			log.Infof("%s Detailed report saved to %s", colorizeText("[INFO]", "green"), detailedFlag)
		}
	}

	if jsonFlag != "" {
		err := saveJSONOutput(allResults, jsonFlag)
		if err != nil {
			log.Fatalf("%s Failed to save JSON report: %v", colorizeText("[ERROR]", "red"), err)
		} else {
			log.Infof("%s JSON report saved to %s", colorizeText("[INFO]", "green"), jsonFlag)
		}
	}

	if htmlReportFlag != "" {
		err := saveHTMLReport(allResults, htmlReportFlag)
		if err != nil {
			log.Fatalf("%s Failed to save HTML report: %v", colorizeText("[ERROR]", "red"), err)
		} else {
			log.Infof("%s HTML report saved to %s", colorizeText("[INFO]", "green"), htmlReportFlag)
		}
	}
}

// Helper functions for the enhanced UI

func colorizeText(text, color string) string {
	switch color {
	case "red":
		return "\033[31m" + text + "\033[0m"
	case "green":
		return "\033[32m" + text + "\033[0m"
	case "yellow":
		return "\033[33m" + text + "\033[0m"
	case "blue":
		return "\033[34m" + text + "\033[0m"
	case "magenta":
		return "\033[35m" + text + "\033[0m"
	case "cyan":
		return "\033[36m" + text + "\033[0m"
	case "white":
		return "\033[97m" + text + "\033[0m"
	default:
		return text
	}
}

func colorizedSeverity(severity, icon string) string {
	if strings.Contains(severity, "CRITICAL") {
		return colorizeText(icon + " " + severity, "red")
	} else if strings.Contains(severity, "MEDIUM") {
		return colorizeText(icon + " " + severity, "yellow")
	} else if strings.Contains(severity, "LOW") {
		return colorizeText(icon + " " + severity, "blue")
	}
	return colorizeText(icon + " " + severity, "green")
}

func printBoxedHeader(text string) {
	width := len(text) + 4
	fmt.Println()
	fmt.Println("  " + colorizeText(strings.Repeat("✧", width), "cyan"))
	fmt.Println("  " + colorizeText("✦", "yellow") + " " + colorizeText(text, "white") + " " + colorizeText("✦", "yellow"))
	fmt.Println("  " + colorizeText(strings.Repeat("✧", width), "cyan"))
	fmt.Println()
}

