package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Karthikdude/Xaphan/pkg/core"
	"github.com/Karthikdude/Xaphan/pkg/reporter"
	"github.com/Karthikdude/Xaphan/pkg/runner"
	"github.com/Karthikdude/Xaphan/pkg/utils"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
)

func displayBanner() {
	version := "v3.0.0"

	fmt.Println()
	fmt.Println("  " + utils.ColorizeText("✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧", "cyan"))
	fmt.Println()
	fmt.Println("      " + utils.ColorizeText("██╗  ██╗ █████╗ ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗", "red"))
	fmt.Println("      " + utils.ColorizeText("╚██╗██╔╝██╔══██╗██╔══██╗██║  ██║██╔══██╗████╗  ██║", "red"))
	fmt.Println("       " + utils.ColorizeText("╚███╔╝ ███████║██████╔╝███████║███████║██╔██╗ ██║", "red"))
	fmt.Println("       " + utils.ColorizeText("██╔██╗ ██╔══██║██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║", "red"))
	fmt.Println("      " + utils.ColorizeText("██╔╝ ██╗██║  ██║██║     ██║  ██║██║  ██║██║ ╚████║", "red"))
	fmt.Println("      " + utils.ColorizeText("╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝", "red"))
	fmt.Println()
	fmt.Println("      " + utils.ColorizeText("✦", "yellow") + " " + utils.ColorizeText("XSS Vulnerability Scanner", "white") + " " + utils.ColorizeText(version, "green") + " " + utils.ColorizeText("✦", "yellow"))
	fmt.Println("      " + utils.ColorizeText("Developed by Karthik S Sathyan", "green"))
	fmt.Println()
	fmt.Println("  " + utils.ColorizeText("✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧✧", "cyan"))
	fmt.Println()
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU()) // Use all available CPU cores

	cfg := &core.Config{
		UrlCache: cache.New(core.DefaultCacheExpiry, core.DefaultCacheCleanup),
		Log:      logrus.New(),
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		},
	}
	cfg.Log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	var cancel context.CancelFunc
	cfg.Ctx, cancel = context.WithCancel(context.Background())
	cfg.Cancel = cancel

	rand.Seed(time.Now().UnixNano())

	flag.StringVar(&cfg.UrlFlag, "url", "", "Scan a single domain.")
	flag.StringVar(&cfg.ListFlag, "list", "", "File containing a list of domains to scan.")
	flag.BoolVar(&cfg.WaybackFlag, "wayback", false, "Use Wayback Machine to fetch URLs.")
	flag.BoolVar(&cfg.GauFlag, "gau", false, "Use gau to fetch URLs.")
	flag.BoolVar(&cfg.VerboseFlag, "verbose", false, "Enable verbose output.")
	flag.BoolVar(&cfg.ResponseFlag, "response", false, "Display HTTP response status codes.")
	flag.StringVar(&cfg.DetailedFlag, "detailed", "", "Save detailed report to a file.")
	flag.StringVar(&cfg.JsonFlag, "json", "", "Save results in JSON format.")
	flag.BoolVar(&cfg.HelpFlag, "help", false, "Show this help message and exit.")
	flag.IntVar(&cfg.Thread, "t", 50, "Number of threads to use for concurrent processing.")
	flag.StringVar(&cfg.ProxyFlag, "proxy", "", "Use a proxy for HTTP requests.")
	flag.IntVar(&cfg.ScanDepthFlag, "depth", core.DefaultScanDepth, "Maximum depth for crawling.")
	flag.StringVar(&cfg.HtmlReportFlag, "html", "", "Save HTML report to a file.")
	flag.StringVar(&cfg.ExcludeFlag, "exclude", "", "Exclude specific patterns from crawling.")
	flag.IntVar(&cfg.TimeoutFlag, "timeout", core.DefaultTimeout, "Timeout for URL collection.")
	flag.IntVar(&cfg.RetryFlag, "retry", core.DefaultRetryAttempts, "Number of retry attempts for failed requests.")
	flag.StringVar(&cfg.SaveFlag, "save", "", "Save raw URLs collected from Wayback/GAU to a file.")
	flag.StringVar(&cfg.SaveGfFlag, "save-gf", "", "Save URLs after GF XSS filtering to a file.")
	flag.StringVar(&cfg.SaveUroFlag, "save-uro", "", "Save URLs after URO optimization to a file.")
	flag.BoolVar(&cfg.KatanaFlag, "katana", false, "Use Katana crawler to fetch URLs.")
	flag.BoolVar(&cfg.UrlfindFlag, "urlfinder", false, "Use urlfinder to extract URLs from JavaScript files.")
	flag.BoolVar(&cfg.ArjunFlag, "arjun", false, "Use Arjun to find query parameters.")
	flag.BoolVar(&cfg.GospiderFlag, "gospider", false, "Use Gospider for web crawling.")
	flag.BoolVar(&cfg.HakrawlerFlag, "hakrawler", false, "Use Hakrawler for web crawling.")
	flag.BoolVar(&cfg.AllFlag, "all", false, "Use all URL extractor tools (only for single domain scan).")

	displayBanner()
	flag.Parse()

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		fmt.Println("\nReceived interrupt signal. Gracefully shutting down...")
		cfg.Cancel()
		os.Exit(0)
	}()

	if cfg.HelpFlag || (cfg.UrlFlag == "" && cfg.ListFlag == "") {
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

	if cfg.ExcludeFlag != "" {
		cfg.ExcludedPatterns = strings.Split(cfg.ExcludeFlag, ",")
		cfg.Log.Infof("%s Excluding URLs containing: %v", utils.ColorizeText("[INFO]", "green"), cfg.ExcludedPatterns)
	}

	if cfg.VerboseFlag {
		cfg.Log.SetLevel(logrus.DebugLevel)
	} else {
		cfg.Log.SetLevel(logrus.InfoLevel)
	}

	var domains []string
	if cfg.UrlFlag != "" {
		domains = append(domains, cfg.UrlFlag)
	} else if cfg.ListFlag != "" {
		data, err := ioutil.ReadFile(cfg.ListFlag)
		if err != nil {
			cfg.Log.Fatalf("%s File %s not found: %v", utils.ColorizeText("[ERROR]", "red"), cfg.ListFlag, err)
			return
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			domain := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			if domain != "" {
				domains = append(domains, domain)
			}
		}
		cfg.Log.Infof("%s Total domains to scan: %d", utils.ColorizeText("[INFO]", "green"), len(domains))
	}

	if len(domains) == 0 {
		cfg.Log.Fatalf("%s No domains to scan. Use -url or -list.", utils.ColorizeText("[ERROR]", "red"))
		return
	}

	if cfg.AllFlag {
		if cfg.ListFlag != "" {
			cfg.Log.Fatalf("%s The -all flag can only be used with a single domain (-url). It is not compatible with -list.", utils.ColorizeText("[ERROR]", "red"))
			return
		}
		cfg.WaybackFlag = true
		cfg.GauFlag = true
		cfg.KatanaFlag = true
		cfg.UrlfindFlag = true
		cfg.ArjunFlag = true
		cfg.GospiderFlag = true
		cfg.HakrawlerFlag = true
		fmt.Printf("%s Using all URL collection methods for comprehensive scanning.\n", utils.ColorizeText("[INFO]", "green"))
	} else if !cfg.WaybackFlag && !cfg.GauFlag && !cfg.KatanaFlag && !cfg.UrlfindFlag && !cfg.ArjunFlag && !cfg.GospiderFlag && !cfg.HakrawlerFlag {
		fmt.Printf("%s No URL collection method specified. Using GAU by default.\n", utils.ColorizeText("[INFO]", "yellow"))
		cfg.GauFlag = true
	}

	requiredTools := []string{"gf", "uro", "Gxss", "kxss"}
	if cfg.GauFlag {
		requiredTools = append(requiredTools, "gau")
	}
	if cfg.KatanaFlag {
		requiredTools = append(requiredTools, "katana")
	}
	if cfg.UrlfindFlag {
		requiredTools = append(requiredTools, "urlfinder")
	}
	if cfg.ArjunFlag {
		requiredTools = append(requiredTools, "arjun")
	}
	if cfg.GospiderFlag {
		requiredTools = append(requiredTools, "gospider")
	}
	if cfg.HakrawlerFlag {
		requiredTools = append(requiredTools, "hakrawler")
	}

	fmt.Printf("  %s Checking for required tools...\n", utils.ColorizeText("⟳", "cyan"))
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
		fmt.Printf("  %s Missing required tools: %s\n", utils.ColorizeText("✗", "red"), strings.Join(missingTools, ", "))
		fmt.Println("\nPlease install the missing tools before running Xaphan.")
		fmt.Println("For installation instructions, visit: https://github.com/KarthikS-Sathyan/Xaphan")
		os.Exit(1)
	}
	fmt.Printf("  %s All required tools found\n", utils.ColorizeText("✓", "green"))

	var wg sync.WaitGroup
	jobs := make(chan string, len(domains))
	results := make(chan map[string]interface{}, len(domains))

	numWorkers := cfg.Thread
	if len(domains) < numWorkers {
		numWorkers = len(domains)
	}

	rateLimitDelay := core.DefaultRateLimitDelay

	if cfg.WaybackFlag {
		cfg.Log.Infof("%s Rate limit detected for webarchive.org. Delaying request by %s.", utils.ColorizeText("[INFO]", "green"), rateLimitDelay)
	}

	cfg.Log.Infof("%s Starting %d workers", utils.ColorizeText("[INFO]", "green"), numWorkers)
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go runner.Worker(w, cfg, jobs, results, &wg)
	}

	totalDomains := int64(len(domains))
	fmt.Println()
	utils.PrintBoxedHeader("SCAN PROGRESS")
	fmt.Printf("\n  Processing domains: 0/%d (0%%)\n\n", totalDomains)

	for _, domain := range domains {
		jobs <- domain
		if cfg.WaybackFlag {
			time.Sleep(rateLimitDelay)
		}
	}
	close(jobs)

	if len(domains) > 1 {
		ticker := time.NewTicker(1 * time.Second)
		go func() {
			for {
				select {
				case <-ticker.C:
					processed := atomic.LoadInt64(&cfg.ProcessedDomains)
					utils.ShowProgress(processed, totalDomains)
				case <-cfg.Ctx.Done():
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
			fmt.Printf("\n%s Results for domain: %s\n", utils.ColorizeText("[INFO]", "green"), domain)
			reporter.DisplayResults(cfg, details)
			allResults = append(allResults, details...)
		} else if errMsg, ok := result["error"].(string); ok {
			fmt.Println(errMsg)
		}
	}

	if len(domains) > 1 {
		fmt.Println()
	}

	fmt.Println()
	utils.PrintBoxedHeader("SCAN SUMMARY")
	fmt.Printf("\n  %s Total domains scanned: %d\n", utils.ColorizeText("▶", "cyan"), atomic.LoadInt64(&cfg.ProcessedDomains))
	fmt.Printf("  %s Total vulnerabilities found: %d\n\n", utils.ColorizeText("▶", "cyan"), len(allResults))

	if cfg.DetailedFlag != "" {
		err := reporter.SaveDetailedReport(allResults, cfg.DetailedFlag)
		if err != nil {
			cfg.Log.Fatalf("%s Failed to save detailed report: %v", utils.ColorizeText("[ERROR]", "red"), err)
		}
	}

	if cfg.JsonFlag != "" {
		err := reporter.SaveJSONOutput(allResults, cfg.JsonFlag)
		if err != nil {
			cfg.Log.Fatalf("%s Failed to save JSON report: %v", utils.ColorizeText("[ERROR]", "red"), err)
		}
	}

	if cfg.HtmlReportFlag != "" {
		err := reporter.SaveHTMLReport(allResults, cfg.HtmlReportFlag)
		if err != nil {
			cfg.Log.Fatalf("%s Failed to save HTML report: %v", utils.ColorizeText("[ERROR]", "red"), err)
		}
	}
}
