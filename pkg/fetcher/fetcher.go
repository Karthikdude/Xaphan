package fetcher

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/Karthikdude/Xaphan/pkg/core"
	"github.com/Karthikdude/Xaphan/pkg/utils"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

// FetchWaybackURLs fetches URLs from the Wayback Machine
func FetchWaybackURLs(cfg *core.Config, domain string) ([]string, error) {
	if cachedURLs, found := cfg.UrlCache.Get("wayback_" + domain); found {
		return cachedURLs.([]string), nil
	}

	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original", domain)

	body, err := utils.FetchWithRetry(cfg, url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch Wayback URLs")
	}

	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if cfg.ExcludeFlag != "" && utils.ShouldExcludeURL(cfg, line) {
			continue
		}
		urls = append(urls, line)
	}

	cfg.UrlCache.Set("wayback_"+domain, urls, cache.DefaultExpiration)

	return urls, scanner.Err()
}

// FetchGauURLs fetches URLs using gau command
func FetchGauURLs(cfg *core.Config, domain string) ([]string, error) {
	if cachedURLs, found := cfg.UrlCache.Get("gau_" + domain); found {
		return cachedURLs.([]string), nil
	}

	fmt.Printf("  %s Executing: gau %s\n", utils.ColorizeText("⟳", "cyan"), domain)
	cmd := exec.Command("gau", domain)
	output, err := cmd.CombinedOutput()

	urls := strings.Split(string(output), "\n")
	if err != nil {
		fmt.Printf("  %s GAU error for %s: %v\n",
			utils.ColorizeText("!", "yellow"),
			utils.ColorizeText(domain, "white"),
			err)
		fmt.Printf("  %s GAU output: %s\n",
			utils.ColorizeText("!", "yellow"),
			string(output))
		return []string{}, nil
	}

	if len(urls) <= 1 {
		fmt.Printf("  %s GAU returned no results for %s\n",
			utils.ColorizeText("!", "yellow"),
			utils.ColorizeText(domain, "white"))
		return []string{}, nil
	}

	var filteredURLs []string
	for _, line := range urls {
		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}

		if cfg.ExcludeFlag != "" && utils.ShouldExcludeURL(cfg, line) {
			continue
		}

		if strings.Contains(line, domain) {
			filteredURLs = append(filteredURLs, line)
		}
	}

	fmt.Printf("  %s GAU found %d URLs for %s\n",
		utils.ColorizeText("✓", "green"),
		len(filteredURLs),
		utils.ColorizeText(domain, "white"))

	cfg.UrlCache.Set("gau_"+domain, filteredURLs, cache.DefaultExpiration)

	return filteredURLs, nil
}

// FetchKatanaURLs uses Katana crawler to fetch URLs from a domain
func FetchKatanaURLs(cfg *core.Config, domain string) ([]string, error) {
	tmpFile, err := ioutil.TempFile("", "katana-output-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	var cmd *exec.Cmd
	if cfg.ProxyFlag != "" {
		cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-jc", "-proxy", cfg.ProxyFlag, "-o", tmpFile.Name(), "-silent")
	} else {
		cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-jc", "-o", tmpFile.Name(), "-silent")
	}

	cfg.Log.Debugf("Running command: %s", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		cfg.Log.Debugf("katana command output: %s", string(output))

		if cfg.ProxyFlag != "" {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-jc", "-proxy", cfg.ProxyFlag, "-o", tmpFile.Name())
		} else {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-jc", "-o", tmpFile.Name())
		}

		output, err = cmd.CombinedOutput()
		if err != nil {
			cfg.Log.Debugf("alternative katana command output: %s", string(output))
			return nil, fmt.Errorf("failed to run katana: %v (output: %s)", err, string(output))
		}
	}

	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read katana output: %v", err)
	}

	if len(data) == 0 {
		if cfg.ProxyFlag != "" {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-jc", "-proxy", cfg.ProxyFlag)
		} else {
			cmd = exec.Command("katana", "-u", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-jc")
		}

		data, err = cmd.CombinedOutput()
		if err != nil {
			cfg.Log.Debugf("direct katana command output: %s", string(data))
			return nil, fmt.Errorf("failed to run direct katana: %v", err)
		}
	}

	urls := strings.Split(string(data), "\n")

	var filteredURLs []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !utils.ShouldExcludeURL(cfg, url) {
			if strings.HasPrefix(url, "{") && strings.HasSuffix(url, "}") {
				var result map[string]interface{}
				if err := json.Unmarshal([]byte(url), &result); err == nil {
					if urlStr, ok := result["url"].(string); ok && urlStr != "" && !utils.ShouldExcludeURL(cfg, urlStr) {
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

// FetchUrlfinderURLs uses urlfinder to extract URLs from JavaScript files
func FetchUrlfinderURLs(cfg *core.Config, domain string) ([]string, error) {
	tmpFile, err := ioutil.TempFile("", "urlfinder-output-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	var cmd *exec.Cmd
	if cfg.ProxyFlag != "" {
		cmd = exec.Command("urlfinder", "-d", domain, "-proxy", cfg.ProxyFlag, "-o", tmpFile.Name())
	} else {
		cmd = exec.Command("urlfinder", "-d", domain, "-o", tmpFile.Name())
	}

	cfg.Log.Debugf("Running command: %s", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		cfg.Log.Debugf("urlfinder command output: %s", string(output))
		return nil, fmt.Errorf("failed to run urlfinder: %v", err)
	}

	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read urlfinder output: %v", err)
	}

	urls := strings.Split(string(data), "\n")

	var filteredURLs []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !utils.ShouldExcludeURL(cfg, url) {
			filteredURLs = append(filteredURLs, url)
		}
	}

	return filteredURLs, nil
}

// FetchArjunParams uses Arjun to find query parameters
func FetchArjunParams(cfg *core.Config, domain string) ([]string, error) {
	tmpFile, err := ioutil.TempFile("", "arjun-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	var cmd *exec.Cmd
	if cfg.ProxyFlag != "" {
		cmd = exec.Command("arjun", "-u", "https://"+domain, "-m", "GET", "-o", tmpFile.Name(), "--headers", "User-Agent: "+utils.GetRandomUserAgent(cfg))
	} else {
		cmd = exec.Command("arjun", "-u", "https://"+domain, "-m", "GET", "-o", tmpFile.Name())
	}

	cfg.Log.Debugf("Running command: %s", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		cfg.Log.Debugf("arjun command output: %s", string(output))
		return nil, fmt.Errorf("failed to run arjun: %v (output: %s)", err, string(output))
	}

	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read arjun output: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse arjun output: %v (raw data: %s)", err, string(data))
	}

	var urls []string
	if params, ok := result["params"].([]interface{}); ok {
		for _, param := range params {
			if paramStr, ok := param.(string); ok {
				url := fmt.Sprintf("https://%s/?%s=xss", domain, paramStr)
				urls = append(urls, url)
			}
		}
	} else {
		for key := range result {
			if key != "params" && key != "url" && key != "method" {
				url := fmt.Sprintf("https://%s/?%s=xss", domain, key)
				urls = append(urls, url)
			}
		}
	}

	return urls, nil
}

// FetchGospiderURLs uses Gospider for web crawling
func FetchGospiderURLs(cfg *core.Config, domain string) ([]string, error) {
	tmpDir, err := ioutil.TempDir("", "gospider-output-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	var cmd *exec.Cmd
	if cfg.ProxyFlag != "" {
		cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-c", "10", "-t", "5", "-a", "-r", "--sitemap", "--robots", "--other-source", "--include-subs", "--proxy", cfg.ProxyFlag, "-o", tmpDir)
	} else {
		cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-c", "10", "-t", "5", "-a", "-r", "--sitemap", "--robots", "--other-source", "--include-subs", "-o", tmpDir)
	}

	cfg.Log.Debugf("Running command: %s", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		cfg.Log.Debugf("gospider command output: %s", string(output))

		if cfg.ProxyFlag != "" {
			cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-c", "10", "--proxy", cfg.ProxyFlag)
		} else {
			cmd = exec.Command("gospider", "-s", "https://"+domain, "-d", fmt.Sprintf("%d", cfg.ScanDepthFlag), "-c", "10")
		}

		output, err = cmd.CombinedOutput()
		if err != nil {
			cfg.Log.Debugf("alternative gospider command output: %s", string(output))
			return nil, fmt.Errorf("failed to run gospider: %v (output: %s)", err, string(output))
		}

		return processGospiderOutput(cfg, string(output))
	}

	files, err := ioutil.ReadDir(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read gospider output directory: %v", err)
	}

	var allData string
	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(tmpDir, file.Name())
			data, err := ioutil.ReadFile(filePath)
			if err != nil {
				cfg.Log.Debugf("Failed to read gospider output file %s: %v", filePath, err)
				continue
			}
			allData += string(data) + "\n"
		}
	}

	if allData == "" {
		return processGospiderOutput(cfg, string(output))
	}

	return processGospiderOutput(cfg, allData)
}

func processGospiderOutput(cfg *core.Config, output string) ([]string, error) {
	lines := strings.Split(output, "\n")
	var urls []string
	for _, line := range lines {
		parts := strings.Split(line, " - ")
		if len(parts) >= 2 {
			url := strings.TrimSpace(parts[1])
			if url != "" && !utils.ShouldExcludeURL(cfg, url) {
				urls = append(urls, url)
			}
			continue
		}

		if strings.Contains(line, "http://") || strings.Contains(line, "https://") {
			urlPattern := `https?://[^\s"']+`
			re := regexp.MustCompile(urlPattern)
			matches := re.FindAllString(line, -1)

			for _, match := range matches {
				if !utils.ShouldExcludeURL(cfg, match) {
					urls = append(urls, match)
				}
			}
		}
	}

	return urls, nil
}

// FetchHakrawlerURLs uses Hakrawler for web crawling
func FetchHakrawlerURLs(cfg *core.Config, domain string) ([]string, error) {
	tmpFile, err := ioutil.TempFile("", "hakrawler-output-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	domainFile, err := ioutil.TempFile("", "hakrawler-domain-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create domain file: %v", err)
	}
	defer os.Remove(domainFile.Name())

	_, err = domainFile.WriteString("https://" + domain)
	if err != nil {
		return nil, fmt.Errorf("failed to write to domain file: %v", err)
	}
	domainFile.Close()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if cfg.ProxyFlag != "" {
			cmd = exec.Command("powershell", "-Command", "Get-Content "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", cfg.ScanDepthFlag)+" -u -t 8 -proxy "+cfg.ProxyFlag+" > "+tmpFile.Name())
		} else {
			cmd = exec.Command("powershell", "-Command", "Get-Content "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", cfg.ScanDepthFlag)+" -u -t 8 > "+tmpFile.Name())
		}
	} else {
		if cfg.ProxyFlag != "" {
			cmd = exec.Command("bash", "-c", "cat "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", cfg.ScanDepthFlag)+" -u -t 8 -proxy "+cfg.ProxyFlag+" > "+tmpFile.Name())
		} else {
			cmd = exec.Command("bash", "-c", "cat "+domainFile.Name()+" | hakrawler -d "+fmt.Sprintf("%d", cfg.ScanDepthFlag)+" -u -t 8 > "+tmpFile.Name())
		}
	}

	cfg.Log.Debugf("Running command: %s", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		cfg.Log.Debugf("hakrawler command output: %s", string(output))
		return nil, fmt.Errorf("failed to run hakrawler: %v (output: %s)", err, string(output))
	}

	data, err := ioutil.ReadFile(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to read hakrawler output: %v", err)
	}

	if len(data) == 0 {
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", "echo https://"+domain+" | hakrawler -d "+fmt.Sprintf("%d", cfg.ScanDepthFlag)+" -u -t 8")
		} else {
			cmd = exec.Command("bash", "-c", "echo https://"+domain+" | hakrawler -d "+fmt.Sprintf("%d", cfg.ScanDepthFlag)+" -u -t 8")
		}

		data, err = cmd.CombinedOutput()
		if err != nil {
			cfg.Log.Debugf("direct hakrawler command output: %s", string(data))
			return nil, fmt.Errorf("failed to run direct hakrawler: %v", err)
		}
	}

	urls := strings.Split(string(data), "\n")

	var filteredURLs []string
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url != "" && !utils.ShouldExcludeURL(cfg, url) {
			filteredURLs = append(filteredURLs, url)
		}
	}

	return filteredURLs, nil
}
