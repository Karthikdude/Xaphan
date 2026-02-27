package utils

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Karthikdude/Xaphan/pkg/core"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

// colorizeText adds ANSI color codes to text
func ColorizeText(text, color string) string {
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

// colorizedSeverity returns colored severity strings
func ColorizedSeverity(severity, icon string) string {
	if strings.Contains(severity, "CRITICAL") {
		return ColorizeText(icon+" "+severity, "red")
	} else if strings.Contains(severity, "MEDIUM") {
		return ColorizeText(icon+" "+severity, "yellow")
	} else if strings.Contains(severity, "LOW") {
		return ColorizeText(icon+" "+severity, "blue")
	}
	return ColorizeText(icon+" "+severity, "green")
}

// printBoxedHeader prints a boxed header to the console
func PrintBoxedHeader(text string) {
	width := len(text) + 4
	fmt.Println()
	fmt.Println("  " + ColorizeText(strings.Repeat("✧", width), "cyan"))
	fmt.Println("  " + ColorizeText("✦", "yellow") + " " + ColorizeText(text, "white") + " " + ColorizeText("✦", "yellow"))
	fmt.Println("  " + ColorizeText(strings.Repeat("✧", width), "cyan"))
	fmt.Println()
}

// GetRandomUserAgent returns a random user agent from the predefined list
func GetRandomUserAgent(cfg *core.Config) string {
	return cfg.UserAgents[rand.Intn(len(cfg.UserAgents))]
}

// CreateHTTPClient creates an HTTP client with the specified timeout and proxy (if any)
func CreateHTTPClient(cfg *core.Config) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}

	// Add proxy if specified
	if cfg.ProxyFlag != "" {
		proxyURL, err := url.Parse(cfg.ProxyFlag)
		if err != nil {
			return nil, errors.Wrap(err, "invalid proxy URL")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.TimeoutFlag) * time.Second,
	}

	return client, nil
}

// FetchWithRetry fetches a URL with retry logic
func FetchWithRetry(cfg *core.Config, url string) ([]byte, error) {
	var (
		resp *http.Response
		err  error
		body []byte
	)

	client, err := CreateHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	// Try to fetch the URL with retries
	for attempt := 0; attempt < cfg.RetryFlag; attempt++ {
		// Check if context is cancelled
		select {
		case <-cfg.Ctx.Done():
			return nil, errors.New("operation cancelled")
		default:
		}

		req, err := http.NewRequestWithContext(cfg.Ctx, "GET", url, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create request")
		}
		req.Header.Set("User-Agent", GetRandomUserAgent(cfg))

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			defer resp.Body.Close()
			body, err = ioutil.ReadAll(resp.Body)
			if err == nil {
				return body, nil
			}
		}

		if err != nil {
			cfg.Log.Debugf("Attempt %d failed: %v", attempt+1, err)
		} else {
			cfg.Log.Debugf("Attempt %d failed with status code: %d", attempt+1, resp.StatusCode)
			resp.Body.Close()
		}

		// Wait before retrying
		time.Sleep(core.DefaultRetryDelay)
	}

	return nil, errors.Errorf("failed after %d attempts", cfg.RetryFlag)
}

// ShouldExcludeURL checks if a URL should be excluded based on the patterns
func ShouldExcludeURL(cfg *core.Config, urlStr string) bool {
	if cfg.ExcludedPatterns == nil && cfg.ExcludeFlag != "" {
		cfg.ExcludedPatterns = strings.Split(cfg.ExcludeFlag, ",")
	}

	for _, pattern := range cfg.ExcludedPatterns {
		if strings.Contains(urlStr, pattern) {
			return true
		}
	}
	return false
}

// CheckURLStatus checks the HTTP status of a URL
func CheckURLStatus(cfg *core.Config, url string) (int, error) {
	// Check cache first
	if cachedStatus, found := cfg.UrlCache.Get("status_" + url); found {
		return cachedStatus.(int), nil
	}

	client, err := CreateHTTPClient(cfg)
	if err != nil {
		return 0, err
	}

	// Try to check the URL status with retries
	for attempt := 0; attempt < cfg.RetryFlag; attempt++ {
		// Check if context is cancelled
		select {
		case <-cfg.Ctx.Done():
			return 0, errors.New("operation cancelled")
		default:
		}

		req, err := http.NewRequestWithContext(cfg.Ctx, "HEAD", url, nil)
		if err != nil {
			return 0, errors.Wrap(err, "failed to create request")
		}
		req.Header.Set("User-Agent", GetRandomUserAgent(cfg))

		resp, err := client.Do(req)
		if err == nil {
			statusCode := resp.StatusCode
			resp.Body.Close()

			// Store in cache
			cfg.UrlCache.Set("status_"+url, statusCode, cache.DefaultExpiration)

			return statusCode, nil
		}

		if cfg.VerboseFlag {
			cfg.Log.Infof("Attempt %d to check URL status failed: %v", attempt+1, err)
		}

		// Wait before retrying
		time.Sleep(core.DefaultRetryDelay)
	}

	return 0, errors.Errorf("failed to check URL status after %d attempts", cfg.RetryFlag)
}

// ShowProgress displays a progress bar in the terminal
func ShowProgress(current, total int64) {
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
		ColorizeText("Progress:", "cyan"),
		ColorizeText(progressBar, "cyan"),
		percentage, current, total)
}
