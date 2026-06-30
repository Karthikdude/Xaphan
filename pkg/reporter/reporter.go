package reporter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/Karthikdude/Xaphan/pkg/core"
	"github.com/Karthikdude/Xaphan/pkg/utils"
	"github.com/pkg/errors"
)

// DetermineSeverity checks the payload severity
func DetermineSeverity(unfilteredSymbols []string) (string, string) {
	criticalSymbols := []string{`"`, `'`, `<`, `>`, `%3c`, `%3e`, `%22`, `%27`, `script`, `onerror`, `onload`}
	mediumSymbols := []string{`$`, `|`, `:`, `;`, `(`, `)`, `{`, `}`, `=`, `alert`, `eval`}
	lowSymbols := []string{`[`, `]`, `/`, `\\`, `*`, `+`}

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

// ExtractXSSDetails generates a list of map records for XSS findings
func ExtractXSSDetails(cfg *core.Config, urls []string) []map[string]interface{} {
	var xssDetails []map[string]interface{}

	if len(urls) == 0 {
		return xssDetails
	}

	fmt.Printf("  %s Analyzing %s potential vulnerabilities...\n",
		utils.ColorizeText("⟳", "cyan"),
		utils.ColorizeText(fmt.Sprintf("%d", len(urls)), "white"))

	for i, url := range urls {
		if len(urls) > 10 && i%5 == 0 {
			percentage := float64(i) / float64(len(urls)) * 100
			fmt.Printf("\r  %s Analysis progress: %.1f%% (%d/%d)  ",
				utils.ColorizeText("⟳", "cyan"),
				percentage, i, len(urls))
		}

		var unfilteredSymbols []string

		if strings.Contains(url, "Unfiltered: [") {
			unfilteredSymbols = strings.Split(strings.Trim(strings.Split(url, "Unfiltered: [")[1], "]"), " ")
		} else if strings.Contains(url, "kxss") {
			unfilteredSymbols = []string{"<", ">", "\"", "'", "script"}
		} else {
			possibleSymbols := []string{"<", ">", "\"", "'", "script", "onerror", "onload"}
			for _, symbol := range possibleSymbols {
				if strings.Contains(strings.ToLower(url), strings.ToLower(symbol)) {
					unfilteredSymbols = append(unfilteredSymbols, symbol)
				}
			}
		}

		severity, severityColor := DetermineSeverity(unfilteredSymbols)
		statusCode := 0
		if cfg.ResponseFlag {
			var err error
			statusCode, err = utils.CheckURLStatus(cfg, url)
			if err != nil && cfg.VerboseFlag {
				fmt.Printf("\n  %s Failed to check status for %s: %v\n",
					utils.ColorizeText("✗", "red"),
					utils.ColorizeText(url, "white"),
					err)
			}
		}
		status := fmt.Sprintf("[Status: %d]", statusCode)
		timestamp := time.Now().Format("[04:01:02:2006]")
		xssDetails = append(xssDetails, map[string]interface{}{
			"url":            url,
			"severity":       severity,
			"status":         status,
			"timestamp":      timestamp,
			"severity_color": severityColor,
		})
		if cfg.VerboseFlag {
			fmt.Printf("\n  %s %s\n", utils.ColorizeText("Found:", "cyan"), url)
			fmt.Printf("  %s %v\n", utils.ColorizeText("Unfiltered:", "cyan"), unfilteredSymbols)
			fmt.Printf("  %s %s\n", utils.ColorizeText("Severity:", "cyan"), severity)
			if cfg.ResponseFlag {
				fmt.Printf("  %s %s\n", utils.ColorizeText("Status:", "cyan"), status)
			}
			fmt.Printf("  %s %s\n", utils.ColorizeText("Timestamp:", "cyan"), timestamp)
			fmt.Println(strings.Repeat("─", 80))
		}
	}

	if len(urls) > 10 {
		fmt.Printf("\r\033[K  %s Analysis complete: Found %s vulnerabilities\n",
			utils.ColorizeText("✓", "green"),
			utils.ColorizeText(fmt.Sprintf("%d", len(xssDetails)),
				func() string {
					if len(xssDetails) > 0 {
						return "red"
					}
					return "green"
				}()))
	}

	return xssDetails
}

// DisplayResults prints results securely and nicely
func DisplayResults(cfg *core.Config, xssDetails []map[string]interface{}) {
	if len(xssDetails) == 0 {
		fmt.Printf("\n  %s No XSS vulnerabilities found\n\n", utils.ColorizeText("✓", "green"))
		return
	}

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

	fmt.Println()
	utils.PrintBoxedHeader("XSS SCAN RESULTS")
	fmt.Printf("\n  Found:  %s Critical: %d  %s Medium: %d  %s Low: %d\n\n",
		utils.ColorizeText("⚠", "red"), criticalCount,
		utils.ColorizeText("⚠", "yellow"), mediumCount,
		utils.ColorizeText("⚠", "blue"), lowCount)

	fmt.Println(strings.Repeat("─", 80))

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

		plainSeverity := strings.Replace(strings.Replace(strings.Replace(severity, "\033[31m", "", -1), "\033[33m", "", -1), "\033[0m", "", -1)
		plainSeverity = strings.Replace(strings.Replace(plainSeverity, "\033[34m", "", -1), "\033[32m", "", -1)

		fmt.Printf("  %s  %s  %s\n", timestamp, utils.ColorizedSeverity(plainSeverity, severityIcon), status)

		fmt.Printf("  %s %s\n", utils.ColorizeText("URL:", "cyan"), url)

		var unfilteredSymbols []string
		if strings.Contains(url, "Unfiltered: [") {
			unfilteredSymbols = strings.Split(strings.Trim(strings.Split(url, "Unfiltered: [")[1], "]"), " ")
		} else if strings.Contains(url, "kxss") {
			unfilteredSymbols = []string{"<", ">", "\"", "'", "script"}
		} else {
			possibleSymbols := []string{"<", ">", "\"", "'", "script", "onerror", "onload"}
			for _, symbol := range possibleSymbols {
				if strings.Contains(strings.ToLower(url), strings.ToLower(symbol)) {
					unfilteredSymbols = append(unfilteredSymbols, symbol)
				}
			}
		}

		if len(unfilteredSymbols) > 0 {
			fmt.Printf("  %s %s\n", utils.ColorizeText("Unfiltered:", "cyan"), strings.Join(unfilteredSymbols, ", "))
		}

		fmt.Println(strings.Repeat("─", 80))
	}

	fmt.Printf("\n  Total vulnerabilities found: %d\n\n", len(xssDetails))
}

func SaveDetailedReport(xssDetails []map[string]interface{}, outputFile string) error {
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

func SaveJSONOutput(xssDetails []map[string]interface{}, outputFile string) error {
	data, err := json.MarshalIndent(xssDetails, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal JSON output")
	}
	return ioutil.WriteFile(outputFile, data, 0644)
}

func SaveHTMLReport(xssDetails []map[string]interface{}, outputFile string) error {
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
