package scanner

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/Karthikdude/Xaphan/pkg/core"
	"github.com/Karthikdude/Xaphan/pkg/utils"
)

// SplitIntoBatches splits URLs into batches
func SplitIntoBatches(urls []string, batchSize int) [][]string {
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

// DetermineBatchSize calculates the optimal batch size
func DetermineBatchSize(urlCount int) int {
	if urlCount <= 10 {
		return 1
	}
	return urlCount / 10
}

// SaveURLsToFile saves a list of URLs to a file
func SaveURLsToFile(urls []string, filename string, suffix string) error {
	if filename == "" {
		return nil
	}

	outputFile := filename
	if suffix != "" {
		// check if filename has an extension
		if idx := strings.LastIndex(filename, "."); idx != -1 {
			outputFile = filename[:idx] + "-" + suffix + filename[idx:]
		} else {
			outputFile = filename + "-" + suffix
		}
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, url := range urls {
		if url != "" {
			file.WriteString(url + "\n")
		}
	}

	fmt.Printf("  %s Saved %d URLs to %s\n",
		utils.ColorizeText("✓", "green"),
		len(urls),
		utils.ColorizeText(outputFile, "green"))

	return nil
}

// RunGfXss runs the gf xss pattern matcher on a list of URLs
func RunGfXss(cfg *core.Config, urls []string, domain string) []string {
	tmpFile, err := ioutil.TempFile("", "xaphan-urls-*.txt")
	if err != nil {
		fmt.Printf("  %s Failed to create temp file: %v\n", utils.ColorizeText("✗", "red"), err)
		return []string{}
	}
	defer os.Remove(tmpFile.Name())

	for _, url := range urls {
		if url != "" {
			tmpFile.WriteString(url + "\n")
		}
	}
	tmpFile.Close()

	fmt.Printf("  %s Running GF XSS pattern matcher...\n", utils.ColorizeText("⟳", "cyan"))
	cmd := exec.Command("gf", "xss", tmpFile.Name())
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("  %s Failed to run gf xss: %v\n", utils.ColorizeText("✗", "red"), err)
		fmt.Printf("  %s Output: %s\n", utils.ColorizeText("!", "yellow"), string(output))

		fmt.Printf("  %s Trying alternative gf method...\n", utils.ColorizeText("⟳", "cyan"))
		if runtime.GOOS == "windows" {
			cmd = exec.Command("powershell", "-Command", "Get-Content "+tmpFile.Name()+" | gf xss")
		} else {
			cmd = exec.Command("bash", "-c", "cat "+tmpFile.Name()+" | gf xss")
		}

		output, err = cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("  %s Alternative gf method failed: %v\n", utils.ColorizeText("✗", "red"), err)
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
		utils.ColorizeText("✓", "green"),
		utils.ColorizeText(fmt.Sprintf("%d", len(filteredGfURLs)), "white"))

	if len(filteredGfURLs) == 0 {
		fmt.Printf("  %s No potential XSS endpoints found, skipping further processing\n",
			utils.ColorizeText("!", "yellow"))
		return []string{}
	}

	if cfg.SaveGfFlag != "" {
		if err := SaveURLsToFile(filteredGfURLs, cfg.SaveGfFlag, domain+"-gf"); err != nil {
			fmt.Printf("  %s Failed to save GF URLs: %v\n", utils.ColorizeText("✗", "red"), err)
		}
	}

	return filteredGfURLs
}

// RunUro runs uro on a list of URLs
func RunUro(cfg *core.Config, urls []string, domain string) []string {
	uroTmpFile, err := ioutil.TempFile("", "xaphan-uro-*.txt")
	if err != nil {
		fmt.Printf("  %s Failed to create uro temp file: %v\n", utils.ColorizeText("✗", "red"), err)
		return urls // Fallback to original
	}
	defer os.Remove(uroTmpFile.Name())

	for _, url := range urls {
		if url != "" {
			uroTmpFile.WriteString(url + "\n")
		}
	}
	uroTmpFile.Close()

	fmt.Printf("  %s Running URO for URL optimization...\n", utils.ColorizeText("⟳", "cyan"))
	var cmd *exec.Cmd
	var output []byte

	cmd = exec.Command("bash", "-c", "cat "+uroTmpFile.Name()+" | uro")
	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("  %s Failed to run uro: %v\n", utils.ColorizeText("✗", "red"), err)
		fmt.Printf("  %s Output: %s\n", utils.ColorizeText("!", "yellow"), string(output))

		if runtime.GOOS == "windows" {
			fmt.Printf("  %s Trying Windows method for uro...\n", utils.ColorizeText("⟳", "cyan"))
			cmd = exec.Command("powershell", "-Command", "Get-Content "+uroTmpFile.Name()+" | uro")
			output, err = cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("  %s Windows method for uro failed: %v\n", utils.ColorizeText("✗", "red"), err)
				cmd = exec.Command("uro", "-i", uroTmpFile.Name())
				output, err = cmd.CombinedOutput()
				if err != nil {
					fmt.Printf("  %s All uro methods failed, using original GF results\n", utils.ColorizeText("!", "yellow"))
					return urls
				}
			}
		} else {
			cmd = exec.Command("uro", "-i", uroTmpFile.Name())
			output, err = cmd.CombinedOutput()
			if err != nil {
				fmt.Printf("  %s All uro methods failed, using original GF results\n", utils.ColorizeText("!", "yellow"))
				return urls
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
		utils.ColorizeText("✓", "green"),
		utils.ColorizeText(fmt.Sprintf("%d", len(filteredUroURLs)), "white"))

	if len(filteredUroURLs) == 0 {
		fmt.Printf("  %s URO returned no results, using original GF results\n", utils.ColorizeText("!", "yellow"))
		filteredUroURLs = urls
	}

	if cfg.SaveUroFlag != "" {
		if err := SaveURLsToFile(filteredUroURLs, cfg.SaveUroFlag, domain+"-uro"); err != nil {
			fmt.Printf("  %s Failed to save URO URLs: %v\n", utils.ColorizeText("✗", "red"), err)
		}
	}

	return filteredUroURLs
}

// ProcessBatchWithGxss runs Gxss on a batch of URLs
func ProcessBatchWithGxss(batch []string) []string {
	if len(batch) == 0 {
		return []string{}
	}

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

	cmd := exec.Command("bash", "-c", "cat "+tmpFile.Name()+" | Gxss")
	output, err := cmd.CombinedOutput()

	if err != nil {
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

	results := strings.Split(string(output), "\n")
	var filtered []string
	for _, line := range results {
		if line != "" {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

// ProcessBatchWithKxss runs kxss on a batch of URLs
func ProcessBatchWithKxss(batch []string) []string {
	if len(batch) == 0 {
		return []string{}
	}

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

	cmd := exec.Command("bash", "-c", "cat "+tmpFile.Name()+" | kxss")
	output, err := cmd.CombinedOutput()

	if err != nil {
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

	results := strings.Split(string(output), "\n")
	var filtered []string
	for _, line := range results {
		if line != "" {
			filtered = append(filtered, line)
		}
	}
	return filtered
}
