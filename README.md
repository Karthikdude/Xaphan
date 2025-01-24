# Xaphan

![Xaphan](xaphan.jpg)

## Introduction

Xaphan is a command-line tool designed to automate the detection of Cross-Site Scripting (XSS) vulnerabilities by identifying unfiltered parameters in web applications. It leverages various tools and APIs to fetch URLs, analyze them for potential XSS risks, and provide detailed reports. Xaphan is built to be efficient, easy to use, and highly customizable, making it a valuable asset for security professionals and developers alike.

## Features

- **Automated XSS Detection**: Automatically detects XSS vulnerabilities in web applications.
- **Multiple URL Fetching Options**: Supports fetching URLs using Wayback Machine, gau, and other custom methods.
- **Detailed Reporting**: Provides detailed and JSON formatted reports of the findings.
- **Verbose Output**: Offers verbose output for detailed inspection.
- **HTTP Response Status Check**: Checks the HTTP response status codes of the URLs.
- **Concurrent Processing**: Utilizes multiple threads for concurrent processing of domains, significantly speeding up the scanning process.
- **Rate Limiting**: Implements rate limiting to avoid overwhelming APIs and external services.
- **Customizable Timeout**: Allows users to set custom timeouts for URL collection and status checks.

## Installation

To install Xaphan, follow these steps:

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/Karthikdude/xaphan
   cd xaphan
   ```

2. **Install Dependencies**:
   ```sh
   go mod tidy
   ```

3. **Install Additional Tools**:
   - Ensure you have `gau`, `waybackurls`, `gf`, `uro`, `Gxss`, and `kxss` installed. You can install them using the following commands:
     ```sh
     go install github.com/lc/gau/v2/cmd/gau@latest
     go install github.com/tomnomnom/waybackurls@latest
     go install github.com/tomnomnom/gf@latest
     go install github.com/tomnomnom/uro@latest
     go install github.com/KathanP19/Gxss@latest
     go install github.com/KathanP19/kxss@latest
     ```

4. **Build the Tool**:
   ```sh
    go build -o xaphan main.go
   ```
   **Build the Tool**:
   ```sh
    go build -o xaphan main.go
   ```

## Usage

![Usage](usage.png)

### Basic Usage

To scan a single domain:
```sh
./xaphan -u testphp.vulnweb.com --wayback
```

To scan a list of domains from a file:
```sh
./xaphan -l domains.txt --gau
```

### Options

- `-u`, `--url`: Scan a single domain.
- `-l`, `--list`: File containing a list of domains to scan.
- `--wayback`: Use Wayback Machine to fetch URLs.
- `--gau`: Use gau to fetch URLs.
- `-v`, `--verbose`: Enable verbose output.
- `-r`, `--response`: Display HTTP response status codes.
- `-d`, `--detailed`: Save detailed report to a file.
- `--json`: Save results in JSON format.
- `-h`, `--help`: Show this help message and exit.
- `-t`, `--threads`: Number of threads to use for concurrent processing (default is 50).

### Example

```sh
./xaphan -u testphp.vulnweb.com --gau -r --json output.json
```

## Tools

Xaphan utilizes the following tools for URL fetching and XSS detection:

| Tool         | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| **gau**      | A fast URL collector.                                                         |
| **waybackurls** | Fetches URLs from the Wayback Machine.                                       |
| **gf**       | A grep for URLs.                                                              |
| **uro**      | A tool to unfurl and rebuild URLs.                                           |
| **Gxss**     | A tool to detect XSS vulnerabilities.                                          |
| **kxss**     | A tool to detect XSS vulnerabilities.                                          |

## Results

![Results](results.png)

Xaphan provides detailed results for each domain scanned. The results include:

- **Timestamp**: The time when the scan was performed.
- **Severity**: The severity level of the XSS vulnerability (CRITICAL, MEDIUM, LOW, SAFE).
- **URL**: The URL where the XSS vulnerability was found.
- **Status**: The HTTP response status code.
- **Unfiltered Symbols**: The symbols that were found unfiltered in the URL.

## Contributing

Contributions are welcome! Please feel free to submit issues and enhancement requests. If you would like to contribute, follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For more information, please contact [Karthik S Sathyan](https://karthik-s-sathyan.vercel.app).

---

Developed by Karthik S Sathyan

[LinkedIn](https://www.linkedin.com/in/karthik-s-sathyan/)
