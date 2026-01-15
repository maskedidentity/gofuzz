#!/bin/bash
echo "Building GoFuzz..."
go mod init gofuzz
go mod tidy
go build -o gofuzz main.go
echo "Build complete! Run: ./gofuzz --help"
┌─[root]──[dig48]──[~/bugbounty/tools/test_fuzz]
└──╼ $ cat main.go
// main.go (fixed version)
package main

import (
        "bufio"
        "flag"
        "fmt"
        "net/http"
        "net/url"
        "os"
        "os/exec"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

type Fuzzer struct {
        urlTemplate string
        wordlist    []string
        rateLimit   int
        resolvers   []string
        stats       struct {
                requests  uint64
                success   uint64
                errors    uint64
                startTime time.Time
        }
}

// HTTPX mode struct
type HTTPX struct {
        urls      []string
        rateLimit int
        resolvers []string
        stats     struct {
                requests  uint64
                success   uint64
                errors    uint64
                startTime time.Time
        }
}

func NewFuzzer(urlTemplate string, wordlist []string, rateLimit int, resolvers []string) *Fuzzer {
        return &Fuzzer{
                urlTemplate: urlTemplate,
                wordlist:    wordlist,
                rateLimit:   rateLimit,
                resolvers:   resolvers,
        }
}

func NewHTTPX(urls []string, rateLimit int, resolvers []string) *HTTPX {
        return &HTTPX{
                urls:      urls,
                rateLimit: rateLimit,
                resolvers: resolvers,
        }
}

func (f *Fuzzer) generateURL(word string) (string, error) {
        // Remove leading slash if present
        cleanWord := strings.TrimPrefix(word, "/")
        generated := strings.ReplaceAll(f.urlTemplate, "FUZZ", cleanWord)

        // Validate URL
        _, err := url.Parse(generated)
        if err != nil {
                return "", err
        }

        return generated, nil
}

// Common curl request function used by both modes
func curlRequest(targetURL string, resolvers []string, requestNum uint64) (*http.Response, error) {
        // Build curl command with headers
        cmd := exec.Command("curl", "-s", "-i", targetURL,
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/;q=0.8",
                "-H", "Accept-Language: en-US,en;q=0.9",
                "-H", "Accept-Encoding: gzip, deflate, br",
                "-H", "Connection: keep-alive",
                "-H", "Upgrade-Insecure-Requests: 1",
                "-H", "Cache-Control: max-age=0",
                "-H", "Sec-Fetch-Dest: document",
                "-H", "Sec-Fetch-Mode: navigate",
                "-H", "Sec-Fetch-Site: none",
                "-H", "Sec-Fetch-User: ?1",
                "--max-time", "10",
                "--retry", "0",
                "--compressed",
                "--location", // Follow redirects
        )

        // If resolvers are provided, use them with curl's --dns-servers
        if len(resolvers) > 0 {
                // Get next resolver in round-robin
                idx := requestNum % uint64(len(resolvers))
                resolver := resolvers[idx]
                cmd.Args = append(cmd.Args, "--dns-servers", resolver)
        }

        output, err := cmd.Output()
        if err != nil {
                // Return a minimal response for timeout/connection errors
                if strings.Contains(err.Error(), "exit status") ||
                        strings.Contains(err.Error(), "timeout") ||
                        strings.Contains(err.Error(), "connection refused") ||
                        strings.Contains(err.Error(), "Could not resolve host") {
                        return &http.Response{
                                StatusCode: 0,
                                Status:     "ERROR",
                                Request: &http.Request{
                                        URL: &url.URL{Path: targetURL},
                                },
                        }, nil
                }
                return nil, err
        }

        return parseCurlOutput(output, targetURL)
}

func parseCurlOutput(output []byte, targetURL string) (*http.Response, error) {
        // Parse the curl -i output (headers + body)
        lines := strings.Split(string(output), "\n")

        // Find the last HTTP response line (in case of redirects)
        var statusLine string
        var headerEnd int
        var lastHTTPIdx = -1

        for i, line := range lines {
                if strings.HasPrefix(line, "HTTP/") {
                        lastHTTPIdx = i
                }
        }

        if lastHTTPIdx >= 0 {
                statusLine = lines[lastHTTPIdx]
                headerEnd = lastHTTPIdx
        }

        if statusLine == "" {
                return nil, fmt.Errorf("no HTTP response")
        }

        // Parse status code
        parts := strings.Split(statusLine, " ")
        if len(parts) < 3 {
                return nil, fmt.Errorf("invalid status line")
        }

        statusCode := 0
        fmt.Sscanf(parts[1], "%d", &statusCode)

        // Parse headers
        headers := make(http.Header)
        for i := headerEnd + 1; i < len(lines); i++ {
                line := strings.TrimSpace(lines[i])
                if line == "" {
                        // Empty line marks end of headers
                        break
                }
                if idx := strings.Index(line, ":"); idx > 0 {
                        key := strings.TrimSpace(line[:idx])
                        value := strings.TrimSpace(line[idx+1:])
                        headers.Add(key, value)
                }
        }

        // Create response
        resp := &http.Response{
                StatusCode: statusCode,
                Status:     statusLine,
                Header:     headers,
                Request: &http.Request{
                        URL: &url.URL{Path: targetURL},
                },
        }

        // Get content length
        if cl := headers.Get("Content-Length"); cl != "" {
                var contentLength int64
                fmt.Sscanf(cl, "%d", &contentLength)
                resp.ContentLength = contentLength
        } else {
                // Estimate from body
                bodyStart := headerEnd + 1
                for i := bodyStart; i < len(lines); i++ {
                        if strings.TrimSpace(lines[i]) == "" {
                                bodyStart = i + 1
                                break
                        }
                }
                body := strings.Join(lines[bodyStart:], "\n")
                resp.ContentLength = int64(len(body))
        }

        return resp, nil
}

func (f *Fuzzer) sendRequest(targetURL string) (*http.Response, error) {
        resp, err := curlRequest(targetURL, f.resolvers, atomic.AddUint64(&f.stats.requests, 1))
        if err != nil {
                atomic.AddUint64(&f.stats.errors, 1)
                return nil, err
        }

        atomic.AddUint64(&f.stats.success, 1)
        return resp, nil
}

func (h *HTTPX) sendRequest(targetURL string) (*http.Response, error) {
        resp, err := curlRequest(targetURL, h.resolvers, atomic.AddUint64(&h.stats.requests, 1))
        if err != nil {
                atomic.AddUint64(&h.stats.errors, 1)
                return nil, err
        }

        atomic.AddUint64(&h.stats.success, 1)
        return resp, nil
}

func formatResponse(resp *http.Response, targetURL string) string {
        // Handle error responses
        if resp.StatusCode == 0 {
                return fmt.Sprintf("\033[31m[×] ERROR\033[0m | %s", targetURL)
        }

        statusClass := resp.StatusCode / 100
        var statusColor string
        var statusIcon string

        switch statusClass {
        case 2:
                statusColor = "\033[32m" // Green
                statusIcon = "[✓]"
        case 3:
                statusColor = "\033[33m" // Yellow
                statusIcon = "[→]"
        case 4:
                statusColor = "\033[35m" // Magenta
                statusIcon = "[!]"
        case 5:
                statusColor = "\033[31m" // Red
                statusIcon = "[×]"
        default:
                statusColor = "\033[37m" // White
                statusIcon = "[?]"
        }

        // Get content length
        contentLength := resp.ContentLength
        if contentLength < 0 {
                contentLength = 0
        }

        // Build the output
        result := fmt.Sprintf("%s%s %d\033[0m | Size: %7d bytes | %s",
                statusColor, statusIcon, resp.StatusCode, contentLength, targetURL)

        // Add redirect location if present
        if resp.StatusCode >= 300 && resp.StatusCode < 400 {
                location := resp.Header.Get("Location")
                if location != "" {
                        result += fmt.Sprintf(" | → %s", location)
                }
        }

        // Add server header if present
        server := resp.Header.Get("Server")
        if server != "" {
                result += fmt.Sprintf(" | Server: %s", server)
        }

        return result
}

func (f *Fuzzer) analyzeResponse(resp *http.Response, targetURL string) {
        fmt.Println(formatResponse(resp, targetURL))
}

func (h *HTTPX) analyzeResponse(resp *http.Response, targetURL string) {
        fmt.Println(formatResponse(resp, targetURL))
}

func (f *Fuzzer) showStats() {
        elapsed := time.Since(f.stats.startTime)
        reqPerSec := float64(f.stats.requests) / elapsed.Seconds()

        fmt.Println("\n" + strings.Repeat("=", 60))
        fmt.Printf("Fuzzing completed!\n")
        fmt.Printf("Time elapsed: %s\n", elapsed.Round(time.Second))
        fmt.Printf("Total requests: %d\n", f.stats.requests)
        fmt.Printf("Successful: %d\n", f.stats.success)
        fmt.Printf("Errors: %d\n", f.stats.errors)
        if len(f.resolvers) > 0 {
                fmt.Printf("Resolvers used: %d\n", len(f.resolvers))
        }
        fmt.Printf("Requests/sec: %.2f\n", reqPerSec)
        fmt.Println(strings.Repeat("=", 60))
}

func (h *HTTPX) showStats() {
        elapsed := time.Since(h.stats.startTime)
        reqPerSec := float64(h.stats.requests) / elapsed.Seconds()

        fmt.Println("\n" + strings.Repeat("=", 60))
        fmt.Printf("HTTPX scanning completed!\n")
        fmt.Printf("Time elapsed: %s\n", elapsed.Round(time.Second))
        fmt.Printf("Total URLs tested: %d\n", h.stats.requests)
        fmt.Printf("Successful: %d\n", h.stats.success)
        fmt.Printf("Errors: %d\n", h.stats.errors)
        if len(h.resolvers) > 0 {
                fmt.Printf("Resolvers used: %d\n", len(h.resolvers))
        }
        fmt.Printf("Requests/sec: %.2f\n", reqPerSec)
        fmt.Println(strings.Repeat("=", 60))
}

func (f *Fuzzer) Run() {
        f.stats.startTime = time.Now()

        fmt.Printf("Starting fuzzer (using curl)...\n")
        fmt.Printf("Target URL: %s\n", f.urlTemplate)
        fmt.Printf("Wordlist size: %d\n", len(f.wordlist))
        fmt.Printf("Rate limit: %d req/sec\n", f.rateLimit)
        if len(f.resolvers) > 0 {
                fmt.Printf("Resolvers: %d\n", len(f.resolvers))
                fmt.Println("DNS rotation will be used")
        }
        fmt.Println(strings.Repeat("-", 60))

        // Rate limiting
        rateLimiter := time.NewTicker(time.Second / time.Duration(f.rateLimit))
        defer rateLimiter.Stop()

        var wg sync.WaitGroup
        semaphore := make(chan struct{}, 10)

        for _, word := range f.wordlist {
                <-rateLimiter.C

                wg.Add(1)
                semaphore <- struct{}{}

                go func(w string) {
                        defer wg.Done()
                        defer func() { <-semaphore }()

                        targetURL, err := f.generateURL(w)
                        if err != nil {
                                return
                        }

                        resp, err := f.sendRequest(targetURL)
                        if err != nil {
                                // Don't print common curl errors
                                if !strings.Contains(err.Error(), "exit status") &&
                                        !strings.Contains(err.Error(), "timeout") &&
                                        !strings.Contains(err.Error(), "connection refused") {
                                        fmt.Printf("[ERROR] %s: %v\n", targetURL, err)
                                }
                                return
                        }

                        f.analyzeResponse(resp, targetURL)
                }(word)
        }

        wg.Wait()
        f.showStats()
}

func (h *HTTPX) Run() {
        h.stats.startTime = time.Now()

        fmt.Printf("Starting HTTPX mode (using curl)...\n")
        fmt.Printf("URLs to test: %d\n", len(h.urls))
        fmt.Printf("Rate limit: %d req/sec\n", h.rateLimit)
        if len(h.resolvers) > 0 {
                fmt.Printf("Resolvers: %d\n", len(h.resolvers))
                fmt.Println("DNS rotation will be used")
        }
        fmt.Println(strings.Repeat("-", 60))

        // Rate limiting
        rateLimiter := time.NewTicker(time.Second / time.Duration(h.rateLimit))
        defer rateLimiter.Stop()

        var wg sync.WaitGroup
        semaphore := make(chan struct{}, 10)

        for _, targetURL := range h.urls {
                <-rateLimiter.C

                wg.Add(1)
                semaphore <- struct{}{}

                go func(u string) { // Changed variable name from 'url' to 'u'
                        defer wg.Done()
                        defer func() { <-semaphore }()

                        // Validate URL format - FIXED THIS LINE
                        if _, err := url.Parse(u); err != nil { // Changed 'url' to 'u'
                                fmt.Printf("[INVALID URL] %s: %v\n", u, err)
                                return
                        }

                        resp, err := h.sendRequest(u) // Changed 'url' to 'u'
                        if err != nil {
                                // Don't print common curl errors
                                if !strings.Contains(err.Error(), "exit status") &&
                                        !strings.Contains(err.Error(), "timeout") &&
                                        !strings.Contains(err.Error(), "connection refused") {
                                        fmt.Printf("[ERROR] %s: %v\n", u, err) // Changed 'url' to 'u'
                                }
                                return
                        }

                        h.analyzeResponse(resp, u) // Changed 'url' to 'u'
                }(targetURL)
        }

        wg.Wait()
        h.showStats()
}

func readLines(filename string) ([]string, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        var lines []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                        lines = append(lines, line)
                }
        }
        return lines, scanner.Err()
}

func main() {
        var (
                urlTemplate  string
                wordlistFile string
                rateLimit    int
                resolverFile string
                urlFile      string
                fuzzMode     bool
                httpxMode    bool
                showHelp     bool
        )

        // Flags for both modes
        flag.IntVar(&rateLimit, "rate", 10, "Rate limit (requests per second)")
        flag.IntVar(&rateLimit, "r", 10, "Rate limit (requests per second)")
        flag.StringVar(&resolverFile, "resolvers", "", "Resolver file path (one IP per line)")
        flag.StringVar(&resolverFile, "rs", "", "Resolver file path (one IP per line)")
        flag.BoolVar(&showHelp, "h", false, "Show help")
        flag.BoolVar(&showHelp, "help", false, "Show help")

        // FUZZ mode specific flags
        flag.StringVar(&urlTemplate, "FUZZ", "", "Target URL with FUZZ placeholder (for fuzzing mode)")
        flag.StringVar(&wordlistFile, "w", "", "Wordlist file path (for fuzzing mode)")
        flag.StringVar(&wordlistFile, "wordlist", "", "Wordlist file path (for fuzzing mode)")

        // HTTPX mode specific flags
        flag.StringVar(&urlFile, "HTTPX", "", "File containing URLs to test (one per line)")
        flag.StringVar(&urlFile, "urls", "", "File containing URLs to test (one per line)")

        flag.Parse()

        // Determine mode based on flags
        fuzzMode = urlTemplate != "" || wordlistFile != ""
        httpxMode = urlFile != ""

        if showHelp {
                fmt.Println("GoFuzz - Advanced URL Fuzzing/Testing Tool (using curl)")
                fmt.Println("\nTwo modes available:")
                fmt.Println("  1. FUZZ mode: Fuzz URLs with a wordlist")
                fmt.Println("  2. HTTPX mode: Test list of full URLs")
                fmt.Println("\nFUZZ Mode (fuzzing):")
                fmt.Println("  -FUZZ <url>       Target URL with FUZZ placeholder (required)")
                fmt.Println("  -w, --wordlist    Wordlist file path (required)")
                fmt.Println("  -r, --rate        Rate limit in requests per second (default: 10)")
                fmt.Println("  -rs, --resolvers  Resolver file with IP addresses (one per line)")
                fmt.Println("\nHTTPX Mode (testing URLs):")
                fmt.Println("  -HTTPX <file>     File containing URLs to test (one per line)")
                fmt.Println("  -r, --rate        Rate limit (default: 10)")
                fmt.Println("  -rs, --resolvers  Resolver file with IP addresses")
                fmt.Println("\nCommon Options:")
                fmt.Println("  -h, --help        Show this help message")
                fmt.Println("\nExamples:")
                fmt.Println("  FUZZ mode:")
                fmt.Println("    ./gofuzz -FUZZ 'http://example.com/FUZZ' -w wordlist.txt")
                fmt.Println("    ./gofuzz -FUZZ 'https://target.com/api/v1/FUZZ' -w paths.txt -rate 20")
                fmt.Println("  HTTPX mode:")
                fmt.Println("    ./gofuzz -HTTPX urls.txt")
                fmt.Println("    ./gofuzz -HTTPX urls.txt -rate 50 -resolvers dns_servers.txt")
                fmt.Println("\nNote: This tool uses curl internally. Make sure curl is installed.")
                os.Exit(0)
        }

        // Check if curl is installed
        if _, err := exec.LookPath("curl"); err != nil {
                fmt.Println("Error: curl is not installed or not in PATH")
                fmt.Println("Install curl: sudo apt install curl (Ubuntu/Debian)")
                os.Exit(1)
        }

        // Read resolvers if provided
        var resolvers []string
        if resolverFile != "" {
                var err error
                resolvers, err = readLines(resolverFile)
                if err != nil {
                        fmt.Printf("Error reading resolver file: %v\n", err)
                        os.Exit(1)
                }
        }

        // Execute appropriate mode
        if fuzzMode && httpxMode {
                fmt.Println("Error: Cannot use both FUZZ and HTTPX modes simultaneously")
                fmt.Println("Use either -FUZZ for fuzzing or -HTTPX for URL testing")
                os.Exit(1)
        } else if fuzzMode {
                // FUZZ MODE
                if !strings.Contains(urlTemplate, "FUZZ") {
                        fmt.Println("Error: URL must contain 'FUZZ' placeholder")
                        os.Exit(1)
                }

                if wordlistFile == "" {
                        fmt.Println("Error: Wordlist file is required for FUZZ mode (-w)")
                        os.Exit(1)
                }

                // Read wordlist
                wordlist, err := readLines(wordlistFile)
                if err != nil {
                        fmt.Printf("Error reading wordlist: %v\n", err)
                        os.Exit(1)
                }

                if len(wordlist) == 0 {
                        fmt.Println("Error: Wordlist is empty")
                        os.Exit(1)
                }

                // Create and run fuzzer
                fuzzer := NewFuzzer(urlTemplate, wordlist, rateLimit, resolvers)
                fuzzer.Run()
        } else if httpxMode {
                // HTTPX MODE
                // Read URLs from file
                urls, err := readLines(urlFile)
                if err != nil {
                        fmt.Printf("Error reading URL file: %v\n", err)
                        os.Exit(1)
                }

                if len(urls) == 0 {
                        fmt.Println("Error: URL file is empty")
                        os.Exit(1)
                }

                // Create and run HTTPX tester
                httpx := NewHTTPX(urls, rateLimit, resolvers)
                httpx.Run()
        } else {
                fmt.Println("Error: Please specify a mode:")
                fmt.Println("  Use -FUZZ <url> for fuzzing mode")
                fmt.Println("  Use -HTTPX <file> for URL testing mode")
                fmt.Println("\nUse -h for help")
                os.Exit(1)
        }
}
