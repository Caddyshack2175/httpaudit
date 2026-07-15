package cmd

import (
	"bufio"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	pkghttp "httpaudit/pkg/http"
)

//go:embed default_frame.html
var defaultFrameTemplate string

var framerCmd = &cobra.Command{
	Use:   "framer",
	Short: "Test for clickjacking vulnerabilities by checking HTTP headers",
	Long: `Test URLs for clickjacking vulnerabilities by checking X-Frame-Options and CSP headers.
Only vulnerable sites (lacking protection headers) will have screenshots generated.`,
	Example: `  # Test URLs from file with screenshots
  httpaudit framer --urls targets.txt -s -o screenshots/

  # Test with authentication cookie
  httpaudit framer --urls targets.txt -s -H "Cookie: session=abc123xyz"

  # Test with multiple custom headers
  httpaudit framer --url https://example.com -s -H "Cookie: session=abc" -H "Authorization: Bearer token123"

  # Test authenticated pages through proxy
  httpaudit framer --urls targets.txt -s -H "Cookie: session=abc" --proxy http://127.0.0.1:8080

  # Test with 5 second screenshot delay
  httpaudit framer --urls targets.txt -s -D 5`,
	RunE: runFramer,
}

func init() {
	rootCmd.AddCommand(framerCmd)

	// Framer specific flags
	framerCmd.Flags().StringP("urls", "u", "", "File containing URLs to test (one per line)")
	framerCmd.Flags().StringP("url", "U", "", "Single URL to test")
	framerCmd.Flags().StringP("template", "T", "", "Custom HTML template file (optional)")
	framerCmd.Flags().BoolP("screenshot", "s", false, "Take screenshots using wkhtmltoimage")
	framerCmd.Flags().IntP("screenshot-delay", "D", 2, "Delay in seconds before taking screenshot")
	framerCmd.Flags().StringP("output-dir", "o", "screenshots", "Directory to save screenshots")
	framerCmd.Flags().IntP("delay", "d", 0, "Delay between processing URLs (seconds)")
	framerCmd.Flags().IntP("threads", "j", 1, "Number of concurrent threads")
	framerCmd.Flags().StringArrayP("header", "H", []string{}, "Custom headers to send (can be used multiple times, e.g., -H 'Cookie: session=abc' -H 'Authorization: Bearer token')")
}

func runFramer(cmd *cobra.Command, args []string) error {
	// Get flags
	urlsFile, _ := cmd.Flags().GetString("urls")
	singleURL, _ := cmd.Flags().GetString("url")
	templateFile, _ := cmd.Flags().GetString("template")
	screenshot, _ := cmd.Flags().GetBool("screenshot")
	screenshotDelay, _ := cmd.Flags().GetInt("screenshot-delay")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	delay, _ := cmd.Flags().GetInt("delay")
	threads, _ := cmd.Flags().GetInt("threads")
	customHeaders, _ := cmd.Flags().GetStringArray("header")

	// Get global flags
	quiet, _ := cmd.Flags().GetBool("quiet")
	verbose, _ := cmd.Flags().GetBool("verbose")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	timeout, _ := cmd.Flags().GetInt("timeout")

	// Validate input
	if urlsFile == "" && singleURL == "" {
		return fmt.Errorf("either --urls or --url must be specified")
	}

	// Load URLs
	var urls []string
	if singleURL != "" {
		urls = append(urls, singleURL)
	}
	if urlsFile != "" {
		loadedURLs, err := loadURLsFromFile(urlsFile)
		if err != nil {
			return fmt.Errorf("error loading URLs from file: %v", err)
		}
		urls = append(urls, loadedURLs...)
	}

	if len(urls) == 0 {
		return fmt.Errorf("no URLs to test")
	}

	// Load or use default template
	var htmlTemplate string
	if templateFile != "" {
		templateData, err := os.ReadFile(templateFile)
		if err != nil {
			return fmt.Errorf("error reading template file: %v", err)
		}
		htmlTemplate = string(templateData)
		if !quiet {
			fmt.Printf("[*] Loaded custom template from: %s\n", templateFile)
		}
	} else {
		htmlTemplate = getDefaultTemplate()
		if !quiet {
			fmt.Println("[*] Using default framing template")
		}
	}

	// Validate template has required placeholder
	if !strings.Contains(htmlTemplate, "{FRAME}") {
		return fmt.Errorf("template must contain {FRAME} placeholder")
	}

	// Parse custom headers into map
	headerMap := make(map[string]string)
	for _, header := range customHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format: %s (expected 'Name: Value')", header)
		}
		headerName := strings.TrimSpace(parts[0])
		headerValue := strings.TrimSpace(parts[1])
		headerMap[headerName] = headerValue
	}

	// Create HTTP client with proxy support if configured
	if timeout == 0 {
		timeout = 10 // Default timeout
	}
	httpClient, err := pkghttp.NewClient(pkghttp.ClientConfig{
		ProxyURL:           proxyURL,
		Timeout:            timeout,
		InsecureSkipVerify: true,
		FollowRedirects:    true,
	})
	if err != nil {
		return fmt.Errorf("error creating HTTP client: %v", err)
	}

	if !quiet && len(customHeaders) > 0 {
		fmt.Printf("[*] Custom headers: %d header(s) will be sent\n", len(customHeaders))
		if verbose {
			for name, value := range headerMap {
				fmt.Printf("    %s: %s\n", name, value)
			}
		}
	}
	if !quiet && proxyURL != "" {
		fmt.Printf("[*] Using proxy: %s\n", proxyURL)
	}

	// Check for wkhtmltoimage if screenshots enabled
	if screenshot {
		if _, err := exec.LookPath("wkhtmltoimage"); err != nil {
			return fmt.Errorf("wkhtmltoimage not found in PATH. Install it or disable --screenshot")
		}

		// Create output directory
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("error creating output directory: %v", err)
		}
		if !quiet {
			fmt.Printf("[*] Screenshots will be saved to: %s/\n", outputDir)
		}
	}

	if !quiet {
		fmt.Printf("[*] Loaded %d URL(s) to test\n", len(urls))
		if screenshot {
			fmt.Printf("[*] Screenshot delay: %d seconds\n", screenshotDelay)
		}
		fmt.Printf("[*] Threads: %d\n", threads)
		fmt.Println(strings.Repeat("=", 80))
	}

	// Process URLs concurrently
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	var mu sync.Mutex

	for i, url := range urls {
		wg.Add(1)
		go func(index int, targetURL string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			mu.Lock()
			if !quiet {
				fmt.Printf("\n[%d/%d] Testing: %s\n", index+1, len(urls), targetURL)
				fmt.Printf("  Checking HTTP headers...\n")
			}
			mu.Unlock()

			// Create HTTP request with custom headers
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				mu.Lock()
				if !quiet {
					fmt.Printf("  [!] Failed to create request: %v\n", err)
					fmt.Printf("  [*] Skipping screenshot (invalid URL)\n")
				}
				mu.Unlock()
				return
			}

			// Add custom headers to request
			for name, value := range headerMap {
				req.Header.Set(name, value)
			}

			// Set User-Agent if not provided by user
			if _, exists := headerMap["User-Agent"]; !exists {
				req.Header.Set("User-Agent", "HTTPHammer/Framer")
			}

			resp, err := httpClient.Do(req)
			var hasXFrameOptions bool
			var xFrameValue string

			if err != nil {
				mu.Lock()
				if !quiet {
					fmt.Printf("  [!] Failed to fetch URL: %v\n", err)
					fmt.Printf("  [*] Skipping screenshot (site unreachable)\n")
				}
				mu.Unlock()
				return
			}

			// Check for X-Frame-Options header
			xFrameValue = resp.Header.Get("X-Frame-Options")
			hasXFrameOptions = xFrameValue != ""

			// Also check for CSP frame-ancestors directive
			cspValue := resp.Header.Get("Content-Security-Policy")
			hasFrameAncestors := strings.Contains(cspValue, "frame-ancestors")

			resp.Body.Close()

			// Determine if site is protected
			isProtected := hasXFrameOptions || hasFrameAncestors

			mu.Lock()
			if !quiet {
				if isProtected {
					if hasXFrameOptions {
						fmt.Printf("  [✓] PROTECTED - X-Frame-Options: %s\n", xFrameValue)
					}
					if hasFrameAncestors {
						fmt.Printf("  [✓] PROTECTED - CSP frame-ancestors directive found\n")
					}
					fmt.Printf("  [*] Skipping screenshot (site is protected)\n")
				} else {
					fmt.Printf("  [!] VULNERABLE - No X-Frame-Options or CSP frame-ancestors header\n")
				}
			}
			mu.Unlock()

			// Only take screenshot if site is VULNERABLE (no protection headers)
			if !isProtected && screenshot {
				baseFilename := sanitizeFilename(targetURL)

				// Generate HTML file with template
				now := time.Now()
				renderedHTML := strings.ReplaceAll(htmlTemplate, "{FRAME}", targetURL)
				renderedHTML = strings.ReplaceAll(renderedHTML, "{DATE}", now.Format("2006-01-02"))
				renderedHTML = strings.ReplaceAll(renderedHTML, "{TIME}", now.Format("15:04:05"))
				renderedHTML = strings.ReplaceAll(renderedHTML, "{URL}", targetURL)

				// Write HTML to temporary file
				tempHTMLPath := filepath.Join(outputDir, "temp_"+baseFilename+".html")
				if err := os.WriteFile(tempHTMLPath, []byte(renderedHTML), 0644); err != nil {
					mu.Lock()
					if !quiet {
						fmt.Printf("  [!] Failed to write HTML file: %v\n", err)
					}
					mu.Unlock()
					return
				}

				// Ensure we clean up the HTML file
				defer os.Remove(tempHTMLPath)

				tempScreenshotPath := filepath.Join(outputDir, "temp_"+baseFilename+".png")

				mu.Lock()
				if !quiet {
					fmt.Printf("  Taking screenshot (delay: %ds)...\n", screenshotDelay)
				}
				mu.Unlock()

				// Build wkhtmltoimage command
				cmdArgs := []string{
					"--enable-local-file-access",
					"--quality", "95",
					"--width", "1920",
				}

				// Add delay if specified
				if screenshotDelay > 0 {
					cmdArgs = append(cmdArgs, "--javascript-delay", fmt.Sprintf("%d", screenshotDelay*1000))
				}

				cmdArgs = append(cmdArgs, tempHTMLPath, tempScreenshotPath)

				screenshotCmd := exec.Command("wkhtmltoimage", cmdArgs...)
				output, err := screenshotCmd.CombinedOutput()

				if err != nil {
					mu.Lock()
					if !quiet {
						fmt.Printf("  [!] Screenshot failed: %v\n", err)
					}
					if verbose {
						fmt.Printf("  Output: %s\n", string(output))
					}
					mu.Unlock()
				} else {
					// Give extra time for file to be completely written
					time.Sleep(500 * time.Millisecond)

					// Determine status based on header check
					var status string
					fileInfo, err := os.Stat(tempScreenshotPath)

					if err == nil {
						// We only screenshot vulnerable sites now, so mark as VULNERABLE
						status = "VULNERABLE"

						mu.Lock()
						if verbose {
							fileSize := fileInfo.Size()
							fmt.Printf("  Screenshot size: %.2f MB\n", float64(fileSize)/(1024*1024))
						}
						mu.Unlock()
					} else {
						status = "ERROR"
					}

					// Create filename with status prefix
					finalFilename := status + "_" + baseFilename + ".png"
					finalPath := filepath.Join(outputDir, finalFilename)

					// Rename temp file to final name with status
					if err := os.Rename(tempScreenshotPath, finalPath); err != nil {
						// If rename fails, keep temp name
						finalPath = tempScreenshotPath
						mu.Lock()
						if verbose {
							fmt.Printf("  [!] Could not rename file: %v\n", err)
						}
						mu.Unlock()
					}

					mu.Lock()
					if !quiet {
						fmt.Printf("  [✓] Screenshot saved: %s\n", finalPath)
					}
					mu.Unlock()
				}
			}

			// Delay between URLs if specified
			if delay > 0 {
				time.Sleep(time.Duration(delay) * time.Second)
			}
		}(i, url)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	if !quiet {
		fmt.Printf("\n%s\n", strings.Repeat("=", 80))
		fmt.Printf("[✓] Completed testing %d URL(s)\n", len(urls))
		if screenshot {
			fmt.Printf("[✓] Screenshots saved to: %s/\n", outputDir)
		}
	}

	return nil
}

// loadURLsFromFile loads URLs from a file, one per line
func loadURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

// sanitizeFilename creates a safe filename from a URL
func sanitizeFilename(url string) string {
	// Remove protocol
	filename := strings.TrimPrefix(url, "https://")
	filename = strings.TrimPrefix(filename, "http://")

	// Replace problematic characters
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		".", "_",
	)

	filename = replacer.Replace(filename)

	// Limit length
	if len(filename) > 100 {
		filename = filename[:100]
	}

	return "frame_" + filename
}

// getDefaultTemplate returns the embedded default HTML template for framing
func getDefaultTemplate() string {
	return defaultFrameTemplate
}

// Legacy inline template (keeping for reference, but using embedded version above)
func getInlineTemplate() string {
	return `<!DOCTYPE html>
<html>
<head>
<title>Clickjacking Test - {URL}</title>
<style>
body {
	background: #2c3e50;
	font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
	margin: 0;
	padding: 20px;
	color: #ecf0f1;
}

.container {
	max-width: 1400px;
	margin: 0 auto;
	background: #34495e;
	border-radius: 10px;
	padding: 30px;
	box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
}

.header {
	text-align: center;
	margin-bottom: 30px;
	padding-bottom: 20px;
	border-bottom: 3px solid #e74c3c;
}

.header h1 {
	color: #e74c3c;
	margin: 0 0 10px 0;
	font-size: 2.5em;
	text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}

.info {
	background: #1abc9c;
	padding: 20px;
	border-radius: 8px;
	margin-bottom: 20px;
	text-align: center;
}

.info p {
	margin: 5px 0;
	font-size: 1.1em;
}

.warning {
	background: #e74c3c;
	color: white;
	padding: 15px;
	border-radius: 8px;
	margin-bottom: 20px;
	text-align: center;
	font-weight: bold;
	font-size: 1.2em;
}

.frame-container {
	background: #000;
	padding: 20px;
	border-radius: 8px;
	box-shadow: inset 0 0 10px rgba(0, 0, 0, 0.5);
}

iframe {
	display: block;
	margin: 0 auto;
	border: 5px solid #95a5a6;
	border-radius: 5px;
	background: white;
}

.click-counter {
	background: #f39c12;
	color: #2c3e50;
	padding: 15px;
	margin-top: 20px;
	border-radius: 8px;
	text-align: center;
	font-size: 1.3em;
	font-weight: bold;
}

.footer {
	text-align: center;
	margin-top: 30px;
	padding-top: 20px;
	border-top: 2px solid #7f8c8d;
	color: #95a5a6;
	font-size: 0.9em;
}

#click-count {
	color: #e74c3c;
	font-size: 2em;
	font-weight: bold;
}
</style>
</head>
<body>
<div class="container">
	<div class="header">
		<h1>🔨 HTTPHammer Clickjacking Test 🔨</h1>
		<p>Framing Vulnerability Assessment</p>
	</div>

	<div class="info">
		<p><strong>Target URL:</strong> {FRAME}</p>
		<p><strong>Test Date:</strong> {DATE} at {TIME}</p>
	</div>

	<div class="warning">
		⚠️ If content appears below, the site is VULNERABLE to clickjacking attacks ⚠️
	</div>

	<div class="frame-container">
		<iframe id="target-frame" src="{FRAME}" width="1300" height="700"></iframe>
	</div>

	<div class="click-counter">
		Frame Interactions Detected: <span id="click-count">0</span>
	</div>

	<div class="footer">
		<p>Generated by HTTPHammer Framing Tool</p>
		<p>This test helps identify clickjacking vulnerabilities by attempting to embed the target in an iframe</p>
	</div>
</div>

<script>
// Click counter to detect iframe interactions and successful framing
let clicks = 0;
let frameLoadedSuccessfully = false;
const clickCountDisplay = document.getElementById('click-count');
const iframe = document.getElementById('target-frame');
const warning = document.querySelector('.warning');
const clickCounter = document.querySelector('.click-counter');

// Detect if iframe loaded successfully
iframe.addEventListener('load', function() {
	// Wait a bit for content to settle, then check if we can detect it loaded
	setTimeout(function() {
		try {
			// Try to access iframe - this will fail for cross-origin but the load event means something loaded
			const iframeDoc = iframe.contentDocument || iframe.contentWindow.document;

			// If we got here, same-origin content loaded (very vulnerable!)
			frameLoadedSuccessfully = true;
			clicks = 1;
			clickCountDisplay.textContent = '1';
			clickCountDisplay.style.color = '#27ae60';
			warning.style.background = '#27ae60';
			warning.innerHTML = '⚠️ VULNERABLE - Site lacks X-Frame-Options header (can be framed) ⚠️';
			clickCounter.style.background = '#27ae60';
			document.title = 'VULNERABLE - ' + document.title;
			console.log('SUCCESS: Same-origin content loaded - VULNERABLE');
		} catch (e) {
			// Cross-origin - but did it load?
			// Check if iframe has a window object with location
			try {
				if (iframe.contentWindow && iframe.contentWindow.length >= 0) {
					// Iframe has a valid window, likely loaded cross-origin content
					frameLoadedSuccessfully = true;
					clicks = 1;
					clickCountDisplay.textContent = '1';
					clickCountDisplay.style.color = '#27ae60';
					warning.style.background = '#27ae60';
					warning.innerHTML = '⚠️ VULNERABLE - Site lacks X-Frame-Options header (can be framed) ⚠️';
					clickCounter.style.background = '#27ae60';
					document.title = 'VULNERABLE - ' + document.title;
					console.log('SUCCESS: Cross-origin content loaded - VULNERABLE to clickjacking');
				}
			} catch (e2) {
				// Completely blocked
				clicks = 0;
				clickCountDisplay.textContent = '0';
				warning.style.background = '#3498db';
				warning.innerHTML = '⚠️ PROTECTED - Site has X-Frame-Options header set (cannot be framed) ⚠️';
				clickCounter.style.background = '#3498db';
				clickCounter.querySelector('span').style.color = '#2c3e50';
				document.title = 'PROTECTED - ' + document.title;
				console.log('PROTECTED: Iframe blocked by X-Frame-Options or CSP');
			}
		}
	}, 1000);
});

// Monitor iframe focus events for user interactions
const iframeMonitor = setInterval(function() {
	const activeElement = document.activeElement;
	if (activeElement && activeElement.tagName === 'IFRAME' && frameLoadedSuccessfully) {
		clicks++;
		clickCountDisplay.textContent = clicks + ' (User clicked iframe)';
		clickCountDisplay.style.animation = 'pulse 0.5s';
		setTimeout(() => {
			clickCountDisplay.style.animation = '';
		}, 500);
	}
}, 100);

// Handle iframe errors
iframe.addEventListener('error', function() {
	clicks = 0;
	clickCountDisplay.textContent = '0';
	warning.style.background = '#3498db';
	warning.innerHTML = '⚠️ PROTECTED - Failed to load (Network Error or X-Frame-Options) ⚠️';
	document.title = 'PROTECTED - ' + document.title;
	console.log('ERROR: Iframe failed to load');
});
</script>
</body>
</html>`
}
