package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/firefox"
)

const (
	BANNER = `
    .d8888b.           888    d8P                             888      
   d88P  Y88b          888   d8P                              888      
   888    888          888  d8P                               888      
   888         .d88b.  888d88K     88888b.   .d88b.   .d8888b 888  888 
   888  88888 d88""88b 8888888b    888 "88b d88""88b d88P"    888 .88P 
   888    888 888  888 888  Y88b   888  888 888  888 888      888888K  
   Y88b  d88P Y88..88P 888   Y88b  888  888 Y88..88P Y88b.    888 "88b 
    "Y8888P88  "Y88P"  888    Y88b 888  888  "Y88P"   "Y8888P 888  888 
      
	  v0.5                                              @waffl3ss`

	MITMPROXY_PORT     = 8000
	CLIENT_VERSION     = "27/1.0.0.2021011237"
	URL_TEAMS          = "https://teams.microsoft.com/api/mt/emea/beta/users/"
	URL_PRESENCE_TEAMS = "https://presence.teams.microsoft.com/v1/presence/getpresence/"
	TOKEN_FILE         = "token.txt"

	TENANT_LOOKUP_BASE_URL = "https://tenantidlookup.com"
	TENANT_LOOKUP_AUTH_URL = TENANT_LOOKUP_BASE_URL + "/api/v1/authenticate"
	TENANT_LOOKUP_API_URL  = TENANT_LOOKUP_BASE_URL + "/api/v1/tenant-id"
)

type Config struct {
	RunTeams     bool
	RunOneDrive  bool
	TeamsLegacy  bool
	TeamsStatus  bool
	InputFile    string
	OutputFile   string
	TargetDomain string
	TeamsToken   string
	MaxThreads   int
	VerboseMode  bool
}

type Results struct {
	ValidNames  []string
	LegacyNames []string
	StatusNames []string
	mu          sync.Mutex
}

type PresenceInfo struct {
	Availability    string `json:"availability"`
	DeviceType      string `json:"deviceType"`
	OutOfOfficeNote string `json:"outOfOfficeNote"`
}

type TeamsResponse struct {
	SkypeID  string `json:"skypeId"`
	MRI      string `json:"mri"`
	Presence struct {
		Availability string `json:"availability"`
		DeviceType   string `json:"deviceType"`
		CalendarData struct {
			OutOfOfficeNote struct {
				Message string `json:"message"`
			} `json:"outOfOfficeNote"`
		} `json:"calendarData"`
	} `json:"presence"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

type TenantAuthRequest struct {
	ClientID string `json:"client_id"`
}

type TenantAuthResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"accessToken"`
}

type TenantOpenIDConfig struct {
	Issuer string `json:"issuer"`
}

type TenantLookupInfo struct {
	TenantID          string `json:"tenantId"`
	DefaultDomainName string `json:"defaultDomainName"`
	DisplayName       string `json:"displayName"`
}

type Logger struct {
	verbose bool
}

func NewLogger(verbose bool) *Logger {
	return &Logger{verbose: verbose}
}

func (l *Logger) Info(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.verbose {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

type TeamsTokenAddon struct {
	proxy.BaseAddon
	tokenChan chan string
	logger    *Logger
}

func (addon *TeamsTokenAddon) Response(f *proxy.Flow) {
	addon.logger.Debug("[PROXY] Response: %s %s", f.Request.Method, f.Request.URL.String())
	requestPath := f.Request.URL.Path
	if f.Request.URL.RawQuery != "" {
		requestPath = requestPath + "?" + f.Request.URL.RawQuery
	}

	if strings.Contains(requestPath, "/oauth2/v2.0/token?client-request-id=") {
		addon.logger.Debug("[PROXY] Found OAuth2 pattern")
		addon.logger.Debug("[PROXY] Request %s", requestPath)

		if f.Response != nil && len(f.Response.Body) > 0 {
			bodyStr := string(f.Response.Body)
			addon.logger.Debug("[PROXY] Response body length: %d", len(bodyStr))

			if addon.logger.verbose && len(bodyStr) > 200 {
				addon.logger.Debug("[PROXY] Response preview: %s...", bodyStr[:200])
			} else if addon.logger.verbose {
				addon.logger.Debug("[PROXY] Full response: %s", bodyStr)
			}

			if strings.Contains(bodyStr, "skype") {
				addon.logger.Info("[PROXY] Found 'skype' in OAuth2 response")

				var tokenResp TokenResponse
				if err := json.Unmarshal(f.Response.Body, &tokenResp); err == nil && tokenResp.AccessToken != "" {
					addon.logger.Debug("[PROXY] Token extracted successfully")
					select {
					case addon.tokenChan <- tokenResp.AccessToken:
						addon.logger.Debug("[PROXY] Token sent to main thread")
					default:
						addon.logger.Debug("[PROXY] Token Channel full")
					}
				} else {
					addon.logger.Debug("[PROXY] Failed to parse JSON token: %v", err)
				}
			} else {
				addon.logger.Debug("[PROXY] No 'skype' found in OAuth2 response")
			}
		}
	}
}

func (addon *TeamsTokenAddon) Request(f *proxy.Flow) {
	if addon.logger.verbose && (strings.Contains(f.Request.URL.Host, "microsoft") || strings.Contains(f.Request.URL.Host, "teams")) {
		addon.logger.Debug("[PROXY] Request: %s %s %s", f.Request.Method, f.Request.URL.Host, f.Request.URL.Path)
	}
}

type driverWithService struct {
	selenium.WebDriver
	service *selenium.Service
}

func (d *driverWithService) Quit() error {
	err := d.WebDriver.Quit()
	d.service.Stop()
	return err
}

func parseFlags() *Config {
	config := &Config{}

	flag.BoolVar(&config.RunTeams, "teams", false, "Run the Teams User Enumeration Module")
	flag.BoolVar(&config.RunOneDrive, "onedrive", false, "Run the One Drive Enumeration Module")
	flag.BoolVar(&config.TeamsLegacy, "l", false, "Write legacy skype users to a separate file")
	flag.BoolVar(&config.TeamsStatus, "s", false, "Write Teams Status for users to a separate file")
	flag.StringVar(&config.InputFile, "i", "", "Input file with newline-separated users to check (required)")
	flag.StringVar(&config.OutputFile, "o", "", "Write output to file")
	flag.StringVar(&config.TargetDomain, "d", "", "Domain to target (required)")
	flag.StringVar(&config.TeamsToken, "t", "", "Teams Token, either file, string, or 'proxy' for interactive Firefox")
	flag.IntVar(&config.MaxThreads, "threads", 10, "Number of threads to use in the Teams User Enumeration")
	flag.BoolVar(&config.VerboseMode, "v", false, "Show verbose errors")
	flag.Parse()
	return config
}

func validateConfig(config *Config) error {
	if !config.RunTeams && !config.RunOneDrive {
		return fmt.Errorf("You must select at least one module to run, Teams or OneDrive")
	}

	if config.InputFile == "" {
		return fmt.Errorf("Input File (-i) is required")
	}

	if config.TargetDomain == "" {
		return fmt.Errorf("Target Domain (-d) is required")
	}

	if config.RunTeams && config.TeamsToken == "" {
		return fmt.Errorf("Teams Bearer Token (-t) is required for Teams Enumeration")
	}

	if config.TeamsLegacy && config.OutputFile == "" {
		return fmt.Errorf("Teams Legacy Output requires an output file (-o)")
	}

	if config.TeamsStatus && config.OutputFile == "" {
		return fmt.Errorf("Teams Status Output requires an output file (-o)")
	}

	return nil
}

func startMitmProxy(tokenChan chan string, logger *Logger) {
	opts := &proxy.Options{
		Addr:              fmt.Sprintf(":%d", MITMPROXY_PORT),
		StreamLargeBodies: 1024 * 1024,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		logger.Error("Failed to create mitmproxy: %v", err)
		return
	}

	addon := &TeamsTokenAddon{
		tokenChan: tokenChan,
		logger:    logger,
	}
	p.AddAddon(addon)

	logger.Info("TLS-intercepting proxy started on port %d", MITMPROXY_PORT)
	logger.Debug("Certificate Info: The proxy generates its own CA Certificate")
	logger.Debug("Firefox will be configured to accept insecure certificates")

	if err := p.Start(); err != nil {
		logger.Error("Proxy failed to start: %v", err)
	}
}

func findFirefox(logger *Logger) string {
	var paths []string

	switch runtime.GOOS {
	case "windows":
		paths = []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Mozilla Firefox", "firefox.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Mozilla Firefox", "firefox.exe"),
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Mozilla Firefox", "firefox.exe"),
		}
	case "darwin":
		paths = []string{
			"/Applications/Firefox.app/Contents/MacOS/firefox",
		}
	case "linux":
		paths = []string{
			"/usr/bin/firefox",
			"/usr/bin/firefox-esr",
			"/snap/bin/firefox",
			"/usr/local/bin/firefox",
		}
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			logger.Debug("Found Firefox at: %s", path)
			return path
		}
	}

	return ""
}

func setupGeckoDriver(logger *Logger) (string, error) {
	if path, err := exec.LookPath("geckodriver"); err == nil {
		logger.Debug("Using existing geckodriver: %s", path)
		return path, nil
	}

	tempDir := os.TempDir()
	var driverName string
	var downloadURL string

	switch runtime.GOOS {
	case "windows":
		driverName = "geckodriver.exe"
		downloadURL = "https://github.com/mozilla/geckodriver/releases/download/v0.34.0/geckodriver-v0.34.0-win64.zip"
	case "darwin":
		driverName = "geckodriver"
		downloadURL = "https://github.com/mozilla/geckodriver/releases/download/v0.34.0/geckodriver-v0.34.0-macos.tar.gz"
	case "linux":
		driverName = "geckodriver"
		downloadURL = "https://github.com/mozilla/geckodriver/releases/download/v0.34.0/geckodriver-v0.34.0-linux64.tar.gz"
	}

	driverPath := filepath.Join(tempDir, driverName)

	if _, err := os.Stat(driverPath); err == nil {
		logger.Debug("Using existing geckodriver: %s", driverPath)
		return driverPath, nil
	}

	logger.Info("Downloading geckodriver from GitHub...")
	return downloadAndExtractGeckoDriver(downloadURL, tempDir, driverName, logger)
}

func downloadAndExtractGeckoDriver(downloadURL, tempDir, driverName string, logger *Logger) (string, error) {
	driverPath := filepath.Join(tempDir, driverName)

	logger.Debug("Downloading geckodriver from: %s", downloadURL)
	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("Failed to download geckodriver: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Failed to download geckodriver: HTTP %d", resp.StatusCode)
	}

	tmpFile := filepath.Join(tempDir, "geckodriver_download")
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", fmt.Errorf("Failed to create temp file: %v", err)
	}
	defer out.Close()
	defer os.Remove(tmpFile)

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to save download: %v", err)
	}
	out.Close()

	logger.Debug("Download complete, extracting...")

	if strings.HasSuffix(downloadURL, ".zip") {
		err = extractZip(tmpFile, tempDir, driverName)
	} else if strings.HasSuffix(downloadURL, ".tar.gz") {
		err = extractTarGz(tmpFile, tempDir, driverName)
	} else {
		return "", fmt.Errorf("Unsupported archive format")
	}

	if err != nil {
		return "", fmt.Errorf("Failed to extract archive: %v", err)
	}

	if runtime.GOOS != "windows" {
		err = os.Chmod(driverPath, 0755)
		if err != nil {
			return "", fmt.Errorf("Failed to make geckodriver executable: %v", err)
		}
	}

	logger.Info("Geckodriver setup complete: %s", driverPath)
	return driverPath, nil
}

func extractZip(src, destDir, targetFile string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.Contains(f.Name, "geckodriver") {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			destPath := filepath.Join(destDir, targetFile)
			outFile, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer outFile.Close()

			_, err = io.Copy(outFile, rc)
			return err
		}
	}

	return fmt.Errorf("geckodriver not found in zip archive")
}

func extractTarGz(src, destDir, targetFile string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if strings.Contains(header.Name, "geckodriver") && header.Typeflag == tar.TypeReg {
			destPath := filepath.Join(destDir, targetFile)
			outFile, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer outFile.Close()

			_, err = io.Copy(outFile, tr)
			return err
		}
	}

	return fmt.Errorf("geckodriver not found in tar.gz archive")
}

func startFirefoxWithProxy(driverPath, firefoxPath string, logger *Logger) (selenium.WebDriver, error) {
	port := 9515
	opts := []selenium.ServiceOption{
		selenium.Output(io.Discard),
	}

	logger.Debug("Starting Geckodriver service on port %d", port)
	service, err := selenium.NewGeckoDriverService(driverPath, port, opts...)
	if err != nil {
		return nil, fmt.Errorf("Failed to start geckodriver service: %v", err)
	}

	time.Sleep(2 * time.Second)

	testURL := fmt.Sprintf("http://localhost:%d/status", port)
	resp, err := http.Get(testURL)
	if err != nil {
		service.Stop()
		return nil, fmt.Errorf("geckodriver service not responding: %v", err)
	}

	resp.Body.Close()
	logger.Debug("Geckodriver service is running")

	firefoxCaps := firefox.Capabilities{
		Binary: firefoxPath,
		Prefs: map[string]interface{}{
			"network.proxy.type":                              1,
			"network.proxy.http":                              "127.0.0.1",
			"network.proxy.http_port":                         MITMPROXY_PORT,
			"network.proxy.ssl":                               "127.0.0.1",
			"network.proxy.ssl_port":                          MITMPROXY_PORT,
			"network.proxy.share_proxy_settings":              true,
			"network.proxy.no_proxies_on":                     "",
			"security.enterprise_roots.enabled":               true,
			"network.cookie.cookieBehavior":                   0,
			"dom.security.https_only_mode":                    false,
			"privacy.trackingprotection.enabled":              false,
			"security.mixed_content.block_active_content":     false,
			"security.mixed_content.block_display_content":    false,
			"security.tls.accept_insecure_certs":              true,
			"security.cert_pinning.enforcement_level":         0,
			"security.tls.hello_downgrade_check":              false,
			"security.ssl.require_safe_negotiation":           false,
			"security.ssl.treat_unsafe_negotiation_as_broken": false,
			"security.ssl.disable_session_identifiers":        true,
			"dom.security.https_first":                        false,
		},
		Args: []string{
			"--new-instance",
			"--no-remote",
		},
	}

	caps := selenium.Capabilities{
		"moz:firefoxOptions":  firefoxCaps,
		"acceptInsecureCerts": true,
	}

	var driver selenium.WebDriver
	for i := 0; i < 3; i++ {
		logger.Debug("Attempting to create WebDriver session (attempt %d/3)", i+1)
		driver, err = selenium.NewRemote(caps, fmt.Sprintf("http://localhost:%d", port))
		if err == nil {
			break
		}
		logger.Debug("Failed to create session: %v, retrying...", err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		service.Stop()
		return nil, fmt.Errorf("Failed to create WebDriver session after retries: %v", err)
	}

	logger.Info("Firefox started with MitM Proxy 127.0.0.1:%d", MITMPROXY_PORT)

	return &driverWithService{
		WebDriver: driver,
		service:   service,
	}, nil
}

func writeTokenToFile(token string) error {
	tokenWithBearer := fmt.Sprintf("Bearer %s", token)
	return os.WriteFile(TOKEN_FILE, []byte(tokenWithBearer), 0644)
}

func getTokenViaProxy(logger *Logger) (string, error) {
	logger.Info("Starting interactive Teams Token Capture")
	logger.Info("This will open a firefox window that is being proxied to capture the correct token")

	tokenChan := make(chan string, 1)

	logger.Info("Starting MitM Proxy on port %d", MITMPROXY_PORT)
	logger.Info("Note: Proxy debug messages may appear below - these can be safely ignored")

	originalOutput := log.Writer()
	originalStderr := os.Stderr
	originalStdout := os.Stdout

	log.SetOutput(io.Discard)
	log.SetFlags(0)
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stderr = devNull
	os.Stdout = devNull

	go startMitmProxy(tokenChan, logger)

	time.Sleep(3 * time.Second)

	logger.Debug("Looking for Firefox...")
	firefoxPath := findFirefox(logger)
	if firefoxPath == "" {
		return "", fmt.Errorf("Firefox not found. Please install firefox")
	}
	logger.Debug("Found Firefox at %s", firefoxPath)

	logger.Debug("Setting up geckodriver...")
	driverPath, err := setupGeckoDriver(logger)
	if err != nil {
		return "", fmt.Errorf("Failed to setup geckodriver: %v", err)
	}

	logger.Info("Starting Firefox with Selenium and MitM proxy...")
	driver, err := startFirefoxWithProxy(driverPath, firefoxPath, logger)
	if err != nil {
		return "", fmt.Errorf("Failed to start firefox with Selenium: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	cleanup := func() {
		logger.Debug("Cleaning up Firefox and Proxy")
		driver.Quit()
		logger.Debug("Cleanup Complete")
		log.SetOutput(originalOutput)
		os.Stderr = originalStderr
		os.Stdout = originalStdout
		devNull.Close()
	}

	go func() {
		<-sigChan
		logger.Info("Received interrupt signal, cleaning up...")
		cleanup()
		os.Exit(0)
	}()

	logger.Info("Navigating to Teams...")
	err = driver.Get("https://teams.microsoft.com")
	if err != nil {
		logger.Debug("HTTPS navigation failed: %v", err)
		logger.Info("Trying HTTP test first")

		err = driver.Get("http://httpbin.org/ip")
		if err != nil {
			cleanup()
			return "", fmt.Errorf("Even HTTP navigation failed: %v", err)
		}

		logger.Debug("HTTP Worked, trying Teams again")
		err = driver.Get("https://teams.microsoft.com")
		if err != nil {
			cleanup()
			return "", fmt.Errorf("Teams HTTPS still failed after HTTP test: %v", err)
		}
	}

	logger.Info("Waiting for authentication token...")
	logger.Info("Please log in to Teams in the Firefox browser...")
	logger.Info("The token will be captured automatically when authenticating...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	browserClosed := make(chan bool, 1)
	go func() {
		for {
			time.Sleep(2 * time.Second)
			_, err := driver.CurrentWindowHandle()
			if err != nil {
				logger.Debug("Browser appears to be closed: %v", err)
				select {
				case browserClosed <- true:
				default:
				}
				return
			}
		}
	}()

	select {
	case token := <-tokenChan:
		logger.Info("Token captured successfully!")

		err := writeTokenToFile(token)
		if err != nil {
			logger.Error("Error writing token to file: %v", err)
		} else {
			logger.Info("Token written to %s", TOKEN_FILE)
		}

		cleanup()
		return token, nil

	case <-browserClosed:
		logger.Info("Browser was closed by user")
		cleanup()
		return "", fmt.Errorf("browser was closed before token could be captured")

	case <-ctx.Done():
		logger.Error("Timeout reached waiting for token")
		cleanup()
		return "", fmt.Errorf("timeout waiting for auth token")
	}
}

func generateClientIDForTenantLookup() string {
	bucket := strconv.FormatInt(time.Now().Unix()/15, 10)
	hash := sha256.Sum256([]byte(bucket))
	return fmt.Sprintf("%x", hash)
}

func getTokenFromTenantLookup() (string, error) {
	clientID := generateClientIDForTenantLookup()
	authReq := TenantAuthRequest{ClientID: clientID}

	jsonData, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth request: %w", err)
	}

	resp, err := http.Post(TENANT_LOOKUP_AUTH_URL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var authResp TenantAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	token := authResp.Token
	if token == "" {
		token = authResp.AccessToken
	}

	if token == "" {
		return "", fmt.Errorf("could not retrieve bearer token from authenticate response")
	}

	return token, nil
}

func getTenantInfoFromAPI(domain, token string) (*TenantLookupInfo, error) {
	openIDURL := fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", domain)
	resp, err := http.Get(openIDURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get openid configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get openid configuration, status: %d", resp.StatusCode)
	}

	var config TenantOpenIDConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode openid configuration: %w", err)
	}

	parts := strings.Split(config.Issuer, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("could not extract tenant ID from openid configuration")
	}
	tenantID := parts[len(parts)-2]

	if tenantID == "" {
		return nil, fmt.Errorf("could not extract tenant ID from openid configuration")
	}

	tenantURL := fmt.Sprintf("%s/%s", TENANT_LOOKUP_API_URL, tenantID)
	req, err := http.NewRequest("GET", tenantURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get tenant info, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var tenantInfo TenantLookupInfo
	if err := json.NewDecoder(resp.Body).Decode(&tenantInfo); err != nil {
		return nil, fmt.Errorf("failed to decode tenant info: %w", err)
	}

	return &tenantInfo, nil
}

func readInputFile(filename string, logger *Logger) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to open input file: %v", err)
	}
	defer file.Close()

	var names []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if strings.Contains(line, "@") {
				line = strings.Split(line, "@")[0]
			}
			names = append(names, strings.ToLower(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Error reading input file: %v", err)
	}

	uniqueNames := make(map[string]bool)
	var result []string
	for _, name := range names {
		if !uniqueNames[name] {
			uniqueNames[name] = true
			result = append(result, name)
		}
	}

	logger.Debug("Read %d unique usernames from the input file", len(result))
	return result, nil
}

func getTenantName(targetDomain string, logger *Logger) (string, error) {
	logger.Debug("Tenant Discovery Method 1: DefaultDomainName via tenantidlookup.com...")

	token, err := getTokenFromTenantLookup()
	if err == nil {
		tenantInfo, err := getTenantInfoFromAPI(targetDomain, token)
		if err == nil && tenantInfo.DefaultDomainName != "" {
			defaultDomainName := tenantInfo.DefaultDomainName
			if strings.HasSuffix(defaultDomainName, ".onmicrosoft.com") {
				tenant := strings.TrimSuffix(defaultDomainName, ".onmicrosoft.com")
				logger.Debug("SUCCESS: Found tenant name via DefaultDomainName: %s", tenant)
				return tenant, nil
			}
		}
		logger.Debug("DefaultDomainName method failed: %v", err)
	} else {
		logger.Debug("Token retrieval failed: %v", err)
	}

	logger.Debug("Tenant Discovery Method 2 (Backup): Sharepoint Discovery...")

	domainPart := strings.Split(targetDomain, ".")[0]
	sharepointURL := fmt.Sprintf("https://%s-my.sharepoint.com", domainPart)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(sharepointURL)
	if err == nil && resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		logger.Debug("Sharepoint redirect: %s", location)

		re := regexp.MustCompile(`https://([^-]+)-my\.sharepoint\.com`)
		matches := re.FindStringSubmatch(location)
		if len(matches) > 1 {
			tenant := matches[1]
			logger.Debug("SUCCESS: Found tenant name via SharePoint: %s", tenant)
			return tenant, nil
		}
	}

	logger.Debug("Tenant Discovery Method 3 (Backup): Pattern Proving...")

	domainBase := strings.Split(targetDomain, ".")[0]
	patterns := []string{
		domainBase,
		strings.ReplaceAll(domainBase, "-", ""),
		strings.ReplaceAll(strings.ReplaceAll(targetDomain, ".com", ""), ".", ""),
		strings.ReplaceAll(targetDomain, ".", ""),
		domainBase + "region",
		"regionof" + domainBase,
		domainBase + "gov",
		domainBase + "-region",
		domainBase + "city",
		domainBase + "county",
	}

	for i, pattern := range patterns {
		logger.Debug("Testing Pattern %d: %s", i+1, pattern)
		testURL := fmt.Sprintf("https://%s-my.sharepoint.com", pattern)

		resp, err := client.Get(testURL)
		if err == nil && resp != nil && (resp.StatusCode == 302 || resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403) {
			logger.Debug("SUCCESS: Found working tenant pattern: %s (HTTP %d)", pattern, resp.StatusCode)
			return pattern, nil
		}
		if err != nil {
			logger.Debug("FAIL: Pattern %s returned error: %v", pattern, err)
		} else if resp != nil {
			logger.Debug("FAIL: Pattern %s returned with HTTP %d", pattern, resp.StatusCode)
		} else {
			logger.Debug("FAIL: Pattern %s returned nil response", pattern)
		}
	}

	fallback := strings.Split(targetDomain, ".")[0]
	logger.Debug("FALLBACK: Using domain-based tenant name: %s", fallback)
	return fallback, nil
}

func oneDriveEnumeratorWithCounter(targetTenant, username, targetDomain string, results *Results, logger *Logger, count, total int) {
	usernamePart := strings.ReplaceAll(username, ".", "_")
	domainPart := strings.ReplaceAll(targetDomain, ".", "_")
	testURL := fmt.Sprintf("https://%s-my.sharepoint.com/personal/%s_%s/_layouts/15/onedrive.aspx", targetTenant, usernamePart, domainPart)

	logger.Debug("Testing: %s", testURL)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(testURL)
	if err != nil {
		logger.Debug("Error accessing %s: %v", testURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 302 {
		logger.Info("[%3d/%d] [+] %s@%s", count, total, username, targetDomain)

		results.mu.Lock()
		results.ValidNames = append(results.ValidNames, username)
		results.mu.Unlock()
	} else {
		logger.Debug("[%3d/%d] [-] %s@%s (HTTP %d)", count, total, username, targetDomain, resp.StatusCode)
	}
}

func getPresence(mri, bearerToken string, logger *Logger) (string, string, string) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	requestData := []map[string]string{{"mri": mri}}
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		logger.Debug("Error marshaling presence request: %v", err)
		return "", "", ""
	}

	req, err := http.NewRequest("POST", URL_PRESENCE_TEAMS, strings.NewReader(string(jsonData)))
	if err != nil {
		logger.Debug("Error creating presence request: %v", err)
		return "", "", ""
	}

	req.Header.Set("x-ms-client-version", CLIENT_VERSION)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("Error on presence response: %v", err)
		return "", "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Debug("Error reading presence response body: %v", err)
		return "", "", ""
	}

	var presenceResp []struct {
		Presence struct {
			Availability string `json:"availability"`
			DeviceType   string `json:"deviceType"`
			CalendarData struct {
				OutOfOfficeNote struct {
					Message string `json:"message"`
				} `json:"outOfOfficeNote"`
			} `json:"calendarData"`
		} `json:"presence"`
	}

	if err := json.Unmarshal(body, &presenceResp); err != nil {
		logger.Debug("Error parsing presence JSON: %v", err)
		return "", "", ""
	}

	if len(presenceResp) == 0 {
		return "", "", ""
	}

	presence := presenceResp[0].Presence
	return presence.Availability, presence.DeviceType, presence.CalendarData.OutOfOfficeNote.Message
}

func teamsEnumeratorWithCounter(bearerToken, username, targetDomain string, config *Config, results *Results, logger *Logger, count, total int) {
	potentialUser := fmt.Sprintf("%s@%s", username, targetDomain)
	logger.Debug("Testing User %s", potentialUser)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	apiURL := fmt.Sprintf("%s%s/externalsearchv3?includeTFLUsers=true", URL_TEAMS, potentialUser)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		logger.Debug("Error creating Teams Request: %v", err)
		return
	}

	req.Header.Set("Host", "teams.microsoft.com")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Ms-Client-Version", CLIENT_VERSION)

	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("Error on Teams Response: %v", err)
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 403:
		logger.Info("[%3d/%d] [+] %s", count, total, potentialUser)
		results.mu.Lock()
		results.ValidNames = append(results.ValidNames, username)
		results.mu.Unlock()
	case 404:
		logger.Debug("[%3d/%d] [-] %s ", count, total, potentialUser)
	case 200:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Debug("Error reading Teams response body for %s: %v", potentialUser, err)
			return
		}

		var teamsResp []map[string]interface{}
		if err := json.Unmarshal(body, &teamsResp); err != nil {
			logger.Debug("Error parsing Teams JSON for %s: %v", potentialUser, err)
			return
		}

		if len(teamsResp) > 0 {
			userInfo := teamsResp[0]

			if _, hasSkypeID := userInfo["skypeId"]; hasSkypeID {
				logger.Info("[%3d/%d] [+] %s -- Legacy Skype Detected", count, total, potentialUser)
				results.mu.Lock()
				results.ValidNames = append(results.ValidNames, username)
				results.LegacyNames = append(results.LegacyNames, username)
				results.mu.Unlock()

				if config.VerboseMode {
					jsonOutput, _ := json.MarshalIndent(userInfo, "", "  ")
					logger.Debug(string(jsonOutput))
				}
			} else {
				if !config.TeamsStatus {
					logger.Info("[%3d/%d] [+] %s", count, total, potentialUser)
					results.mu.Lock()
					results.ValidNames = append(results.ValidNames, username)
					results.mu.Unlock()

					if config.VerboseMode {
						jsonOutput, _ := json.MarshalIndent(userInfo, "", "  ")
						logger.Debug(string(jsonOutput))
					}
				}
			}

			if config.TeamsStatus {
				if mri, exists := userInfo["mri"].(string); exists {
					availability, deviceType, outOfOfficeNote := getPresence(mri, bearerToken, logger)
					statusEntry := fmt.Sprintf("%s -- %s -- %s", potentialUser, availability, deviceType)
					if outOfOfficeNote != "" {
						cleanedNote := strings.ReplaceAll(outOfOfficeNote, "\n", "--")
						cleanedNote = strings.ReplaceAll(cleanedNote, "\r", "--")
						logger.Info("[%3d/%d] [+] %s -- %s -- %s -- %s", count, total, potentialUser, availability, deviceType, cleanedNote)
						statusEntry += " -- " + cleanedNote
					} else {
						logger.Info("[%3d/%d] [+] %s -- %s -- %s", count, total, potentialUser, availability, deviceType)
					}

					results.mu.Lock()
					results.ValidNames = append(results.ValidNames, username)
					results.StatusNames = append(results.StatusNames, statusEntry)
					results.mu.Unlock()
				}
			}
		} else {
			logger.Debug("[%3d/%d] [-] %s", count, total, potentialUser)
		}
	case 401:
		logger.Error("Error with Teams Auth Token... Please check your token or proxy settings")
		os.Exit(1)
	default:
		logger.Debug("Unexpected status code %d for %s", resp.StatusCode, potentialUser)
	}
}

func readTokenFromFile(filename string) (string, error) {
	tokenBytes, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(tokenBytes))

	token = strings.ReplaceAll(token, "Bearer%3D", "")
	token = strings.ReplaceAll(token, "%26Origin%3Dhttps%3A%2F%2Fteams.microsoft.com", "")
	token = strings.ReplaceAll(token, "%26origin%3Dhttps%3A%2F%2Fteams.microsoft.com", "")
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)
	return token, nil
}

func getTeamsToken(config *Config, logger *Logger) (string, error) {
	if config.TeamsToken == "" {
		return "", fmt.Errorf("No Teams Token provided")
	}

	if config.TeamsToken == "proxy" {
		return getTokenViaProxy(logger)
	}

	if len(config.TeamsToken) < 150 {
		if _, err := os.Stat(config.TeamsToken); err == nil {
			logger.Debug("Reading token from file: %s", config.TeamsToken)
			return readTokenFromFile(config.TeamsToken)
		}
	}

	logger.Debug("Using provided token string")
	token := config.TeamsToken

	token = strings.ReplaceAll(token, "Bearer%3D", "")
	token = strings.ReplaceAll(token, "%26Origin%3Dhttps%3A%2F%2Fteams.microsoft.com", "")
	token = strings.ReplaceAll(token, "%26origin%3Dhttps%3A%2F%2Fteams.microsoft.com", "")
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)

	return token, nil
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func writeResults(config *Config, results *Results, logger *Logger) error {
	if len(results.ValidNames) == 0 {
		logger.Info("No valid users found")
		return nil
	}

	if config.OutputFile != "" {
		if _, err := os.Stat(config.OutputFile); err == nil {
			fmt.Print(" [!] Output file exists, overwrite? (Y/n) ")
			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))

			if response != "" && response != "y" && response != "yes" {
				logger.Info("Not overwriting output file")
				return nil
			}
		}

		uniqueNames := removeDuplicates(results.ValidNames)
		file, err := os.Create(config.OutputFile)
		if err != nil {
			return fmt.Errorf("Failed to create output file: %v", err)
		}
		defer file.Close()

		for _, name := range uniqueNames {
			fmt.Fprintf(file, "%s@%s\n", name, config.TargetDomain)
		}

		logger.Info("Wrote %d valid users to %s", len(uniqueNames), config.OutputFile)
	}

	if config.TeamsLegacy && len(results.LegacyNames) > 0 {
		legacyFile := "Legacy_" + config.OutputFile

		if _, err := os.Stat(legacyFile); err == nil {
			fmt.Print(" [!] Legacy output file exists, overwrite? (Y/n) ")
			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))

			if response != "" && response != "y" && response != "yes" {
				logger.Info("Not overwriting legacy skype users file")
			} else {
				uniqueLegacy := removeDuplicates(results.LegacyNames)
				file, err := os.Create(legacyFile)
				if err != nil {
					return fmt.Errorf("Failed to create legacy output file: %v", err)
				}
				defer file.Close()

				for _, name := range uniqueLegacy {
					fmt.Fprintf(file, "%s@%s\n", name, config.TargetDomain)
				}

				logger.Info("Wrote %d legacy skype users to %s", len(uniqueLegacy), legacyFile)
			}
		} else {
			uniqueLegacy := removeDuplicates(results.LegacyNames)
			file, err := os.Create(legacyFile)
			if err != nil {
				return fmt.Errorf("Failed to create legacy output file: %v", err)
			}
			defer file.Close()

			for _, name := range uniqueLegacy {
				fmt.Fprintf(file, "%s@%s\n", name, config.TargetDomain)
			}

			logger.Info("Wrote %d legacy skype users to %s", len(uniqueLegacy), legacyFile)
		}
	}

	if config.TeamsStatus && len(results.StatusNames) > 0 {
		statusFile := "Status_" + config.OutputFile

		if _, err := os.Stat(statusFile); err == nil {
			fmt.Print(" [!] Status output file exists, overwrite? (Y/n) ")
			var response string
			fmt.Scanln(&response)
			response = strings.ToLower(strings.TrimSpace(response))

			if response != "" && response != "y" && response != "yes" {
				logger.Info("Not overwriting Teams status file")
			} else {
				file, err := os.Create(statusFile)
				if err != nil {
					return fmt.Errorf("Failed to create status output file: %v", err)
				}
				defer file.Close()

				fmt.Fprintln(file, "Username -- Availability -- Device Type -- Out of Office Note")

				uniqueStatus := removeDuplicates(results.StatusNames)
				for _, status := range uniqueStatus {
					fmt.Fprintln(file, status)
				}

				logger.Info("Wrote %d users with status information to %s", len(uniqueStatus), statusFile)
			}
		} else {
			file, err := os.Create(statusFile)
			if err != nil {
				return fmt.Errorf("Failed to create status output file: %v", err)
			}
			defer file.Close()

			fmt.Fprintln(file, "Username -- Availability -- Device Type -- Out of Office Note")

			uniqueStatus := removeDuplicates(results.StatusNames)
			for _, status := range uniqueStatus {
				fmt.Fprintln(file, status)
			}

			logger.Info("Wrote %d users with status information to %s", len(uniqueStatus), statusFile)
		}
	} else if config.TeamsLegacy && len(results.LegacyNames) == 0 {
		logger.Info("No legacy skype users found")
	}

	return nil
}

func runOneDriveEnumeration(config *Config, usernames []string, results *Results, logger *Logger) error {
	logger.Info("Running OneDrive Enumeration...")

	logger.Debug("Discovering tenant for target domain")
	targetTenant, err := getTenantName(config.TargetDomain, logger)
	if err != nil || targetTenant == "" {
		return fmt.Errorf("Error retrieving tenant for target: %v", err)
	}

	logger.Debug("Using target tenant %s", targetTenant)
	logger.Debug("Running OneDrive Enumeration using %d threads", config.MaxThreads)

	semaphore := make(chan struct{}, config.MaxThreads)
	var wg sync.WaitGroup

	total := len(usernames)
	completed := 0
	var completedMutex sync.Mutex

	for _, username := range usernames {
		wg.Add(1)
		go func(user string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			completedMutex.Lock()
			completed++
			currentCount := completed
			completedMutex.Unlock()

			oneDriveEnumeratorWithCounter(targetTenant, user, config.TargetDomain, results, logger, currentCount, total)
		}(username)
	}

	wg.Wait()
	logger.Info("OneDrive enumeration completed")
	return nil
}

func runTeamsEnumeration(config *Config, usernames []string, results *Results, logger *Logger) error {
	logger.Info("Running Teams User Enumeration...")

	token, err := getTeamsToken(config, logger)
	if err != nil {
		return fmt.Errorf("Failed to get Teams Token: %v", err)
	}

	logger.Debug("Running Teams User Enumeration using %d threads", config.MaxThreads)

	if config.TeamsStatus {
		logger.Info("Username -- Availability -- Device Type -- Out of Office Note")
		fmt.Println()
	}

	semaphore := make(chan struct{}, config.MaxThreads)
	var wg sync.WaitGroup

	total := len(usernames)
	completed := 0
	var completedMutex sync.Mutex

	for _, username := range usernames {
		wg.Add(1)
		go func(user string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			completedMutex.Lock()
			completed++
			currentCount := completed
			completedMutex.Unlock()

			teamsEnumeratorWithCounter(token, user, config.TargetDomain, config, results, logger, currentCount, total)
		}(username)
	}

	wg.Wait()
	logger.Info("Teams Enumeration Completed")
	return nil
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\n[!] Received interrupt signal, cleaning up...")
		os.Exit(0)
	}()
}

func main() {
	fmt.Println(BANNER)
	fmt.Println()
	setupSignalHandler()
	config := parseFlags()
	logger := NewLogger(config.VerboseMode)

	if err := validateConfig(config); err != nil {
		logger.Error(err.Error())
		flag.Usage()
		os.Exit(1)
	}

	usernames, err := readInputFile(config.InputFile, logger)
	if err != nil {
		logger.Error("Failed to read input file: %v", err)
		os.Exit(1)
	}

	logger.Info("Loaded %d usernames for enumeration", len(usernames))

	results := &Results{
		ValidNames:  make([]string, 0),
		LegacyNames: make([]string, 0),
		StatusNames: make([]string, 0),
	}

	if config.RunTeams && len(usernames) > 0 {
		if err := runTeamsEnumeration(config, usernames, results, logger); err != nil {
			logger.Error("Teams Enumeration Failed: %v", err)
			os.Exit(1)
		}

		if config.RunOneDrive {
			validNamesMap := make(map[string]bool)
			for _, name := range results.ValidNames {
				validNamesMap[name] = true
			}

			var filteredUsernames []string
			for _, username := range usernames {
				if !validNamesMap[username] {
					filteredUsernames = append(filteredUsernames, username)
				}
			}
			usernames = filteredUsernames
			logger.Info("Filtered to %d usernames for OneDrive Enumeration (Excluding Teams Valid Users)", len(usernames))
		}

	}

	if config.RunOneDrive {
		if err := runOneDriveEnumeration(config, usernames, results, logger); err != nil {
			logger.Error("OneDrive Enumeration Failed: %v", err)
			os.Exit(1)
		}
	}

	if err := writeResults(config, results, logger); err != nil {
		logger.Error("Failed to write results: %v", err)
		os.Exit(1)
	}

	logger.Info("Enumeration completed successfully!")
	logger.Info("Total valid users found: %d", len(removeDuplicates(results.ValidNames)))
	if len(results.LegacyNames) > 0 {
		logger.Info("Legacy Skype users found: %d", len(removeDuplicates(results.LegacyNames)))
	}
	if len(results.StatusNames) > 0 {
		logger.Info("Users with status information: %d", len(removeDuplicates(results.StatusNames)))
	}

	if config.TeamsToken == "proxy" {
		if _, err := os.Stat(TOKEN_FILE); err == nil {
			logger.Info("Token saved to %s for future use", TOKEN_FILE)
		}
	}
}
