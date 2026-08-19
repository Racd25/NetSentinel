package enrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Vulnerability representa un CVE asociado a un servicio detectado.
type Vulnerability struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
}

// knownProduct relaciona nombre interno con su CPE oficial de NVD (vendor:product).
type knownProduct struct {
	Vendor  string
	Product string
}

var knownProducts = map[string]knownProduct{
	"openssh": {Vendor: "openbsd", Product: "openssh"},
	"nginx":   {Vendor: "nginx", Product: "nginx"},
	"apache":  {Vendor: "apache", Product: "http_server"},
	"vsftpd":  {Vendor: "vsftpd", Product: "vsftpd"},
	"proftpd": {Vendor: "proftpd", Product: "proftpd"},
	"dnsmasq": {Vendor: "thekelleys", Product: "dnsmasq"},
}

// bannerPatterns extrae producto+versión de banners comunes con regex.
var bannerPatterns = []struct {
	re      *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`(?i)OpenSSH[_ ](\d+(?:\.\d+)+(?:p\d+)?)`), "openssh"},
	{regexp.MustCompile(`(?i)nginx/(\d+(?:\.\d+)+)`), "nginx"},
	{regexp.MustCompile(`(?i)Apache/(\d+(?:\.\d+)+)`), "apache"},
	{regexp.MustCompile(`(?i)vsftpd[ ]?(\d+(?:\.\d+)+)`), "vsftpd"},
	{regexp.MustCompile(`(?i)ProFTPD[ ]?(\d+(?:\.\d+)+)`), "proftpd"},
	{regexp.MustCompile(`(?i)dnsmasq-(\d+(?:\.\d+)+)`), "dnsmasq"},
}

// ParseBanner extrae (producto, versión) de un banner.
// Devuelve strings vacíos si no lo reconoce.
func ParseBanner(banner string) (string, string) {
	for _, p := range bannerPatterns {
		if m := p.re.FindStringSubmatch(banner); m != nil {
			return p.product, m[1]
		}
	}
	return "", ""
}

// Client consulta la API de NVD con caché en disco y rate limiting.
type Client struct {
	apiKey     string
	cacheFile  string
	cache      map[string][]Vulnerability
	mu         sync.Mutex
	lastCall   time.Time
	httpClient *http.Client
}

// NewClient crea el cliente y carga la caché si existe.
func NewClient(apiKey, cacheFile string) *Client {
	c := &Client{
		apiKey:     apiKey,
		cacheFile:  cacheFile,
		cache:      map[string][]Vulnerability{},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	c.loadCache()
	return c
}

// Lookup devuelve los CVEs de un producto+versión (caché primero, NVD después).
func (c *Client) Lookup(product, version string) []Vulnerability {
	key := product + "@" + version

	c.mu.Lock()
	if vulns, ok := c.cache[key]; ok { // caché hit → no toca la red
		c.mu.Unlock()
		return vulns
	}
	c.waitRateLimit() // respeta los límites de la API
	c.mu.Unlock()

	vulns := c.queryNVD(product, version)

	c.mu.Lock()
	c.cache[key] = vulns // guarda aunque esté vacío (caché negativa)
	c.mu.Unlock()
	c.saveCache()

	return vulns
}

// waitRateLimit impone la pausa obligatoria entre llamadas a NVD.
// Sin API key: ~5 requests/30s → pausa de 6.5s. Con key: 50/30s → 0.7s.
func (c *Client) waitRateLimit() {
	gap := 6500 * time.Millisecond
	if c.apiKey != "" {
		gap = 700 * time.Millisecond
	}
	if elapsed := time.Since(c.lastCall); elapsed < gap {
		time.Sleep(gap - elapsed)
	}
	c.lastCall = time.Now()
}

// queryNVD consulta la API oficial por CPE exacto (vendor:product:version).
func (c *Client) queryNVD(product, version string) []Vulnerability {
	kp, ok := knownProducts[product]
	if !ok {
		return nil
	}

	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", kp.Vendor, kp.Product, version)
	params := url.Values{}
	params.Set("cpeName", cpe)

	req, err := http.NewRequest(http.MethodGet,
		"https://services.nvd.nist.gov/rest/json/cves/2.0?"+params.Encode(), nil)
	if err != nil {
		return nil
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var data nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	var out []Vulnerability
	for _, v := range data.Vulnerabilities {
		vuln := Vulnerability{ID: v.CVE.ID, Severity: "UNKNOWN"}
		if len(v.CVE.Metrics.CvssV31) > 0 {
			vuln.Score = v.CVE.Metrics.CvssV31[0].CvssData.BaseScore
			vuln.Severity = strings.ToUpper(v.CVE.Metrics.CvssV31[0].CvssData.BaseSeverity)
		}
		out = append(out, vuln)
	}

	// Ordena por severidad (score) descendente
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func (c *Client) loadCache() {
	data, err := os.ReadFile(c.cacheFile)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &c.cache)
}

func (c *Client) saveCache() {
	data, err := json.MarshalIndent(c.cache, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(c.cacheFile, data, 0644)
}

// ----- Structs que espejan el JSON de la API de NVD -----

type nvdResponse struct {
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID      string     `json:"id"`
	Metrics nvdMetrics `json:"metrics"`
}

type nvdMetrics struct {
	CvssV31 []nvdCvss `json:"cvssMetricV31"`
}

type nvdCvss struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}
