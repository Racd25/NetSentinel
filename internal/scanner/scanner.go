package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OpenPort ahora incluye el banner real capturado.
type OpenPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

// HostResult agrupa el resultado completo de un host.
type HostResult struct {
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname,omitempty"`
	OpenPorts []OpenPort `json:"open_ports"`
}

var commonServices = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
	1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}

func ServiceName(port int) string {
	if svc, ok := commonServices[port]; ok {
		return svc
	}
	return "unknown"
}

// ScanHost usa un canal de resultados en lugar de mutex.
// ctx permite cancelación y timeouts jerárquicos.
func ScanHost(ctx context.Context, ip string, ports []int, timeout time.Duration, workers int) []OpenPort {
	// Canal de resultados con buffer (no bloqueante)
	results := make(chan OpenPort, len(ports))
	var wg sync.WaitGroup

	// Canal de trabajos
	jobs := make(chan int, len(ports))

	// Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-ctx.Done():
					return // cancelado
				default:
					if openPort := scanPort(ctx, ip, port, timeout); openPort != nil {
						results <- *openPort
					}
				}
			}
		}()
	}

	// Enviar trabajos
	for _, p := range ports {
		select {
		case <-ctx.Done():
			break
		case jobs <- p:
		}
	}
	close(jobs)

	// Esperar a que terminen y cerrar results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Recolectar resultados del canal
	var open []OpenPort
	for port := range results {
		open = append(open, port)
	}

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

// scanPort escanea un puerto y captura el banner si está abierto.
func scanPort(ctx context.Context, ip string, port int, timeout time.Duration) *OpenPort {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	// Usar DialContext para respetar el context
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil // puerto cerrado o timeout
	}
	defer conn.Close()

	// Capturar banner
	banner := readBanner(conn, port, timeout)
	service := identifyServiceFromBanner(banner, port)

	return &OpenPort{
		Port:    port,
		Service: service,
		Banner:  banner,
	}
}

// readBanner lee los primeros bytes que el servicio envía.
func readBanner(conn net.Conn, port int, timeout time.Duration) string {
	// Para HTTP/HTTPS, debemos enviar una request primero
	if port == 80 || port == 8080 || port == 8000 {
		// HTTP: enviar request GET
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr().String())
	} else if port == 443 || port == 8443 {
		// HTTPS: no podemos leer banner sin TLS handshake, saltamos
		return ""
	}

	// Leer con timeout
	conn.SetReadDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)

	var banner strings.Builder
	for i := 0; i < 512; i++ { // máximo 512 bytes
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		banner.WriteByte(b)
		// Si encontramos fin de línea doble, paramos (típico en HTTP/SMTP)
		if banner.Len() > 2 && strings.HasSuffix(banner.String(), "\r\n\r\n") {
			break
		}
	}

	result := banner.String()
	// Limpiar caracteres de control y saltos de línea
	result = strings.TrimSpace(result)
	result = strings.ReplaceAll(result, "\r\n", " ")
	result = strings.ReplaceAll(result, "\n", " ")

	// Limitar longitud para legibilidad
	if len(result) > 100 {
		result = result[:100] + "..."
	}

	return result
}

// identifyServiceFromBanner intenta identificar el servicio por el banner.
func identifyServiceFromBanner(banner string, port int) string {
	bannerLower := strings.ToLower(banner)

	// SSH
	if strings.HasPrefix(banner, "SSH-") {
		return "SSH"
	}
	// FTP
	if strings.HasPrefix(banner, "220") && (strings.Contains(bannerLower, "ftp") || strings.Contains(bannerLower, "filezilla")) {
		return "FTP"
	}
	// HTTP
	if strings.Contains(bannerLower, "http/") || strings.Contains(bannerLower, "server:") {
		return "HTTP"
	}
	// SMTP
	if strings.HasPrefix(banner, "220") && strings.Contains(bannerLower, "smtp") {
		return "SMTP"
	}
	// MySQL (binario, pero contiene versión)
	if strings.Contains(bannerLower, "mysql") {
		return "MySQL"
	}
	// PostgreSQL
	if strings.Contains(bannerLower, "postgresql") {
		return "PostgreSQL"
	}

	// Fallback al mapeo por puerto
	return ServiceName(port)
}

// ParsePorts convierte "80,443,3389" o "1-1024" en una lista de puertos.
func ParsePorts(input string) ([]int, error) {
	var ports []int
	seen := map[int]bool{}

	add := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("puerto inválido: %d", p)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
		return nil
	}

	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(bounds[0])
			end, err2 := strconv.Atoi(bounds[1])
			if err != nil || err2 != nil || start > end {
				return nil, fmt.Errorf("rango inválido: %s", part)
			}
			for p := start; p <= end; p++ {
				if err := add(p); err != nil {
					return nil, err
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("puerto inválido: %s", part)
			}
			if err := add(p); err != nil {
				return nil, err
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no hay puertos válidos en %q", input)
	}
	return ports, nil
}
