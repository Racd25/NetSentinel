package scanner

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OpenPort representa un puerto abierto detectado en un host.
type OpenPort struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// commonServices relaciona puertos con su servicio habitual.
var commonServices = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
	1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}

// ServiceName devuelve el servicio asociado a un puerto.
func ServiceName(port int) string {
	if svc, ok := commonServices[port]; ok {
		return svc
	}
	return "unknown"
}

// ScanHost escanea puertos de un host usando un "worker pool" de goroutines.
// Conceptos: goroutine (hilo ligero), channel (tubería de datos),
// WaitGroup (esperar a que terminen), Mutex (candado de escritura).
func ScanHost(ip string, ports []int, timeout time.Duration, workers int) []OpenPort {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		jobs = make(chan int, len(ports)) // canal por donde viajan los puertos a probar
		open []OpenPort
	)

	// Lanza los trabajadores concurrentes.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() { // ← esto crea una goroutine
			defer wg.Done()
			for port := range jobs { // cada worker toma puertos del canal
				addr := net.JoinHostPort(ip, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil { // si conecta, el puerto está abierto
					conn.Close()
					mu.Lock() // candado: solo una goroutine escribe a la vez
					open = append(open, OpenPort{Port: port, Service: ServiceName(port)})
					mu.Unlock()
				}
			}
		}()
	}

	// Envía los trabajos y cierra el canal.
	for _, p := range ports {
		jobs <- p
	}
	close(jobs)
	wg.Wait() // espera a que todos los workers terminen

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
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
