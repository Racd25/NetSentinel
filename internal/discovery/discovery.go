package discovery

import (
	"bytes"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"sync"
)

// HostsFromCIDR expande un CIDR (ej: "192.168.1.0/24") a la lista de IPs.
func HostsFromCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for cur := ip.Mask(network.Mask); network.Contains(cur); inc(cur) {
		hosts = append(hosts, cur.String())
	}

	// Quita dirección de red y de broadcast (solo aplica a /30 o mayores).
	ones, bits := network.Mask.Size()
	if bits == 32 && ones < 31 && len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

// inc incrementa una IP en 1 (192.168.1.5 → 192.168.1.6).
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Sweep hace un ping sweep concurrente y devuelve los hosts que responden.
func Sweep(hosts []string, workers int, timeoutMs int) []string {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		jobs = make(chan string, len(hosts))
		up   []string
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if ping(ip, timeoutMs) {
					mu.Lock()
					up = append(up, ip)
					mu.Unlock()
				}
			}
		}()
	}

	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)
	wg.Wait()

	// Ordena IPs numéricamente.
	sort.Slice(up, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(up[i]).To4(), net.ParseIP(up[j]).To4()) < 0
	})
	return up
}

// ping usa el ping del sistema operativo (sin dependencias externas,
// funciona igual en Windows y Linux).
func ping(ip string, timeoutMs int) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	return cmd.Run() == nil
}
