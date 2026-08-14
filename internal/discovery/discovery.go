package discovery

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// HostInfo incluye IP y hostname resuelto.
type HostInfo struct {
	IP       string
	Hostname string
}

func HostsFromCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for cur := ip.Mask(network.Mask); network.Contains(cur); inc(cur) {
		hosts = append(hosts, cur.String())
	}

	ones, bits := network.Mask.Size()
	if bits == 32 && ones < 31 && len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Sweep ahora devuelve HostInfo con hostname resuelto.
func Sweep(ctx context.Context, hosts []string, workers int, timeoutMs int) []HostInfo {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		jobs = make(chan string, len(hosts))
		up   []HostInfo
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					if ping(ctx, ip, timeoutMs) {
						hostname := resolveHostname(ip)
						mu.Lock()
						up = append(up, HostInfo{IP: ip, Hostname: hostname})
						mu.Unlock()
					}
				}
			}
		}()
	}

	for _, h := range hosts {
		select {
		case <-ctx.Done():
			break
		case jobs <- h:
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(up, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(up[i].IP).To4(), net.ParseIP(up[j].IP).To4()) < 0
	})
	return up
}

// resolveHostname hace reverse DNS lookup.
func resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Limpiar el punto final que agregan algunos DNS
	name := strings.TrimSuffix(names[0], ".")
	return name
}

func ping(ctx context.Context, ip string, timeoutMs int) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), ip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip)
	}
	return cmd.Run() == nil
}
