package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netsentinel/internal/discovery"
	"netsentinel/internal/report"
	"netsentinel/internal/scanner"
)

const defaultTopPorts = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443"

func main() {
	subnet := flag.String("subnet", "192.168.1.0/24", "Red a escanear en formato CIDR")
	portsStr := flag.String("ports", defaultTopPorts, "Puertos a escanear (lista o rango)")
	timeout := flag.Int("timeout", 800, "Timeout por puerto en milisegundos")
	workers := flag.Int("workers", 100, "Goroutines concurrentes")
	noPing := flag.Bool("no-ping", false, "Omitir descubrimiento y escanear todas las IPs")
	outJSON := flag.String("out", "netsentinel-report.json", "Archivo JSON de salida")
	outHTML := flag.String("html", "netsentinel-report.html", "Archivo HTML de salida")
	flag.Parse()

	// Context con cancelación manual (Ctrl+C)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Capturar señales del sistema
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⚠️  Cancelando escaneo...")
		cancel()
	}()

	ports, err := scanner.ParsePorts(*portsStr)
	if err != nil {
		fmt.Println("Error en puertos:", err)
		os.Exit(1)
	}

	hosts, err := discovery.HostsFromCIDR(*subnet)
	if err != nil {
		fmt.Println("Error en red:", err)
		os.Exit(1)
	}

	fmt.Printf("NetSentinel v2: escaneando %s (%d hosts, %d puertos/host)\n", *subnet, len(hosts), len(ports))

	withPing := !*noPing
	var up []discovery.HostInfo
	if withPing {
		fmt.Println("[1/2] Descubriendo hosts vivos...")
		up = discovery.Sweep(ctx, hosts, *workers, *timeout)
		fmt.Printf("      %d hosts vivos detectados.\n", len(up))
	} else {
		up = make([]discovery.HostInfo, len(hosts))
		for i, h := range hosts {
			up[i] = discovery.HostInfo{IP: h}
		}
	}

	if len(up) == 0 {
		fmt.Println("Sin hosts vivos. Verifica el CIDR y tu conexión.")
		os.Exit(0)
	}

	fmt.Println("[2/2] Escaneando puertos con banner grabbing...")
	results := []scanner.HostResult{}
	for _, host := range up {
		select {
		case <-ctx.Done():
			fmt.Println("Escaneo cancelado.")
			break
		default:
			open := scanner.ScanHost(ctx, host.IP, ports, time.Duration(*timeout)*time.Millisecond, *workers)
			if open == nil {
				open = []scanner.OpenPort{}
			}

			if len(open) == 0 && !withPing {
				continue
			}

			result := scanner.HostResult{
				IP:        host.IP,
				Hostname:  host.Hostname,
				OpenPorts: open,
			}
			results = append(results, result)

			if len(open) > 0 {
				fmt.Printf("      ✔ %s → %d puertos abiertos\n", host.IP, len(open))
			} else {
				fmt.Printf("      · %s → activo, sin puertos abiertos\n", host.IP)
			}
		}
	}

	rep := report.ScanReport{
		GeneratedAt: time.Now(),
		Subnet:      *subnet,
		HostsUp:     len(up),
		Results:     results,
	}

	report.PrintTable(rep)

	if err := report.SaveJSON(rep, *outJSON); err != nil {
		fmt.Println("Error al guardar JSON:", err)
		os.Exit(1)
	}
	fmt.Println("Reporte JSON guardado en:", *outJSON)

	if err := report.SaveHTML(rep, *outHTML); err != nil {
		fmt.Println("Error al guardar HTML:", err)
	} else {
		fmt.Println("Reporte HTML guardado en:", *outHTML)
	}
}
