package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"netsentinel/internal/discovery"
	"netsentinel/internal/report"
	"netsentinel/internal/scanner"
)

const defaultTopPorts = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443"

func main() {
	// ----- Banderas de la CLI -----
	subnet := flag.String("subnet", "192.168.0.0/24", "Red a escanear en formato CIDR")
	portsStr := flag.String("ports", defaultTopPorts, "Puertos a escanear (lista o rango)")
	timeout := flag.Int("timeout", 800, "Timeout por puerto en milisegundos")
	workers := flag.Int("workers", 100, "Goroutines concurrentes")
	noPing := flag.Bool("no-ping", false, "Omitir descubrimiento y escanear todas las IPs")
	outJSON := flag.String("out", "netsentinel-report.json", "Archivo JSON de salida")
	flag.Parse()

	// ----- 1. Validar puertos y red -----
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

	fmt.Printf("NetSentinel: escaneando %s (%d hosts, %d puertos/host)\n", *subnet, len(hosts), len(ports))
	// ----- 2. Descubrimiento de hosts -----
	withPing := !*noPing
	up := hosts
	if withPing {
		fmt.Println("[1/2] Descubriendo hosts vivos...")
		up = discovery.Sweep(hosts, *workers, *timeout)
		fmt.Printf("      %d hosts vivos detectados:\n", len(up))
		for _, ip := range up {
			fmt.Printf("        • %s\n", ip) // ← ahora imprime cada IP viva
		}
	}

	if len(up) == 0 {
		fmt.Println("Sin hosts vivos. Verifica el CIDR y tu conexión.")
		os.Exit(0)
	}

	// ----- 3. Escaneo de puertos por host -----
	fmt.Println("[2/2] Escaneando puertos de hosts vivos...")
	results := []report.HostResult{}
	for _, ip := range up {
		open := scanner.ScanHost(ip, ports, time.Duration(*timeout)*time.Millisecond, *workers)
		if open == nil {
			open = []scanner.OpenPort{} // truco: en JSON se verá [] en vez de null
		}

		// Sin ping no podemos confirmar que un host esté "activo":
		// en modo -no-ping solo reportamos los que tengan puertos abiertos.
		if len(open) == 0 && !withPing {
			continue
		}

		results = append(results, report.HostResult{IP: ip, OpenPorts: open}) // ← ahora TODOS los vivos entran al reporte
		if len(open) > 0 {
			fmt.Printf("      ✔ %s → %d puertos abiertos\n", ip, len(open))
		} else {
			fmt.Printf("      · %s → activo, sin puertos abiertos\n", ip)
		}
	}

	// ----- 4. Reporte -----
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
}
