package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"netsentinel/internal/scanner"
)

// HostResult agrupa el resultado de un host.
type HostResult struct {
	IP        string             `json:"ip"`
	OpenPorts []scanner.OpenPort `json:"open_ports"`
}

// ScanReport es el reporte completo del escaneo.
type ScanReport struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Subnet      string       `json:"subnet"`
	HostsUp     int          `json:"hosts_up"`
	Results     []HostResult `json:"results"`
}

// PrintTable muestra el resumen bonito en terminal.
func PrintTable(r ScanReport) {
	fmt.Println()
	fmt.Println("==========================================================")
	fmt.Printf(" NetSentinel — Reporte (%s)\n", r.Subnet)
	fmt.Println("==========================================================")
	for _, h := range r.Results {
		if len(h.OpenPorts) == 0 {
			fmt.Printf("\n■ Host: %s (activo, sin puertos abiertos)\n", h.IP)
			continue
		}
		fmt.Printf("\n■ Host: %s (%d puertos abiertos)\n", h.IP, len(h.OpenPorts))
		for _, p := range h.OpenPorts {
			fmt.Printf("   %-8d %-12s\n", p.Port, p.Service)
		}
	}
	fmt.Println()
}

// SaveJSON escribe el reporte en un archivo JSON.
func SaveJSON(r ScanReport, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
