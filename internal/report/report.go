package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"netsentinel/internal/scanner"
)

type ScanReport struct {
	GeneratedAt time.Time            `json:"generated_at"`
	Subnet      string               `json:"subnet"`
	HostsUp     int                  `json:"hosts_up"`
	Results     []scanner.HostResult `json:"results"`
}

func PrintTable(r ScanReport) {
	fmt.Println()
	fmt.Println("==========================================================")
	fmt.Printf(" NetSentinel v2 — Report (%s)\n", r.Subnet)
	fmt.Println("==========================================================")
	for _, h := range r.Results {
		if len(h.OpenPorts) == 0 {
			if h.Hostname != "" {
				fmt.Printf("\n■ Host: %s (%s) — activo, sin puertos abiertos\n", h.IP, h.Hostname)
			} else {
				fmt.Printf("\n■ Host: %s — activo, sin puertos abiertos\n", h.IP)
			}
			continue
		}
		if h.Hostname != "" {
			fmt.Printf("\n■ Host: %s (%s) — %d puertos abiertos\n", h.IP, h.Hostname, len(h.OpenPorts))
		} else {
			fmt.Printf("\n■ Host: %s — %d puertos abiertos\n", h.IP, len(h.OpenPorts))
		}
		for _, p := range h.OpenPorts {
			if p.Banner != "" {
				fmt.Printf("   %-8d %-12s\n", p.Port, p.Service)
				fmt.Printf("            └─ %s\n", p.Banner)
			} else {
				fmt.Printf("   %-8d %-12s\n", p.Port, p.Service)
			}
		}
	}
	fmt.Println()
}

func SaveJSON(r ScanReport, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
