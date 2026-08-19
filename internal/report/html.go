package report

import (
	"html/template"
	"os"

	"netsentinel/internal/scanner" // ← import nuevo
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel Report - {{.Subnet}}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .meta { color: #7f8c8d; margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #3498db; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ecf0f1; }
        tr:hover { background: #f8f9fa; }
        .port { font-weight: bold; color: #2c3e50; }
        .service { color: #27ae60; font-weight: 600; }
        .banner { color: #7f8c8d; font-size: 0.9em; font-family: monospace; }
        .critical { background: #ffe6e6; }
        .hostname { color: #3498db; font-style: italic; }
        .vuln { color: #c0392b; font-size: 0.85em; margin-left: 12px; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛰️ NetSentinel v3 Report</h1>
        <div class="meta">
            <strong>Subnet:</strong> {{.Subnet}}<br>
            <strong>Generated:</strong> {{.GeneratedAt.Format "2006-01-02 15:04:05"}}<br>
            <strong>Hosts found:</strong> {{.HostsUp}}
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Open Ports</th>
                    <th>Services & Banners</th>
                </tr>
            </thead>
            <tbody>
                {{range .Results}}
                <tr{{if gt (len .OpenPorts) 0}}{{if hasCriticalPort .OpenPorts}} class="critical"{{end}}{{end}}>
                    <td><strong>{{.IP}}</strong></td>
                    <td class="hostname">{{if .Hostname}}{{.Hostname}}{{else}}—{{end}}</td>
                    <td>{{len .OpenPorts}}</td>
                    <td>
                        {{range .OpenPorts}}
                        <div style="margin: 5px 0;">
                            <span class="port">{{.Port}}</span> 
                            <span class="service">{{.Service}}</span>
                            {{if .Banner}}<br><span class="banner">└─ {{.Banner}}</span>{{end}}
                            {{range .Vulns}}
                            <div class="vuln">⚠ {{.ID}} — {{.Severity}} · {{printf "%.1f" .Score}}</div>
                            {{end}}
                        </div>
                        {{else}}
                        <em style="color: #95a5a6;">Sin puertos abiertos</em>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`

// hasCriticalPort ahora recibe el tipo calificado con su paquete.
func hasCriticalPort(ports []scanner.OpenPort) bool {
	critical := map[int]bool{22: true, 3389: true, 445: true, 23: true, 21: true}
	for _, p := range ports {
		if critical[p.Port] {
			return true
		}
	}
	return false
}

func SaveHTML(r ScanReport, path string) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"hasCriticalPort": hasCriticalPort,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, r)
}
