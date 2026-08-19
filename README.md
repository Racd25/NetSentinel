# NetSentinel
Lightweight concurrent network scanner with host discovery and TCP port scanning, built in Go.

## Features
- Host discovery (ping sweep / ARP-ready)
- Concurrent TCP port scanning with worker pool
- Configurable timeouts and port ranges
- (próximamente) JSON output, Sentinel integration...

## Installation / Build
go build ./cmd/netsentinel

## Usage
./netsentinel -target 192.168.1.0/24 -ports 1-1024 -timeout 2s
(ejemplo de salida real aquí)
.\netsentinel.exe -subnet 192.168.0.0/24 

## Architecture
(cmd/ = entrypoint, internal/ = lógica; cómo funciona la concurrencia)

## Roadmap
- [ ] JSON output
- [ ] Service/banner detection
- [ ] Azure Sentinel integration

## Responsible Use
Scan only networks you own or have explicit permission to test.
