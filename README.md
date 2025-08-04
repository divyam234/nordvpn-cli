# NordVPN CLI

A lightweight, efficient command-line interface for NordVPN using NordLynx/WireGuard directly on Linux systems.

## Why This Client?

This NordVPN CLI client is a more efficient alternative to the official NordVPN client:

- **Memory Efficient**: Unlike the official NordVPN client which runs background daemons and uses significant memory, this client only consumes resources when actively connecting/disconnecting
- **Direct WireGuard Integration**: Connects directly via WireGuard without unnecessary overhead
- **Minimal Dependencies**: Only requires standard system tools (`curl`, `jq`, `wg-tools`, etc.)
- **No Background Services**: No constantly running processes consuming CPU or memory
- **Simpler Architecture**: Eliminates complex service layers for a more straightforward VPN experience

This makes it ideal for servers, containers, or users who want a lightweight VPN solution without the resource overhead of the official client.

## Features

- CLI interface with commands: `up`, `down`, `reset`, `status`
- Configuration via JSON file (`~/.config/nordlynx-cli/config.json` or `/etc/nordlynx-cli/config.json`)
- Supports command-line flags to override config file settings
- Server selection via NordVPN API based on country code and category
- Automatic route and firewall rule management
- IPv4 kill-switch functionality
- Tailscale integration support

## Prerequisites

The script requires the following dependencies:

- `curl`
- `jq`
- `wg` (WireGuard tools)
- `wg-quick`
- `ip` (iproute2)
- `iptables`
- `dig`

Install these using your distribution's package manager:

```bash
# Ubuntu/Debian
sudo apt install curl jq wireguard-tools iproute2 iptables dnsutils

# Fedora/RHEL/CentOS
sudo dnf install curl jq wireguard-tools iproute iptables bind-utils

# Arch Linux
sudo pacman -S curl jq wireguard-tools iproute2 iptables bind-tools
```

## Installation
   ```bash
   sudo curl -so /usr/bin/nordvpn https://raw.githubusercontent.com/divyam234/nordvpn-cli/main/nordvpn
   sudo chmod +x /usr/bin/nordvpn
   ```

## Configuration

Create a JSON configuration file at `~/.config/nordlynx-cli/config.json`:

```json
{
  "nordlynx": {
    "private_key": "your_wireguard_private_key",
    "token": "your_nordvpn_api_token",
    "country_code": "us",
    "category": "standard",
    "interface": "eth0",
    "wg_interface": "wg0",
    "net_local": "192.168.1.0/24;10.0.0.0/8"
  }
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `private_key` | Your WireGuard private key | None |
| `file_private_key` | Path to file containing private key | None |
| `token` | Your NordVPN API token | None |
| `country_code` | NordVPN country code (e.g., us, gb) | None |
| `category` | NordVPN server category (standard, p2p, double, obfuscated, onion) | None |
| `interface` | Physical network interface | eth0 |
| `wg_interface` | WireGuard interface name | wg0 |
| `net_local` | Comma/semicolon separated local networks | None |
| `listen_port` | WireGuard listen port | 51820 |
| `address` | Client tunnel IP address | 10.5.0.2/32 |
| `dns` | DNS server IP(s) | 103.86.96.100, 103.86.99.100 |
| `allowed_ips` | WireGuard AllowedIPs | 0.0.0.0/0 |
| `persistent_keepalive` | WireGuard persistent keepalive | 25 |
| `endpoint` | Manual server endpoint | None |
| `public_key` | Manual server public key | None |

## Usage

The script must be run as root:

```bash
sudo ./nordvpn.sh <command> [options]
```

### Commands

- `up`: Connect to NordVPN using NordLynx/WireGuard
- `down`: Disconnect from NordVPN and clean up rules
- `reset`: Disconnect and then reconnect
- `status`: Show the current connection status and firewall rules

### Examples

Connect using configuration file:
```bash
sudo ./nordvpn.sh up
```

Connect to a German server, overriding config:
```bash
sudo ./nordvpn.sh up --country-code de
```

Connect with a specific token:
```bash
sudo ./nordvpn.sh up --token "your_token"
```

Disconnect:
```bash
sudo ./nordvpn.sh down
```

## Firewall

The script automatically configures iptables rules to implement a kill-switch that prevents traffic leaks outside the VPN tunnel. It allows:

- Loopback traffic
- Traffic through the WireGuard interface
- Traffic to the VPN server endpoint
- Traffic to specified local networks
- All other traffic is blocked