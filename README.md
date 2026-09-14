# VPN Status Plugin for DynamicLake

Shows your VPN connection status in the MacBook notch with a disconnect button.

## Features

- Shield icon when connected, shows active protocol (NordLynx, NordWhisper, WireGuard, etc.)
- Works with NordVPN and ProtonVPN
- One-click disconnect (disables auto-reconnect)
- Auto-detects VPN state via scutil and utun interface detection

## Requirements

- macOS with DynamicLake or DynamicLake Playground
- Python 3 (pre-installed on macOS) — needed for disconnect (NordVPN and ProtonVPN)

## Installation

### 1. Install via DynamicLake

Open DynamicLake Settings > Plugins > Install Local, then select the `VPNStatus.dynamiclakeplugin` folder.

### 2. Compile (if modifying source)

```bash
cd VPNStatus.dynamiclakeplugin
swiftc -parse-as-library -O -o vpn-status VPNStatusPlugin.swift
```

### 3. Disconnect Setup (required for NordVPN and ProtonVPN)

The disconnect button requires a one-time sudoers entry to disable auto-reconnect before stopping.

```bash
echo "$(whoami) ALL=(root) NOPASSWD: /usr/bin/python3" | sudo tee /etc/sudoers.d/dynamiclake-vpn-ondemand && sudo chmod 440 /etc/sudoers.d/dynamiclake-vpn-ondemand
```

Without this, VPNs will immediately auto-reconnect after disconnecting.

## Supported VPNs

| VPN | Detection | Disconnect |
|-----|-----------|------------|
| NordVPN | scutil (NordWhisper, NordLynx) | Disables OnDemand + scutil stop |
| ProtonVPN | utun interface detection | Disables network service via networksetup |

## Debug Logs

```
~/Library/Application Support/DynamicLake/PluginLogs/vpn-status-debug.log
```

## File Structure

```
VPNStatus.dynamiclakeplugin/
├── plugin.json           # Plugin manifest
├── VPNStatusPlugin.swift # Source code
├── vpn-status            # Compiled binary
└── icon.png              # Plugin icon
```

## Troubleshooting

**Disconnect doesn't work:** Verify sudoers entry exists:
```bash
cat /etc/sudoers.d/dynamiclake-vpn-ondemand
```
Output should say "Permission Denied" instead of "no such file or directory"

**ProtonVPN won't reconnect after disconnect:** Re-enable the network service:
```bash
networksetup -setnetworkserviceenabled "ProtonVPN" on
```
Or open the ProtonVPN app, which will re-enable it automatically.

Please visit the VPN status plugin page on the DynamicLake discord and report any issues.
