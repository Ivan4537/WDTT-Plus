// Package firewall blocks traffic that bypasses the VPN adapter using the
// Windows Filtering Platform.
//
// It is adapted from golang.zx2c4.com/wireguard/windows/tunnel/firewall
// (MIT, WireGuard LLC). The only functional change is in
// permitWireGuardService: the permit rule for this process matches its exe
// path alone, without the WireGuard service SID condition.
package firewall
