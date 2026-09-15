# SOP: BGP Session Down (eBGP)

**Document ID:** SOP-BGP-001  
**Severity Class:** Critical  
**Applies To:** FRRouting / Cisco IOS-XR / Juniper Junos eBGP peers  
**Last Updated:** 2026-07-30

## Symptoms

- Syslog: `%BGP-5-ADJCHANGE: neighbor <ip> Down`
- `show ip bgp summary` shows neighbor in **Idle** or **Active**
- Customer prefixes withdrawn; traffic blackhole or detour via alternate ASN

## Immediate Triage (Tier-1)

1. Identify the affected device and peer IP from the syslog.
2. Confirm severity — single peer down on dual-homed edge may be Major; sole uplink is Critical.
3. Open a correlated incident and attach the raw syslog + timestamp.

## Diagnostic Commands (FRR / vtysh)

1. `show ip bgp summary` — verify State/PfxRcd.
2. `show ip bgp neighbors <peer>` — Last reset reason, notification codes.
3. `show interface <facing-intf>` — link/protocol state.
4. `ping <peer>` / `traceroute <peer>` — underlay reachability.
5. `show ip route <peer>` — connected / IGP path to peer.

## Root Cause Hypotheses

| Rank | Hypothesis | Evidence |
|------|------------|----------|
| 1 | Underlay link / interface down | Interface DOWN, ping 100% loss |
| 2 | Hold timer expiry after congestion | Interface UP, intermittent loss |
| 3 | Admin shutdown / config change | `neighbor shutdown` in running-config |
| 4 | ASN / MD5 / capability mismatch | Notification OPEN / AUTH errors |
| 5 | ACL / firewall blocking TCP/179 | SYN sent, no ESTABLISHED |

## Remediation Steps

1. Restore underlay: check optics, cabling, `no shutdown` on interface.
2. Verify IP addressing on the peering subnet (/30 or /31).
3. Remove unintended `neighbor <peer> shutdown`.
4. Clear session only after underlay is healthy: `clear ip bgp <peer>`.
5. Confirm Established and prefix counts return to baseline.
6. Document RCA and update change calendar if human-driven.

## Historical Cases

- **Case:** lab-r1-eth1-down-2026Q2 — Interface eth1 DOWN caused eBGP Idle; recovery after `ip link set eth1 up` and BGP renegotiation within 12s.
- **Case:** prod-pe3-holdtimer — Microbursts caused hold-timer expiry; fixed by QoS on control-plane policing and BFD enablement.
- **History:** Always correlate BGP Down with interface syslog within ±30 seconds before blaming BGP config.

## Escalation

Escalate to Tier-2 Network Engineering if session does not re-establish within 15 minutes after underlay restore.
