# SOP: Interface / Link Down

**Document ID:** SOP-L2-002  
**Severity Class:** Critical  
**Applies To:** PE / P / Leaf-Spine ethernet interfaces  
**Last Updated:** 2026-07-30

## Symptoms

- Syslog: `%LINK-3-UPDOWN: Interface ethX, changed state to down`
- `%LINEPROTO-5-UPDOWN: Line protocol on Interface ethX, changed state to down`
- Dependent protocols (BGP, OSPF, LACP, BFD) fail immediately after

## Immediate Triage

1. Identify chassis, slot/port (or containerlab node + ethN).
2. Check for concurrent optics alarms / LOS / CRC error storms.
3. Determine blast radius: single access link vs. spine uplink vs. peering cross-connect.

## Diagnostic Commands

1. `show interface eth1` — admin/oper status, counters, error rates.
2. `ip link show eth1` — Linux/FRR lab equivalent.
3. `show interface eth1 counters` — CRC, input errors, carrier transitions.
4. Optical DOM (platform-specific): TX/RX power vs. thresholds.
5. Peer side verification — confirm far-end also sees Down (rules out one-sided RX fault).

## Root Cause Hypotheses

| Rank | Hypothesis | Evidence |
|------|------------|----------|
| 1 | Physical layer fault (cable/optic) | Both ends Down, LOS |
| 2 | Administrative shutdown | `shutdown` in config |
| 3 | Remote peer maintenance | Change ticket / NOC notice |
| 4 | Hardware / driver failure | Kernel logs, repeated flap |
| 5 | Lab intentional inject | fault_injector.py / automation |

## Remediation Steps

1. If admin-down unintentionally: `no shutdown` / `ip link set eth1 up`.
2. Reseat or replace optic / DAC / fiber; clean connectors.
3. Hard-swap to spare port if hardware suspected; update IGP/BGP cost as needed.
4. After link UP, verify dependent BGP/OSPF adjacencies re-form.
5. Clear sticky counters and baseline error rates for 30 minutes.

## Historical Cases

- **Case:** clab-telco-aiops iface-down demo — `ip link set eth1 down` on r1 dropped eBGP within hold-timer; auto-recover restored Established in <10s.
- **History:** 70% of BGP Down tickets in peering edge correlated with interface Down within 5 seconds.

## Safety Notes

- Never bounce a production uplink during peak without change approval.
- Risk level for interface flap: **medium** (traffic impact); for shut/no-shut on maintenance window: **low**.
