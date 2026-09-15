# SOP: OSPF Adjacency Down

**Document ID:** SOP-IGP-005  
**Severity Class:** Major  
**Applies To:** FRRouting / Cisco IOS / Juniper OSPF areas  
**Last Updated:** 2026-09-14

## Symptoms

- Syslog: `%OSPF-5-ADJCHG` neighbor from FULL to DOWN
- `show ip ospf neighbor` missing FULL/DR or FULL/BDR
- Dependent BGP next-hops become unreachable after IGP hole

## Diagnostic Steps

1. Confirm the interface and area (`show ip ospf interface`).
2. Compare hello/dead timers and MTU on both sides.
3. Check underlay carrier / BFD if configured.
4. Review recent area or authentication changes.

## Remediation Steps

1. Restore the Layer-2 / BFD session first if the link is down.
2. Align OSPF hello/dead, network type, and MTU.
3. Clear the neighbor only after the underlay is stable.
4. Confirm RIB convergence and BGP next-hop reachability.
