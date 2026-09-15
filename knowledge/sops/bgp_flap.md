# SOP: BGP Session Flapping

**Document ID:** SOP-BGP-003  
**Severity Class:** Major  
**Applies To:** eBGP / iBGP peers with repeated Established ↔ Idle transitions  
**Last Updated:** 2026-07-30

## Symptoms

- Multiple `%BGP-5-ADJCHANGE` Up/Down within a short window
- Route oscillation; FIB churn; CPU elevation on control plane
- Monitoring: flap-count threshold exceeded

## Diagnostic Steps

1. `show ip bgp summary` — observe flapping neighbor and PfxRcd instability.
2. `show ip bgp neighbors <peer>` — last reset reasons over time.
3. Correlate with interface carrier transitions and BFD sessions.
4. Check MTU mismatch / ICMP fragmentation blackhole on the path.
5. Review recent configuration commits and software upgrades.

## Remediation Steps

1. Enable or tune BFD for sub-second detection if flaps are link-related.
2. Stabilize underlay (replace flapping optic, fix CRC).
3. Consider `neighbor <peer> shutdown` temporarily to stop control-plane thrash while investigating (change-controlled).
4. Increase hold-timer only as a temporary mitigation — prefer fixing root cause.
5. After stability ≥ 30 minutes, document flap histogram in RCA.

## Historical Cases

- **Case:** pe-flap-mtu-2025 — MTU 1500 vs 9000 mismatch caused intermittent BGP drops under large UPDATE bursts; resolved by standardizing interface MTU and MSS clamp.
- **History:** Flaps coinciding with `clear ip bgp *` automation jobs are operator-induced — tag as change-related, not incident.
