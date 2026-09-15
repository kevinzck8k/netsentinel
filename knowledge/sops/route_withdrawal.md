# SOP: Route / Prefix Withdrawal

**Document ID:** SOP-BGP-006  
**Severity Class:** Warning  
**Applies To:** eBGP edge, IX peering, transit  
**Last Updated:** 2026-09-14

## Symptoms

- Syslog: prefix withdrawn by neighbor, RIB delta, reachability loss
- Historical analogues: YouTube hijack (2008), AS9121 route leak

## Diagnostic Steps

1. Identify the withdrawn prefix and origin AS (`show ip bgp`).
2. Diff against the previous prefix baseline / looking-glass.
3. Decide leak vs hijack vs intended withdraw vs session reset.

## Remediation Steps

1. Apply or tighten prefix-lists / max-prefix / RPKI ROV on the offending peer.
2. Prefer a valid alternate path if one exists.
3. Contact the peer NOC with the exact prefix and timestamp.
4. Document as routing-policy RCA, not a physical-link ticket.
