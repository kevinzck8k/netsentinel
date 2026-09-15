# SOP: High CPU on Network Node

**Document ID:** SOP-SYS-004  
**Severity Class:** Major  
**Applies To:** FRR / NOS control-plane hosts  
**Last Updated:** 2026-07-30

## Symptoms

- Syslog / telemetry: CPU utilization > 90% sustained
- Slow CLI response; BGP slow-peer; missed hold timers secondary effect

## Diagnostic Steps

1. Identify top processes (`top`, `vtysh -c 'show process cpu'` where available).
2. Check for BGP UPDATE storms / route thrash.
3. Inspect debug logging left enabled in production.
4. Review recent policy changes causing soft-reconfiguration churn.

## Remediation Steps

1. Disable excessive debugs.
2. Dampen flapping peers; fix underlay flaps first.
3. Scale-out or increase CPU allocation for lab VMs / containers.
4. If BGP slow-peer, enable short-lived peer dampening per platform guides.

## Historical Cases

- **History:** High CPU secondary to interface flap loops — remediating L2 stability normalized CPU within 5 minutes.
