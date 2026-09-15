# SOP: High Memory / Control-Plane Pressure

**Document ID:** SOP-SYS-005  
**Severity Class:** Major  
**Applies To:** FRR / NOS control-plane hosts  
**Last Updated:** 2026-09-14

## Symptoms

- Syslog: memory low / exhausted / OOM killer
- Slow CLI; BGP slow-peer; process restart

## Diagnostic Steps

1. Capture `free -m` and top memory consumers.
2. Check for BGP RIB growth or debug logging left enabled.
3. Look for leak after a recent software upgrade.

## Remediation Steps

1. Disable leftover debug / packet capture.
2. Apply prefix filters if the RIB is unexpectedly large.
3. Restart the offending daemon in a change window if memory does not recover.
4. Escalate for a core dump if the leak reproduces.
