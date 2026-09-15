# SOP: Physical Link / BFD Failure

**Document ID:** SOP-L1-003  
**Severity Class:** Critical  
**Applies To:** PE / P / leaf-spine ethernet and BFD-protected links  
**Last Updated:** 2026-09-14

## Symptoms

- Syslog: carrier lost, link failure, BFD session down
- Immediate OSPF/BGP adjacency collapse on the same interface

## Diagnostic Steps

1. Check optics / LOS / CRC on both ends.
2. Confirm BFD discriminator and multiplier.
3. Separate fiber cut from admin shutdown.

## Remediation Steps

1. Restore Layer-1 (optics, patch, far-end no shutdown).
2. Verify BFD Up before clearing IGP/BGP.
3. Confirm dependent sessions return to Established / FULL.
