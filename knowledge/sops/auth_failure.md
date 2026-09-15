# SOP: Network Authentication Failure

**Document ID:** SOP-AUTH-005  
**Severity Class:** Warning / Major  
**Applies To:** BGP TCP-MD5, SSH, TACACS+, RADIUS, device login

## Symptoms

- BGP reports TCP MD5 digest mismatch or authentication failure.
- SSH reports `authentication failure`, `Failed password`, or `Invalid user`.
- A neighbor remains Idle even though IP reachability and TCP/179 are healthy.

## Diagnostic Steps

1. Identify whether the failure is control-plane peering or management access.
2. Correlate source IP, username, peer address, and recent credential changes.
3. For BGP, compare the configured neighbor password on both peers without logging secrets.
4. For SSH, check repeated failures, source reputation, AAA server reachability, and account lockout.
5. Verify clock synchronization when time-based authentication is involved.

## Remediation Steps

1. Rotate or synchronize the BGP TCP-MD5 secret through an approved change window.
2. Block abusive SSH source addresses and disable invalid accounts.
3. Restore TACACS+/RADIUS connectivity or use the approved break-glass procedure.
4. Clear the BGP session only after credentials match and underlay reachability is confirmed.
5. Preserve authentication logs for security investigation and audit.

## Safety Notes

- Never include plaintext credentials in an RCA report, prompt, trace, or ticket.
- Do not interpret an authentication alarm as a physical interface failure without telemetry.
- Escalate repeated SSH failures to the security operations team.

## Historical Cases

- **Case:** BGP peer remained Idle after one side rotated its TCP-MD5 key; synchronizing the key restored Established.
- **History:** Repeated invalid SSH users commonly indicate Internet scanning rather than a network link fault.
