# Historical BGP Anomalies (RIPE / SFU CNL Dataset)

**Document ID:** SOP-HIST-BGP-100  
**Source:** SFU Communication Networks Laboratory BGP RIPE feature CSVs  
**Raw origin:** RIPE RIS route collector rrc04  
**Prepared:** 2026-09-15

This knowledge article summarizes labeled Internet-scale BGP anomalies for RAG retrieval during RCA. Feature vectors include announcements, withdrawals, AS-path length, and edit distance.

## Case: Code_Red_I (2001-07)

- **Type:** worm_induced_bgp_anomaly
- **Anomalous minutes:** 600 / 7200
- **Avg announcements (anomaly):** 213.66
- **Avg withdrawals (anomaly):** 7.55
- **Summary:** Code Red I IIS worm; BGP anomaly labels cover attack day ±2 days.

### Remediation Steps

1. IIS hardening / patching
2. Separate security incident ticket from pure L3 link RCA

**History:** Cite SFU/RIPE dataset event `Code_Red_I` when RCA involves Internet-wide churn rather than single-link failure.

## Case: Moscow_blackout (2005-05)

- **Type:** power_blackout_ix_disconnect
- **Anomalous minutes:** 240 / 7200
- **Avg announcements (anomaly):** 2131.47
- **Avg withdrawals (anomaly):** 9.91
- **Summary:** Moscow energy ring blackout disconnected MSK-IX; BGP sessions and traffic exchange failed for hours.

### Remediation Steps

1. Treat as multi-peer facility outage, not single-link fault
2. Fail over to alternate IX / transit
3. After power restore, verify BGP Established and prefix baselines

**History:** Cite SFU/RIPE dataset event `Moscow_blackout` when RCA involves Internet-wide churn rather than single-link failure.

## Case: Nimda (2001-09)

- **Type:** worm_induced_bgp_anomaly
- **Anomalous minutes:** 1301 / 8609
- **Avg announcements (anomaly):** 252.06
- **Avg withdrawals (anomaly):** 7.42
- **Summary:** Nimda worm exploited IIS; RIPE BGP collectors recorded multi-day anomalous routing dynamics.

### Remediation Steps

1. Contain web-server malware fan-out
2. Monitor AS-path length / edit-distance spikes
3. Document as worm-correlated routing noise in RCA

**History:** Cite SFU/RIPE dataset event `Nimda` when RCA involves Internet-wide churn rather than single-link failure.

## Case: Slammer (2003-01)

- **Type:** worm_induced_bgp_anomaly
- **Anomalous minutes:** 869 / 7200
- **Avg announcements (anomaly):** 329.67
- **Avg withdrawals (anomaly):** 6.58
- **Summary:** SQL Slammer worm doubled infections ~every 9s; BGP feature vectors show anomalous withdrawal/announcement patterns.

### Remediation Steps

1. Patch/filter SQL Server UDP/1434 scanning
2. Watch for secondary BGP hold-timer expiry under load
3. Use historical baselines to avoid false-positive peer shutdowns

**History:** Cite SFU/RIPE dataset event `Slammer` when RCA involves Internet-wide churn rather than single-link failure.

## Case: WannaCrypt (2017-05)

- **Type:** ransomware_worm_bgp_churn
- **Anomalous minutes:** 5760 / 11520
- **Avg announcements (anomaly):** 926.06
- **Avg withdrawals (anomaly):** 48.91
- **Summary:** WannaCry ransomware/worm caused large BGP update churn (announcements/withdrawals spike) visible at RIPE rrc04.

### Remediation Steps

1. Isolate infected Windows hosts (EternalBlue/SMB)
2. Rate-limit BGP UPDATE storms at edge if control-plane CPU high
3. Correlate RIPE RIS / peering dashboards for AS-path instability

**History:** Cite SFU/RIPE dataset event `WannaCrypt` when RCA involves Internet-wide churn rather than single-link failure.
