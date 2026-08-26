-- Operational database for the SOC testbed (postgres-operational).
-- Schema + minimal-but-non-degenerate seed. Runs once on first container init
-- (/docker-entrypoint-initdb.d). Reproducible: drop the volume and it re-seeds.
--
-- Column sets mirror exactly the dicts each tool's data-access seam returns, so
-- swapping canned->real changed only seam internals, never the return shape.
-- (alerts.severity exists in the table but the SIEM seam does NOT select it —
--  the returned alert shape has no severity key, matching the current canned.)

-- ---- schema ----------------------------------------------------------------
CREATE TABLE alerts (
    id          text PRIMARY KEY,
    ts          timestamptz NOT NULL,
    severity    text,                         -- present but not returned by seam
    source_ip   text,
    dest_ip     text,
    rule_name   text,
    description text
);

CREATE TABLE assets (
    asset_id      text PRIMARY KEY,
    hostname      text,
    owner         text,
    owner_contact text,
    criticality   text,
    location      text,
    os            text,
    last_seen     timestamptz
);

CREATE TABLE users (
    user_id      text PRIMARY KEY,
    display_name text,
    department   text,
    manager      text,
    email        text,
    privileged   boolean,
    mfa_enrolled boolean
);

CREATE TABLE iocs (
    indicator  text PRIMARY KEY,
    verdict    text,               -- malicious | suspicious | clean
    confidence double precision,
    source     text
);

CREATE TABLE runbook (
    id         serial PRIMARY KEY,
    title      text,
    steps      jsonb,              -- array of step strings
    attack_ref text,
    source     text,
    keywords   text                -- space-separated, for keyword search
);

CREATE TABLE incidents (
    incident_id text PRIMARY KEY,
    status      text,
    title       text,
    description text,
    severity    text,
    assignee    text,
    created_at  timestamptz,
    updated_at  timestamptz,
    note        text
);

-- ---- seed: alerts (variety of source/dest/rule; newest first via ts) --------
INSERT INTO alerts (id, ts, severity, source_ip, dest_ip, rule_name, description) VALUES
 ('alert-0001','2026-08-02T14:23:17Z','high','10.14.7.32','198.51.100.77','Suspicious Outbound Data Transfer',
   'Host 10.14.7.32 transferred 4.2 GB to external address 198.51.100.77 over 11 minutes, exceeding the baseline for this asset by 40x.'),
 ('alert-0002','2026-08-02T13:10:05Z','high','10.14.7.55','203.0.113.9','Malware C2 Beacon',
   'Endpoint 10.14.7.55 is beaconing every 60s to 203.0.113.9 with encoded payloads; EDR flags a known trojan family.'),
 ('alert-0003','2026-08-02T11:47:52Z','critical','10.0.0.10','10.0.0.25','Anomalous Privileged Logon',
   'Domain controller 10.0.0.10 recorded anomalous privileged logons and suspicious process creation off-hours.'),
 ('alert-0004','2026-08-02T09:15:00Z','low','10.14.7.60','10.0.0.5','Scheduled Patch Reboot',
   'Host 10.14.7.60 rebooted during the maintenance window after a scheduled OS patch install. No anomalies.'),
 ('alert-0005','2026-08-02T08:02:31Z','medium','10.14.7.32','185.199.110.153','Phishing Link Click',
   'User jdoe on 10.14.7.32 clicked a link flagged by the mail gateway; the URL resolved to 185.199.110.153.');

-- ---- seed: assets (differing criticality; DC known by hostname and by IP) ----
INSERT INTO assets (asset_id, hostname, owner, owner_contact, criticality, location, os, last_seen) VALUES
 ('10.14.7.32','fin-ws-0447','finance-workstations','it-finance@example.corp','medium','HQ-3F','Windows 11 Pro 23H2','2026-08-02T14:20:00Z'),
 ('10.14.7.55','fin-ws-0455','finance-workstations','it-finance@example.corp','medium','HQ-3F','Windows 11 Pro 23H2','2026-08-02T13:05:00Z'),
 ('10.14.7.60','ops-ws-0060','operations','it-ops@example.corp','low','HQ-2F','Windows 11 Pro 23H2','2026-08-02T09:14:00Z'),
 ('dc-01','dc-01','core-identity','it-core@example.corp','critical','DC-East','Windows Server 2022','2026-08-02T11:50:00Z'),
 ('10.0.0.10','dc-01','core-identity','it-core@example.corp','critical','DC-East','Windows Server 2022','2026-08-02T11:50:00Z'),
 ('10.0.0.25','app-srv-0025','payments','it-payments@example.corp','high','DC-East','Ubuntu 24.04 LTS','2026-08-02T11:40:00Z');

-- ---- seed: users (privileged vs not, differing departments) ------------------
INSERT INTO users (user_id, display_name, department, manager, email, privileged, mfa_enrolled) VALUES
 ('jdoe','Jordan Doe','Finance','amorgan','jdoe@example.corp',false,true),
 ('amorgan','Alex Morgan','Finance','ceo','amorgan@example.corp',true,true),
 ('svc-backup','Backup Service Account','Operations','it-ops','svc-backup@example.corp',true,false);

-- ---- seed: IOCs (some malicious / suspicious / clean; verdict keyed on id) ---
INSERT INTO iocs (indicator, verdict, confidence, source) VALUES
 ('198.51.100.77','suspicious',0.72,'synthetic-ti'),
 ('10.14.7.32','clean',0.90,'synthetic-ti'),
 ('203.0.113.9','malicious',0.95,'synthetic-ti'),
 ('185.199.110.153','clean',0.83,'synthetic-ti'),
 ('evil.example.com','malicious',0.88,'synthetic-ti'),
 ('8.8.8.8','clean',0.99,'synthetic-ti');

-- ---- seed: runbook (keyword-searchable; steps as jsonb array) ----------------
INSERT INTO runbook (title, steps, attack_ref, source, keywords) VALUES
 ('Suspected Data Exfiltration — Initial Response',
  '["Confirm the outbound transfer volume and destination against baseline.","Isolate the source host from the network to arrest ongoing transfer.","Preserve volatile evidence (netflow, process list, open handles).","Enrich the destination indicator and check for related alerts.","Open an incident ticket and escalate to IR if exfiltration is confirmed."]',
  'TA0010 (Exfiltration)','synthetic-runbook','exfiltration data transfer outbound exfil upload'),
 ('Malware C2 Beacon — Containment',
  '["Confirm periodicity and destination of the beacon in netflow.","Block the C2 destination at the perimeter.","Isolate the beaconing endpoint and capture memory.","Identify the malware family from EDR and hunt for siblings.","Open an incident and begin eradication."]',
  'TA0011 (Command and Control)','synthetic-runbook','malware beacon c2 command control trojan'),
 ('Phishing Link Click — Triage',
  '["Confirm the destination URL reputation and mail gateway verdict.","Check whether credentials were entered on the phishing page.","Reset the affected user credentials if in doubt.","Scan the endpoint and review browser/download activity.","Report and close if no compromise is found."]',
  'TA0001 (Initial Access)','synthetic-runbook','phishing link click email credential url');
