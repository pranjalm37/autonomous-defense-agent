# NIST SP 800-61r2 — Computer Security Incident Handling Guide (Summary)

## Incident Response Life Cycle
NIST defines a four-phase incident response life cycle. The phases are iterative:
lessons from one incident feed back into preparation for the next.

## Preparation
Preparation establishes the capability to respond before an incident occurs. It
covers building the incident response team, defining communication channels and
escalation paths, provisioning tooling (SIEM, EDR, forensic kits, jump bags), and
hardening systems to reduce the number of incidents. A current asset inventory,
network diagrams, and baselines of normal behavior are prerequisites for fast
triage. Preparation also includes training and tabletop exercises.

## Detection and Analysis
Detection and analysis is the hardest phase. Signs of an incident come from
precursors (signs an incident may occur, e.g. recon scanning) and indicators
(signs an incident has occurred, e.g. antivirus alerts, failed-login bursts,
anomalous outbound traffic). Analysts validate alerts, scope the incident, and
prioritize by functional impact, information impact, and recoverability. Accurate,
time-synchronized logging and a documented baseline are essential. Every incident
should be assigned a severity and an owner, and all evidence handled to preserve
chain of custody.

## Containment, Eradication, and Recovery
Containment limits damage before it spreads — for example isolating a host from
the network, disabling a compromised account, or blocking a malicious IP.
Containment strategy balances the need to stop the attacker against the need to
preserve evidence and avoid tipping off the adversary. Eradication removes the
root cause: deleting malware, closing the exploited vulnerability, and resetting
affected credentials. Recovery restores systems to normal operation, validates
they are clean, and monitors closely for signs the attacker returns. Decisions
during this phase should be documented with timestamps for the after-action report.

## Post-Incident Activity
After recovery, the team holds a lessons-learned meeting to ask what happened,
how well the team performed, what could be improved, and what indicators should be
added to detection. The output updates playbooks, detection rules, and
preparation. Metrics such as time-to-detect and time-to-contain track program
maturity over time.

## Prioritization
NIST recommends prioritizing incidents by impact rather than first-come-first-served.
Functional impact (effect on business operations), information impact
(confidentiality/integrity of data), and recoverability (effort to recover)
combine into an overall priority that drives response order and resource allocation.
