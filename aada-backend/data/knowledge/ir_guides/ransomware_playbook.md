# Incident Response Playbook: Ransomware

## Overview
Ransomware encrypts data and demands payment for the decryption key. Modern
operators also exfiltrate data first and threaten to leak it (double extortion).
Speed of containment is the single biggest factor in limiting damage.

## Detection Indicators
Mass file-rename or extension-change events, spikes in file-write throughput,
shadow-copy deletion (`vssadmin delete shadows`), disabled security tooling,
ransom notes appearing in many directories, and beaconing to known C2 prior to
encryption. Early precursors include brute-forced RDP/SSH, phishing, and
privilege escalation.

## Containment
Immediately isolate affected hosts from the network (disable switch ports or pull
network access) while keeping them powered on to preserve memory for forensics.
Disable compromised accounts and revoke their sessions. Block identified C2 IPs
and domains at the firewall. Segment to protect backups — confirm backups are
offline and intact before the attacker reaches them.

## Eradication
Identify the initial access vector and the ransomware family. Remove persistence
mechanisms, malicious binaries, and any created accounts. Patch the exploited
vulnerability. Reset all potentially exposed credentials, including service and
domain-admin accounts.

## Recovery
Restore data from known-clean offline backups after verifying the environment is
clean. Rebuild rather than clean badly compromised systems. Monitor restored
systems intensively for re-infection. Do not pay the ransom without legal and
executive sign-off; payment does not guarantee recovery and may violate sanctions.

## Lessons Learned
Add the observed TTPs and IOCs to detection. Close the initial access vector
(MFA on remote access, phishing-resistant auth, patch SLAs). Test backup restore
times against the recovery-time objective.
