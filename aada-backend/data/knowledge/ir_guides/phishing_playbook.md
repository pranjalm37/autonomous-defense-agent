# Incident Response Playbook: Phishing

## Overview
Phishing uses fraudulent messages to steal credentials, deliver malware, or
trick users into actions (wire fraud). It is the most common initial-access
vector and frequently precedes brute force, credential stuffing, and ransomware.

## Detection Indicators
User-reported suspicious emails, clicks on URLs flagged by threat intel,
credential entry on look-alike domains, mail from newly registered domains,
attachments with macros or double extensions, and a spike in failed logins
shortly after an email campaign.

## Containment
Quarantine the malicious message across all mailboxes (purge from the mail
platform). Block the sender, URLs, and domains. If credentials were entered,
immediately reset the affected user's password and revoke active sessions and
tokens. If an attachment was opened, isolate the endpoint and scan for malware.

## Eradication
Remove any dropped malware and persistence. Identify all recipients and which
ones interacted. Hunt for follow-on activity such as inbox rules that hide replies,
OAuth app consents granted, or mail-forwarding rules created by the attacker.

## Recovery
Restore affected accounts with new credentials and MFA. Re-enable access only
after verifying the endpoint and account are clean. Communicate with affected
users and, if needed, customers.

## Lessons Learned
Feed the sender/URL/domain IOCs into mail and web filtering. Run targeted
security-awareness training. Tighten controls: enforce MFA, block macros from the
internet, and deploy DMARC/DKIM/SPF to reduce spoofing.
