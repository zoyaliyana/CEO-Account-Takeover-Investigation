# 🔐 CEO Account Takeover Investigation
![MITRE ATT&CK](https://img.shields.io/badge/-MITRE_ATT%26CK-C7252B?&style=for-the-badge&logoColor=white)

## Overview

This project documents a simulated SOC investigation into a CEO account takeover at Cloudora, a fictional B2B HR software company. Using KQL in Azure Data Explorer, I analysed authentication and audit logs to investigate suspicious sign-in activity, identify a password-spraying campaign, determine the scope of compromised accounts, and investigate attacker persistence.

The investigation identified two compromised accounts, including the CEO account, alongside 24 additional accounts targeted by password spraying. Further analysis identified attacker persistence through an unauthorised authentication method and a malicious inbox rule.

This project demonstrates practical skills in KQL, authentication log analysis, incident investigation, threat detection, scoping, MITRE ATT&CK mapping, and incident response documentation.
## Investigation Objectives

The investigation aimed to:

- Investigate suspicious sign-in activity associated with the CEO account.
- Determine whether the activity represented a genuine account compromise.
- Establish the scope of the password-spraying campaign.
- Identify any additional compromised or targeted accounts.
- Investigate audit logs for evidence of attacker persistence.
- Map the observed attacker behaviour to relevant MITRE ATT&CK techniques.
- Determine appropriate containment, remediation, and detection improvements.
- ## Tools & Data Sources

| Tool / Data Source | Purpose |
|---|---|
| Azure Data Explorer | Environment used to investigate the simulated security logs |
| KQL (Kusto Query Language) | Queried, filtered, summarised, and correlated security events |
| CloudoraSignIn_CL | Analysed authentication activity, failed sign-ins, successful sign-ins, IP addresses, locations, and affected accounts |
| CloudoraAudit_CL | Investigated account changes and persistence-related activity |
| MITRE ATT&CK | Mapped observed attacker behaviour to recognised techniques |
## Investigation Summary

The investigation began with suspicious sign-in activity associated with CEO Daniel Reeve's account. Analysis of the authentication logs identified repeated failed sign-in attempts from Lagos-based IP addresses within the `102.89.*` range, followed by successful authentication to Daniel's account.

Further analysis showed that the same infrastructure was conducting a wider password-spraying campaign. A total of 114 failed authentication attempts targeted 26 Cloudora accounts between 8 and 10 August 2026.

Two accounts were confirmed as compromised:

- **Daniel Reeve** — successful attacker-associated sign-ins followed by access to Microsoft 365, Outlook Web, and Azure Portal.
- **Priya Nair** — successful attacker-associated sign-ins followed by access to Microsoft 365 and SharePoint.

Audit-log analysis of Daniel's account also identified persistence activity, including the registration of a **Pixel 6 authentication method** and the creation of a malicious **RSS Subscriptions inbox rule** designed to hide finance and invoice-related emails.

The remaining 24 accounts were identified as targeted by the password-spraying campaign but were not confirmed as compromised from the available evidence.
## Key Findings

- Password-spraying activity affected 26 Cloudora accounts between 8–10 August 2026.
- Three attacker IP addresses generated 114 failed authentication attempts.
- Two accounts were confirmed compromised: Daniel Reeve and Priya Nair.
- Persistence was established on Daniel Reeve's account through a newly registered authentication method.
- A malicious inbox rule named `RSS Subscriptions` was created to move finance and invoice-related emails and mark them as read.
- 24 additional accounts were targeted but were not confirmed compromised based on the available evidence.
- Omar Farah's Dubai sign-in activity was investigated and found to be consistent with his established sign-in behaviour.
## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force: Password Spraying | T1110.003 | Repeated failed authentication attempts from `102.89.*` targeted multiple Cloudora accounts |
| Initial Access | Valid Accounts | T1078 | Successful attacker-associated sign-ins to Daniel Reeve and Priya Nair using compromised credentials |
| Persistence | Account Manipulation: Device Registration | T1098.005 | A Pixel 6 authentication method was registered to Daniel's account |
| Defense Evasion | Hide Artifacts: Email Hiding Rules | T1564.008 | The `RSS Subscriptions` inbox rule was created to hide finance and invoice-related emails |
- **Malicious inbox rule:** An `RSS Subscriptions` rule was created to move finance and invoice-related emails and mark them as read.
- **24 additional accounts targeted:** These accounts experienced password-spray attempts but were not confirmed as compromised from the available evidence.
- **False positive investigated:** Omar Farah's Dubai sign-ins were consistent with legitimate travel and normal account behaviour, although his account was also targeted by the password spray.
## Indicators of Compromise (IOCs)

| Indicator | Type | Significance |
|---|---|---|
| `102.89.44.17` | IP Address | Password-spray activity and Daniel Reeve account compromise |
| `102.89.44.23` | IP Address | Password-spray activity |
| `102.89.45.101` | IP Address | Password-spray activity and Priya Nair account compromise |
| Pixel 6 | Authentication Device | Unauthorised authentication method registered to Daniel's account |
| `RSS Subscriptions` | Inbox Rule | Malicious rule used to hide finance and invoice-related emails |
## KQL Investigation
### 1. Initial CEO Account Triage

I began by reviewing Daniel Reeve's authentication activity during the incident window to identify suspicious sign-in behaviour, including failed and successful authentication attempts, source IP addresses, and geographic locations.

```kusto
CloudoraSignIn_CL
| where UserPrincipalName == "daniel.reeve@cloudora.io"
| where TimeGenerated between (datetime(2026-08-10) .. datetime(2026-08-11))
| project TimeGenerated, AppDisplayName, IPAddress, City, Country, ResultType, ResultDescription
| order by TimeGenerated asc
```

**Finding:** The logs showed repeated failed authentication attempts from Lagos-based IP address `102.89.44.17`, followed by a successful Microsoft 365 sign-in at 03:12:05 UTC. Additional successful access to Outlook Web and Azure Portal followed from the same IP address, making the activity suspicious and requiring further investigation.

[View evidence screenshot](screenshots/01-ceo-suspicious-signins.png)
### 2. Password Spray Analysis

I expanded the investigation beyond the CEO account to determine whether the suspicious activity was part of a wider attack. I analysed failed authentication attempts to identify source IP addresses targeting multiple Cloudora accounts.

```kusto
CloudoraSignIn_CL
| where ResultType == "50126"
| summarize Failures=count(), TargetedAccounts=dcount(UserPrincipalName) by IPAddress, Country
| order by Failures desc
```

**Finding:** Three IP addresses in the `102.89.*` range generated a combined 114 failed authentication attempts:

- `102.89.44.17` — 48 failures targeting 23 accounts
- `102.89.45.101` — 38 failures targeting 20 accounts
- `102.89.44.23` — 28 failures targeting 18 accounts

The repeated failures across multiple accounts were consistent with a password-spraying campaign. Across the wider investigation, 26 unique Cloudora accounts were targeted.

[View evidence screenshot](screenshots/02-password-spray-analysis.png)

[View password-spray timeline](screenshots/03-password-spray-timeline.png)
### 3. Persistence Investigation

After confirming suspicious authentication activity, I analysed audit logs associated with the attacker infrastructure to determine whether any persistence mechanisms had been established.

```kusto
CloudoraAudit_CL
| where IPAddress startswith "102.89."
| project TimeGenerated, ActivityDisplayName, TargetUser, Details
| order by TimeGenerated asc
```

**Finding:** Two significant events were identified on Daniel Reeve's account:

- At **03:18:44 UTC**, a **Pixel 6 authentication method** was registered.
- At **03:31:09 UTC**, an **RSS Subscriptions inbox rule** was created to move finance and invoice-related emails and mark them as read.

These events showed that the attacker had established persistence on the compromised CEO account and attempted to conceal potentially sensitive finance-related email activity.

[View persistence evidence](screenshots/04-persistence-evidence.png)
### 4. Compromise Scoping

I then searched for successful authentication activity originating from the attacker-associated `102.89.*` infrastructure to determine which targeted accounts had evidence of successful compromise.

```kusto
CloudoraSignIn_CL
| where IPAddress startswith "102.89." and ResultType == "0"
| summarize by UserPrincipalName, IPAddress, TimeGenerated
| order by TimeGenerated asc
```

**Finding:** Five successful authentication events were identified from the attacker-associated infrastructure:

- **Daniel Reeve** — three successful events from `102.89.44.17`
- **Priya Nair** — two successful events from `102.89.45.101`

This established that Daniel Reeve and Priya Nair were the two accounts with successful attacker-associated authentication activity. The remaining targeted accounts were investigated separately and were not confirmed as compromised from the available evidence.

[View compromised-account scoping evidence](screenshots/05-compromised-account-scoping.png)
## Response & Remediation

Based on the investigation findings, the following containment and remediation actions were identified:

- Revoke active sessions and refresh tokens for Daniel Reeve and Priya Nair.
- Reset credentials for both compromised accounts.
- Remove the unauthorised Pixel 6 authentication method from Daniel's account.
- Delete the malicious `RSS Subscriptions` inbox rule.
- Review Priya Nair's MFA methods and mailbox rules for additional persistence.
- Force precautionary password resets for the remaining 24 targeted accounts.
- Block the identified attacker IP addresses through Conditional Access.
- Re-run authentication and scoping queries to verify that no new successful activity from the attacker infrastructure occurs.
## Recommendations

To reduce the likelihood and impact of similar identity-based attacks, the following security improvements were recommended:

- Require MFA for all users and disable legacy authentication where possible.
- Implement password-spray detection for repeated authentication failures across multiple accounts.
[View password-spray detection query](screenshots/06-password-spray-detection.png)
- Generate alerts for new MFA method registrations and suspicious inbox-rule creation, particularly for privileged and executive accounts.
- Review Conditional Access policies and apply stronger authentication controls to sign-ins from unexpected or high-risk locations.
- Require precautionary password resets for accounts targeted during confirmed password-spraying activity.
- Provide finance staff with business email compromise (BEC) awareness training and independently verify requests to change payment details.
