# Incident Report — CLD-IR-0001

## CEO Account Takeover and Password Spray Investigation

| Field | Details |
|---|---|
| Report ID | CLD-IR-0001 |
| Related Ticket | CLD-0001 |
| Analyst | Zoya Ali |
| Date of Report | 01 October 2026 |
| Severity | P1 |
| Status | Contained – eradication verified, monitoring continues |
| Environment | Simulated SOC Environment |

---

## Executive Summary

Between 8 and 10 August 2026, Cloudora was targeted by a password-spraying campaign that affected 26 employee accounts and resulted in the compromise of two users, including CEO Daniel Reeve and Priya Nair.

The incident was identified through suspicious sign-in activity and further investigation showed that the attacker had established persistence on Daniel's account by registering an additional authentication method and creating an inbox rule designed to hide finance and invoice-related emails.

The compromised accounts were contained, the identified persistence mechanisms were removed, and access from the known attacker infrastructure was blocked.

No evidence of data theft or fraudulent payment was identified in the available logs, although the activity created a significant risk of business email compromise and financial fraud.

The remaining 24 targeted accounts were identified for precautionary password resets and additional security controls were recommended to improve detection and reduce the risk of similar attacks.

---

## Incident Timeline

All times are in UTC.

| Time | Source | Event |
|---|---|---|
| 08 Aug 2026, 03:16:43 | CloudoraSignIn_CL | Password-spray activity targeted Priya Nair from Lagos-based attacker infrastructure. |
| 10 Aug 2026, 03:09:12–03:10:41 | CloudoraSignIn_CL | Two failed authentication attempts against Daniel Reeve from `102.89.44.17`. |
| 10 Aug 2026, 03:12:05 | CloudoraSignIn_CL | Successful Microsoft 365 authentication to Daniel Reeve's account from `102.89.44.17`. |
| 10 Aug 2026, 03:14:30 | CloudoraSignIn_CL | Outlook Web accessed using Daniel Reeve's compromised account. |
| 10 Aug 2026, 03:18:44 | CloudoraAudit_CL | A Pixel 6 authentication method was registered to Daniel Reeve's account. |
| 10 Aug 2026, 03:26:02 | CloudoraSignIn_CL | Azure Portal accessed using Daniel Reeve's compromised account. |
| 10 Aug 2026, 03:31:09 | CloudoraAudit_CL | `RSS Subscriptions` inbox rule created to move finance and invoice-related emails and mark them as read. |
| 10 Aug 2026, 03:44:55 | CloudoraSignIn_CL | Failed authentication attempt against Priya Nair from attacker-associated infrastructure. |
| 10 Aug 2026, 03:47:18 | CloudoraSignIn_CL | Successful authentication to Priya Nair's account from `102.89.45.101`. |
| 10 Aug 2026, 03:52:40 | CloudoraSignIn_CL | Successful SharePoint access from Priya Nair's compromised account. |
| 10 Aug 2026, 08:41 | CloudoraSignIn_CL | Successful London sign-in to Daniel Reeve's account from `203.0.113.11`. |
| 10 Aug 2026, 08:55 | Incident Ticket | Suspicious sign-in activity escalated for investigation. |
| 10 Aug 2026, ~10:30 | Incident Response | Compromised accounts contained and remediation actions initiated. |

---

## Scope & Impact

### Confirmed Compromised Accounts

Two accounts were confirmed as compromised:

| Account | Evidence |
|---|---|
| `daniel.reeve@cloudora.io` | Three successful attacker-associated authentication events from `102.89.44.17`, followed by persistence activity. |
| `priya.nair@cloudora.io` | Two successful attacker-associated authentication events from `102.89.45.101`. |

### Accounts Targeted but Not Confirmed Compromised

The password-spraying campaign targeted **26 unique Cloudora accounts**. After excluding the two confirmed compromised accounts, **24 accounts** had failed attacker-associated authentication attempts but were not confirmed as compromised from the available evidence.

The affected accounts were:

`alba.vega`, `amelia.frost`, `aria.reid`, `cole.burke`, `dina.said`, `emma.hayes`, `ethan.wells`, `freya.lynn`, `gwen.muir`, `isla.grant`, `joel.kerr`, `jude.ross`, `kian.patel`, `leah.stone`, `lena.voss`, `liam.doyle`, `mira.shah`, `nina.cole`, `omar.farah`, `rhys.owen`, `ruth.dean`, `ryan.boyd`, `seth.lane`, and `sofia.marino` — all `@cloudora.io`.

### False Positive Investigation

Omar Farah's Dubai sign-ins were investigated and assessed as consistent with legitimate travel and normal account behaviour.

His account remained within the 24 targeted accounts because it also received password-spray attempts.

---

## Indicators of Compromise

| Indicator | Type | Significance |
|---|---|---|
| `102.89.44.17` | IP Address | Password-spray activity and successful compromise of Daniel Reeve |
| `102.89.44.23` | IP Address | Password-spray activity |
| `102.89.45.101` | IP Address | Password-spray activity and successful compromise of Priya Nair |
| Pixel 6 | Authentication Method | Unauthorised authentication method registered to Daniel Reeve |
| `RSS Subscriptions` | Inbox Rule | Rule used to hide finance and invoice-related emails |

---

## Attack Analysis

Analysis of failed authentication activity identified three attacker-associated IP addresses:

| IP Address | Failed Attempts | Targeted Accounts |
|---|---:|---:|
| `102.89.44.17` | 48 | 23 |
| `102.89.45.101` | 38 | 20 |
| `102.89.44.23` | 28 | 18 |

Across the three IP addresses, **114 failed authentication attempts** were recorded.

The campaign targeted **26 unique Cloudora accounts** between 8 and 10 August 2026.

Successful authentication activity from the same infrastructure established that Daniel Reeve and Priya Nair were compromised.

---

## Persistence Activity

Following the successful compromise of Daniel Reeve's account, two persistence-related events were identified.

At **03:18:44 UTC**, a **Pixel 6 authentication method** was registered to Daniel's account.

At **03:31:09 UTC**, an **RSS Subscriptions inbox rule** was created. The rule moved finance and invoice-related emails to RSS Feeds and marked them as read.

No persistence-related audit events were identified for Priya Nair in the available audit data.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force: Password Spraying | T1110.003 | Repeated failed authentication attempts across multiple Cloudora accounts |
| Initial Access | Valid Accounts | T1078 | Successful attacker-associated authentication to Daniel Reeve and Priya Nair |
| Persistence | Account Manipulation: Device Registration | T1098.005 | Pixel 6 authentication method registered to Daniel Reeve |
| Defense Evasion | Hide Artifacts: Email Hiding Rules | T1564.008 | `RSS Subscriptions` inbox rule used to conceal finance and invoice-related emails |

---

## Response & Remediation

The following response actions were documented for the simulated incident:

1. Revoked active sessions and refresh tokens for Daniel Reeve and Priya Nair.
2. Reset credentials for both confirmed compromised accounts.
3. Removed the unauthorised Pixel 6 authentication method from Daniel Reeve's account and reviewed Priya Nair's authentication methods.
4. Deleted the malicious `RSS Subscriptions` inbox rule and reviewed both mailboxes for additional suspicious rules.
5. Blocked `102.89.44.17`, `102.89.44.23`, and `102.89.45.101` through Conditional Access / named locations.
6. Re-ran authentication and scoping queries following containment and forced re-authentication on both compromised accounts.

---

## Detection Improvement

A password-spray detection rule was developed to identify IP addresses generating more than **10 failed authentication attempts across more than 10 unique accounts within a six-hour window**.

Historical analysis showed that this logic would have identified suspicious activity on **8 August 2026**, before the confirmed account compromises on 10 August.

---

## Recommendations

| Priority | Recommendation |
|---|---|
| High | Force password resets for the 24 targeted but not confirmed compromised accounts. |
| High | Require multi-factor authentication for all users and disable legacy authentication where possible. |
| High | Alert on new authentication method registrations and suspicious inbox-rule creation, particularly for executive accounts. |
| High | Deploy password-spray detection based on failed authentication attempts across multiple accounts. |
| Medium | Review Conditional Access policies and apply stronger authentication controls to unexpected or high-risk locations. |
| Medium | Brief finance staff on business email compromise risks and independently verify requests to change payment details. |

---

## Investigation Outcome

The investigation confirmed a password-spraying campaign affecting 26 Cloudora accounts.

Two accounts — Daniel Reeve and Priya Nair — showed successful attacker-associated authentication activity and were confirmed as compromised. Persistence was identified on Daniel Reeve's account through an unauthorised authentication method and malicious inbox rule.

The remaining 24 accounts were targeted but were not confirmed as compromised from the available evidence.

The incident was contained, persistence mechanisms were removed, known attacker infrastructure was blocked, and additional security improvements were recommended.
