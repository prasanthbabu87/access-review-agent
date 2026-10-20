# User Access Review — FinanceERP

**As of:** 2026-09-30  
**Prepared:** 2026-10-19 21:09 by access-review-agent (AI-assisted, requires reviewer sign-off)

**Population:** 27 accounts (25 human, 2 service), 23 HR records. **Accounts flagged:** 13.

## 1. Checks performed

| Check | Description | Flagged |
|---|---|---:|
| `terminated_with_access` | Active application accounts belonging to employees terminated in HR | 3 |
| `orphan_accounts` | Human accounts with no matching HR record, and service accounts with no named owner | 3 |
| `sod_conflicts` | Accounts holding role combinations prohibited by the segregation of duties ruleset | 5 |
| `excess_privilege` | Roles not permitted for the user's department under the role matrix (least privilege) | 4 |
| `dormant_accounts` | Accounts with no login within the dormancy threshold | 3 |

## 2. Remediation decisions

High: **10** · Medium: **2** · Low: **1**

| Risk | Account | Action | Roles to remove | Rationale |
|---|---|---|---|---|
| High | `dnair` | revoke account | — | Employee terminated 2026-08-12 but account remains active. Login after termination - escalate to security as a potential incident. |
| High | `fali` | remove roles | GL_POSTER | SoD conflict (SOD-4); GL_POSTER not permitted for the user's department. |
| High | `jdsouza` | revoke account | — | Human account with employee ID E999 not found in HR; holds AP_CLERK. No accountable individual. |
| High | `kgeorge` | remove roles | VENDOR_MAINT | SoD conflict (SOD-1); VENDOR_MAINT not permitted for the user's department. |
| High | `miyer` | remove roles | PAY_APPROVER | SoD conflict (SOD-2); PAY_APPROVER not permitted for the user's department. |
| High | `nkumar` | review with manager | — | SoD conflict (SOD-3) between roles both permitted for the department; manager to split duties or document a compensating control. |
| High | `rjoseph` | revoke account | — | Employee terminated 2026-06-30 but account remains active. |
| High | `rmalhotra` | revoke account | — | Employee terminated 2026-09-05 but account remains active. |
| High | `svc_bankfeed` | review with manager | — | Service account has no accountable owner; holds PAY_APPROVER. Assign an accountable owner or disable. |
| High | `temp_admin` | revoke account | — | Human account with no employee ID; holds SYS_ADMIN, PAY_APPROVER. No accountable individual. |
| Medium | `averma` | remove roles | AP_CLERK | Account Manager in Sales holds AP_CLERK not permitted for the department. |
| Medium | `sdas` | review with manager | — | No login for 172 days (threshold 90); holds transactional roles - disable if no longer needed. |
| Low | `phegde` | review with manager | — | No login for 151 days (threshold 90); read-only access. |

## 3. Issue detail

- **`averma`**
  - excess_privilege: Account Manager in Sales holds AP_CLERK not permitted for the department
- **`dnair`**
  - terminated_with_access: Terminated 2026-08-12, account still active; LOGGED IN AFTER TERMINATION on 2026-09-02
- **`fali`**
  - sod_conflicts: SYS_ADMIN + GL_POSTER: Administrator can post transactions and alter logs
  - excess_privilege: Support Engineer in IT holds GL_POSTER not permitted for the department
- **`jdsouza`**
  - orphan_accounts: Human account with employee ID E999 not found in HR
- **`kgeorge`**
  - sod_conflicts: VENDOR_MAINT + PAY_APPROVER: Create a fictitious vendor and approve payment to it
  - excess_privilege: Treasury Manager in Finance-Treasury holds VENDOR_MAINT not permitted for the department
- **`miyer`**
  - sod_conflicts: AP_CLERK + PAY_APPROVER: Enter a fraudulent invoice and approve its payment
  - excess_privilege: AP Clerk in Finance-AP holds PAY_APPROVER not permitted for the department
- **`nkumar`**
  - sod_conflicts: GL_POSTER + GL_APPROVER: Post and approve own journal entries
- **`phegde`**
  - dormant_accounts: No login for 151 days (threshold 90)
- **`rjoseph`**
  - terminated_with_access: Terminated 2026-06-30, account still active
  - dormant_accounts: No login for 93 days (threshold 90)
- **`rmalhotra`**
  - terminated_with_access: Terminated 2026-09-05, account still active
- **`sdas`**
  - dormant_accounts: No login for 172 days (threshold 90)
- **`svc_bankfeed`**
  - orphan_accounts: Service account has no accountable owner
- **`temp_admin`**
  - orphan_accounts: Human account with no employee ID
  - sod_conflicts: SYS_ADMIN + PAY_APPROVER: Administrator can release payments and alter controls

## 4. Summary

13 of 27 accounts require action (10 High risk), including 5 account revocations. 3 terminated employees retained access (1 with a login after the termination date), pointing to a gap in the HR-to-IT leaver process. SoD conflicts and excess roles in payment and journal processes indicate role assignments are not checked against the role matrix at provisioning. Recommend automating leaver de-provisioning from the HR system and adding an SoD check to the access request workflow.

_Manager certification sheet: `certification.csv`._
