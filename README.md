# AWS Control Tower Pre-Upgrade Precheck

![AWS](https://img.shields.io/badge/AWS-Control%20Tower-orange)
![Language](https://img.shields.io/badge/python-3.9%2B-blue)
![Access](https://img.shields.io/badge/access-read--only_by_default-brightgreen)
![License](https://img.shields.io/badge/license-MIT--0-green)

> **Disclaimer:** This code is provided as-is to demonstrate a concept or workflow for AWS
> customers. You are responsible for ensuring it meets your requirements and for thoroughly
> reviewing and testing it in a sandbox environment before running it against production.

A **read-only** command-line tool that you run **before** updating, repairing, or resetting an
AWS Control Tower landing zone. It confirms the environment is in a known-good state and reports
the issues, drift, out-of-band changes, and customizations that can interfere with a
landing-zone update — **so you can fix them first and reduce failed upgrades.**

Some checks map directly to a documented cause of update failure: AWS Control Tower names
[three](https://docs.aws.amazon.com/controltower/latest/userguide/troubleshooting.html)
(prerequisites not met, AWS Config resources in the Security OU accounts, and closed accounts
that still hold a provisioned product), plus the
[version 4.0 prerequisites](https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html).
The remaining checks are health and readiness conditions that are documented as drift or as
repair scenarios, but are **not** documented as blocking an update — they are included because
they are worth knowing before you start, and their severities reflect that distinction. See
[What it checks](#what-it-checks) for the per-check severity model and
[Limitations and scope](#limitations-and-scope).

Updating a landing zone is meant to be routine, but
[AWS Control Tower does not roll back to a previous landing zone version if an update fails](https://docs.aws.amazon.com/controltower/latest/userguide/troubleshooting.html)
— you may find your landing zone in an indeterminate state, and need AWS Support to recover it.
Most failures are caused by a small set of *detectable* preconditions (drift, suspended accounts
with orphaned resources, lingering AWS Config resources, custom StackSet instances in new Regions,
and so on). This tool checks for those preconditions and gates the upgrade with a non-zero exit
code when it finds a blocker.

## Table of Contents

- [Overview](#overview)
- [What it checks](#what-it-checks)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Sample output](#sample-output)
- [How it works](#how-it-works)
- [Limitations and scope](#limitations-and-scope)
- [FAQs](#faqs)
- [Security](#security)
- [Notices](#notices)
- [License](#license)

## Overview

The tool runs from the **AWS Control Tower management account** in the **home Region** and
performs a series of `List*` / `Get*` / `Describe*` / `Search*` calls. It:

- Verifies landing-zone health and **drift** status.
- Confirms whether an update is actually pending, and the version delta.
- Inspects **managed accounts**, **enabled controls**, and **enabled baselines** (including child
  accounts) for drift or non-successful states.
- Detects the **out-of-band changes** and **orphaned resources** that block updates.
- Flags **customizations** (CfCT, AFT, custom StackSets) you must account for.

Every finding is classified as one of:

| Level | Meaning |
|-------|---------|
| `BLOCKER` | Must be resolved before upgrading. Causes a non-zero exit code. |
| `WARNING` | Should be reviewed; may cause partial or downstream issues. |
| `UNKNOWN` | Could **not** be verified (missing permission or API error). Never assumed good. |
| `INFO` | Informational (e.g. customizations, version delta). |
| `PASS` | Verified good. |

## What it checks

Each check maps to a documented cause of landing-zone update failure or drift.

| # | Check | Detects | Data source (read-only) | Default severity |
|---|-------|---------|-------------------------|------------------|
| 1 | Landing zone status | `FAILED` / `PROCESSING` / mid-operation | `controltower:GetLandingZone` | BLOCKER |
| 2 | Landing zone drift | [Landing-zone drift specifically](https://docs.aws.amazon.com/controltower/latest/userguide/governance-drift.html): IAM role drift, or organizational drift affecting Foundational OUs and shared accounts (deleted Foundational OU, trusted access disabled, audit / log archive account moved or removed). Most of these make Control Tower unusable until resolved. A managed-SCP modification is *account and OU* governance drift, not landing-zone drift, and is reported by checks 6 and 17 instead | `controltower:GetLandingZone` (`driftStatus`) | BLOCKER |
| 3 | Update availability | Version currency and delta | `controltower:GetLandingZone` (`version`, `latestAvailableVersion`) | INFO |
| 4 | Managed accounts | `SUSPENDED` accounts in the org | `organizations:ListAccounts` | WARNING |
| 5 | Orphaned provisioned products | Suspended account still holding an Account Factory product (→ `AWSControlTowerExecution` can't be assumed) | `organizations:ListAccounts` + `servicecatalog:SearchProvisionedProducts` | BLOCKER |
| 6 | Enabled controls drift | Drifted / non-`SUCCEEDED` controls across every registered OU. WARNING, not a blocker: control drift is a [repairable change](https://docs.aws.amazon.com/controltower/latest/userguide/drift.html), absent from the documented list of drift to resolve right away, and resolved with `ResetEnabledControl` or by re-registering the OU | `organizations` (OU discovery) + `controltower:ListEnabledControls` | WARNING |
| 7 | Enabled baselines drift | Drifted / non-`SUCCEEDED` baselines. Severity depends on the target: a service-integration account (management / Audit / Log archive) is a BLOCKER because a landing-zone update acts on it; a member account or OU is a WARNING, because [enrolled accounts are updated separately](https://docs.aws.amazon.com/controltower/latest/userguide/update-existing-accounts.html) and that is repairable drift. `Not Applicable` / `Not Enabled` are [expected in 4.0](https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html) and never reported | `controltower:ListEnabledBaselines` (`includeChildren=true`) | BLOCKER / WARNING |
| 8 | StackSet health | `AWSControlTower*` stack instances INOPERABLE/FAILED. Only **shared-account** (mgmt/audit/log-archive) instances block; **member-account** instances are WARNING; instances for **departed accounts** are INFO. OUTDATED is INFO (normal before an update). Failures on `AWSControlTowerExecutionRole` never block in any account: the role is usually created with the account by AWS Organizations, so a failed instance is expected and does not show the role is missing — use `--check-member-roles` to test that properly. **DRIFTED** is reported separately as a WARNING, because [drift is resolved as part of the update](https://docs.aws.amazon.com/controltower/latest/userguide/resolve-drift.html) on 3.1+ and StackSet resource drift is not one of [drift.html](https://docs.aws.amazon.com/controltower/latest/userguide/drift.html)'s resolve-right-away types | `cloudformation:ListStackSets` / `ListStackInstances` | BLOCKER / WARNING / INFO |
| 9 | AWS Config in shared accounts | Config recorders **or delivery channels** in Audit & Log Archive (across governed Regions) that Control Tower did not create — identified by name (`aws-controltower-*`), so a **single** pre-existing customer recorder in a newly governed Region is caught | `sts:AssumeRole` + `config:DescribeConfigurationRecorders` / `DescribeDeliveryChannels` | WARNING |
| 10 | Customizations | CfCT / AFT / custom StackSets targeting governed Regions | `cloudformation` / `organizations` | INFO |
| 11 | Trusted access | Required Organizations trusted service access disabled | `organizations:ListAWSServiceAccessForOrganization` | BLOCKER |
| 12 | Delegated administrators | Conflicting delegated admins (CFN StackSets / Config) | `organizations:ListDelegatedAdministrators` / `ListDelegatedServicesForAccount` | INFO |
| 13 | Required IAM roles | Missing core CT management-account service roles (all versions), and the org Config aggregator role on LZ < 4.0. The CloudTrail role's managed policy is a separate 4.0 prerequisite — see check 28 | `iam:GetRole` | BLOCKER |
| 14 | KMS key requirements | Landing-zone customer-managed key failing any of Control Tower's [documented pre-check requirements](https://docs.aws.amazon.com/controltower/latest/userguide/configure-kms-keys.html) that a single `DescribeKey` can decide: **Enabled**, **Symmetric**, **not a multi-Region key**, and **in the management account**. Control Tower does not support asymmetric or multi-Region keys at all. The fifth requirement, the key policy, is check 24 | `kms:DescribeKey` | BLOCKER |
| 15 | STS regional activation | STS deactivated in a governed Region (update fails midway) | `sts:GetCallerIdentity` (per Region) | BLOCKER |
| 16 | SCP headroom | Target at/near the 10-SCP limit + custom SCP inventory | `organizations:ListPoliciesForTarget` | WARNING |
| 17 | SCP blocking content | `FullAWSAccess` detached; a custom `Deny` on a service Control Tower acts on **inside member accounts** (`cloudformation`, `cloudtrail`, `config`, `events`, `iam`, `lambda`, `logs`, `s3`, `sns`) without an `AWSControlTowerExecution` exemption; a `Deny` on `Action: "*"` or using `NotAction`, which cannot be evaluated by action; Region restriction via SCP. Severity follows **which actions** are denied, not merely whether the statement names the Control Tower role — a `Deny` touching none of those services is not reported, including `Deny controltower:*`, because those are management-account control-plane calls and [SCPs never apply to the management account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) | `organizations:ListPoliciesForTarget` / `DescribePolicy` | WARNING |
| 18 | In-progress StackSet operations | `RUNNING`/`STOPPING`/`QUEUED` operation on an `AWSControlTower*` StackSet (conflicts with the update) | `cloudformation:ListStackSetOperations` | BLOCKER |
| 19 | Foundational StackSets present | Core `AWSControlTower*` StackSets entirely **missing** (broken / partially-deleted landing zone — repair, don't upgrade) | `cloudformation:ListStackSets` | WARNING |
| 20 | Account Factory product health | Provisioned products in `ERROR`/`TAINTED` (inconsistent account — cannot update via Account Factory, can block controls on its OU; account-re-baselining issue, not an LZ-update blocker) or `UNDER_CHANGE`/`PLAN_IN_PROGRESS` (mid-flight) | `servicecatalog:SearchProvisionedProducts` | WARNING |
| 21 | Upgrade-path considerations | Version-specific changes on the path from the deployed version to the target. For 4.0: the CloudTrail managed-policy prerequisite, the Security OU no longer being created, integrations becoming optional with baseline dependencies, the AWS Config scope change, drift notifications moving to EventBridge, and `CentralizedLogging` disable deleting logging-account resources | Version comparison only — no additional API calls | INFO |
| 22 | Service-integration accounts share one parent OU | Landing zone 4.0 [requires all accounts configured for each service integration to be under the same parent OU](https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html) — that OU becomes the designated Security OU, so a split across OUs is an unsupported layout. Evaluated when 4.0+ is deployed or available; explicitly disabled integrations are skipped, since a disabled integration names no account to place | `organizations:ListParents` | WARNING |
| 23 | Service-integration dependencies | Landing zone 4.0 integrations are individually switchable but not independent. [Disabling AWS Config requires also disabling Security Roles, Access Management and Backup](https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-launch.html), and the [baseline dependency graph](https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html) additionally makes Access Management and Backup depend on Security Roles. A contradictory manifest is rejected. `centralizedLogging` is independent in both directions. Only an explicit `enabled: false` triggers a rule, so a pre-4.0 manifest with no flags never fires | Manifest only — no API call | WARNING |
| 24 | IAM Identity Center Region | The [documented prerequisite](https://docs.aws.amazon.com/controltower/latest/userguide/getting-started-prereqs.html) that Identity Center sits in the landing zone home Region, and prerequisites apply to an update as well as a launch. `us-east-1` is never flagged — Control Tower uses an instance there regardless of home Region. Searches the home Region, then `us-east-1`, then the remaining governed Regions; finding the instance elsewhere is the only proof of a real mismatch. No instance anywhere is INFO, not a finding, since an organization without Identity Center is valid | `sso:ListInstances` (per Region) | WARNING |
| 25 | Baseline target OU still exists | An enabled baseline whose target OU is no longer present in AWS Organizations — what you get when an OU is deleted in Organizations without being deregistered from Control Tower first. A later landing-zone update reads the policies attached to each OU it knows about, fails with `TargetNotFoundException` on the missing one, and leaves the landing zone `FAILED`, which then also blocks registering OUs and enabling controls. The stale reference is cleared on the Control Tower side, so retrying does not help | `controltower:ListEnabledBaselines` (`includeChildren=true`) + `organizations:ListOrganizationalUnitsForParent` | WARNING |
| 26 | Foundational OU structure | Three of the four drift types [drift.html](https://docs.aws.amazon.com/controltower/latest/userguide/drift.html) says to resolve right away. **Shared accounts split across OUs or sitting at root** (WARNING — the documented remediation is itself a landing-zone update); **a foreign account inside the Foundational OU**, which Control Tower's update validator rejects outright with *"the Security OU contains accounts other than the shared accounts"* (BLOCKER); **no Additional OU** at all, when *"at least one Additional OU is required for AWS Control Tower to operate"* (WARNING). The Foundational OU is identified by where the shared accounts live, never by name, since renaming it is permitted and on 4.0 the OU holding the service-integration accounts becomes the Security OU. The foreign-account test is skipped, and says so, when any service integration is disabled: a disabled integration names no account while its account usually still sits in that OU | `organizations:ListParents` / `ListAccountsForParent` / `ListOrganizationalUnitsForParent` | BLOCKER / WARNING / INFO |
| 27 | Governed Region availability | A governed Region that is not enabled for this account. Observed blocking a landing-zone update. WARNING rather than BLOCKER because opt-in status is only one reason a Region can be unusable — a service-side regional event can block an update while every Region still reports enabled, and that is not visible from the account | `account:ListRegions` | WARNING |
| 28 | CloudTrail role managed policy | Only when an upgrade into 4.0 is available: whether `AWSControlTowerCloudTrailRole` uses the AWS managed policy `AWSControlTowerCloudTrailRolePolicy` rather than the legacy inline policy, which [updating to 4.0 via the API requires](https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html). Skipped when the landing zone is already 4.0+, and a missing role is left to check 13 | `iam:ListAttachedRolePolicies` | WARNING |
| 29 | Log Archive S3 bucket state | Three conditions on the `aws-controltower-*` buckets in the Log Archive account. **Requester Pays** is a documented precondition — ["be sure that the Amazon S3 logging bucket for the Log Archive account does not have the Requester Pays feature enabled ... before you begin the Update or Reset process"](https://docs.aws.amazon.com/controltower/latest/userguide/configuration-updates.html) (BLOCKER). **S3 Object Lock with a default retention rule**, which AWS Config cannot deliver to, so the delivery channel and the Config baseline stack fail with `InsufficientDeliveryPolicyException` (BLOCKER); the flag on its own is a WARNING, since it cannot be turned off again and a reset reuses the persisted bucket name. **A logging-StackSet bucket carrying no `aws:cloudformation:*` tag**, which suggests it exists outside StackSet control and will fail `AlreadyExists` when the StackSet tries to create it (WARNING — tags can also be removed by hand). Requires the precheck role in the Log Archive account; reports UNKNOWN without it | `s3:ListAllMyBuckets` / `GetBucketLocation` / `GetBucketRequestPayment` / `GetBucketObjectLockConfiguration` / `GetBucketTagging` | BLOCKER / WARNING |
| 30 | Control target OU still exists | An enabled control whose target OU is no longer present in AWS Organizations. Deleting an OU without first [deregistering it from Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/remove-ou.html) leaves Control Tower holding a reference to an OU that is gone; an update enabling mandatory controls has been seen to fail on exactly that, with `ParentNotFoundException` naming the deleted OU and the landing zone left `FAILED`. Check 8 cannot see these, because it asks what is enabled on each OU that *exists*; this one lists every enabled control and checks the target it holds. WARNING rather than blocker: AWS has stated the service-side handling of this case is fixed, so the stale reference is worth clearing but is not a demonstrated hard failure | `controltower:ListEnabledControls` (no target filter) | WARNING |
| 31 | Foundational OU is not nested | On landing zone 4.0+ Control Tower resolves the foundational OU from where the service-integration accounts sit, then rejects the operation if that OU is nested under another OU instead of sitting directly under the organization root ([4.0 key changes](https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html)). Check 26 covers the opposite error, those accounts left at the root. Because the rejection happens during input validation the update never starts, so no partial state is left behind - which is why this is a blocker rather than a warning. Skipped when 4.0 is neither deployed nor available, since the requirement arrived with 4.0 | `organizations:ListParents`, `organizations:ListOrganizationalUnitsForParent` | BLOCKER |

**Opt-in deeper checks** (off by default — slower or heuristic; enable with a flag):

| Flag | Check | Detects | Data source | Default severity |
|------|-------|---------|-------------|------------------|
| `--detect-drift` | Active StackSet drift | Actually runs CloudFormation drift detection on `AWSControlTower*` StackSets and reports **DRIFTED** instances with the drifted resource(s); without it, stored `DriftStatus` is only as fresh as the last run (often `NOT_CHECKED`). `--drift-timeout` (default 900s) is one budget **shared across all StackSets**, not a per-StackSet allowance: when it runs out no further detections are started, and the StackSets not reached are reported as `not_started` rather than as timeouts. Detections already running are left to finish on their own and are named in the finding | `cloudformation:DetectStackSetDrift` / `DescribeStackSetOperation` / `DescribeStackResourceDrifts` | WARNING |
| `--check-member-roles` | Member execution-role sweep | Assumes into every enrolled account to confirm `AWSControlTowerExecution` exists/assumable (missing = role drift → LZ can become unavailable) | `sts:AssumeRole` per account | WARNING |
| `--check-kms-policy` | KMS key-policy | Landing-zone CMK key policy does not grant CT's `config`/`cloudtrail` service principals (heuristic) | `kms:GetKeyPolicy` | WARNING |
| `--check-orphaned-resources` | Recreate-collision scan | **When the LZ looks broken** (FAILED or a foundational StackSet missing), scans the shared accounts for baseline-created resources that still exist even though the StackSet that manages them is gone (IAM roles, Config recorder/delivery channel, SNS topics, CloudWatch log groups, `NotificationForwarder` Lambda, `ConfigComplianceChangeEventRule`, `BaselineCloudTrail`, `aws-controltower-*` S3 buckets) — these collide (`already exists`) when Repair/Reset recreates them | `sts:AssumeRole` + (in shared accounts) `iam:GetRole`, `config:DescribeConfigurationRecorders`/`DescribeDeliveryChannels`, `sns:ListTopics`, `logs:DescribeLogGroups`, `lambda:GetFunction`, `events:ListRules`, `cloudtrail:DescribeTrails`, `s3:ListAllMyBuckets` | WARNING |

> **Severity model.** Only issues in the **shared accounts** (management, log archive, audit) and
> org-level configuration **hard-block** the landing-zone update. The same issue in a **member**
> account is a **WARNING**, because a landing-zone update/repair/reset acts on the shared accounts
> and org config first — member accounts are re-baselined separately (via *Re-register OU*). With
> `--detect-drift`, active drift detection owns `DRIFTED` reporting and the stored-status check
> defers to it (no double-counting). Drift itself is a **WARNING** wherever it is found: it is
> repairable, and an update resolves it — which is also why it is worth reviewing first, since the
> update resolves drift by reasserting Control Tower's intent over your out-of-band change.

The core CT management-account IAM roles verified by check #13 are required on **every** landing
zone version: `AWSControlTowerAdmin`, `AWSControlTowerCloudTrailRole`, and
`AWSControlTowerStackSetRole`. The organization AWS Config aggregator role
`AWSControlTowerConfigAggregatorRoleForOrganizations` is required **only on landing zone versions
below 4.0** — in 4.0+ the AWS Config integration is optional and the aggregator is service-linked,
so its absence is expected and is **not** treated as a blocker (see the [v4 Config updates](https://docs.aws.amazon.com/controltower/latest/userguide/config-updates-v4.html)).

Additionally, when an upgrade to landing zone **4.0+** is available (deployed version below 4.0),
the tool verifies that `AWSControlTowerCloudTrailRole` uses the AWS managed policy
`AWSControlTowerCloudTrailRolePolicy` rather than the legacy inline policy — a documented 4.0
upgrade prerequisite ([key changes for v4](https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html)).
If it does not, the tool emits a WARNING (not a blocker).

## Prerequisites

- Python 3.9+ and `boto3` (see [`requirements.txt`](requirements.txt)). `boto3` itself requires
  Python 3.9 or later, so 3.8 is not supported.
- Credentials for the **Control Tower management account**, used in the **home Region**.
- A read-only permission set covering the actions in the table above. Minimum policy:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "ReadOnlyPrecheck",
        "Effect": "Allow",
        "Action": [
          "controltower:ListLandingZones",
          "controltower:GetLandingZone",
          "controltower:ListEnabledControls",
          "controltower:ListEnabledBaselines",
          "organizations:DescribeOrganization",
          "organizations:ListRoots",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:ListParents",
          "organizations:ListAccounts",
          "organizations:ListAccountsForParent",
          "organizations:ListPoliciesForTarget",
          "organizations:DescribePolicy",
          "organizations:ListAWSServiceAccessForOrganization",
          "organizations:ListDelegatedAdministrators",
          "organizations:ListDelegatedServicesForAccount",
          "servicecatalog:SearchProvisionedProducts",
          "cloudformation:ListStackSets",
          "cloudformation:ListStackInstances",
          "cloudformation:ListStacks",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketRequestPayment",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetObjectLockConfiguration",
          "s3:GetBucketTagging",
          "cloudformation:ListStackSetOperations",
          "sso:ListInstances",
          "account:ListRegions",
          "sts:GetCallerIdentity"
        ],
        "Resource": "*"
      },
      {
        "Sid": "ControlTowerRoleReads",
        "Effect": "Allow",
        "Action": ["iam:GetRole", "iam:ListAttachedRolePolicies"],
        "Resource": "arn:aws:iam::*:role/AWSControlTower*"
      },
      {
        "Sid": "LandingZoneKeyReads",
        "Effect": "Allow",
        "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
        "Resource": "<landing-zone-cmk-arn>"
      },
      {
        "Sid": "CrossAccountReadOnlyChecks",
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::*:role/AWSControlTowerExecution"
      },
      {
        "Sid": "OptInActiveDriftDetectionOnly",
        "Effect": "Allow",
        "Action": [
          "cloudformation:DetectStackSetDrift",
          "cloudformation:DescribeStackSetOperation"
        ],
        "Resource": "arn:aws:cloudformation:*:*:stackset/AWSControlTower*:*"
      }
    ]
  }
  ```

  Notes on this policy:

  - The last statement, `OptInActiveDriftDetectionOnly`, is needed **only** if you use
    `--detect-drift`. `DetectStackSetDrift` is state-changing (it starts a StackSet operation), so
    omit this statement entirely for a strictly read-only role.
  - `iam:*`, `kms:*` and `sts:AssumeRole` are scoped by resource rather than `*`. Replace
    `<landing-zone-cmk-arn>` with your landing zone's CMK ARN, or drop that statement if your
    landing zone does not use a customer-managed key.
  - The cross-account checks additionally need, **in the shared/member accounts** via the assumed
    role: `cloudformation:DescribeStackResourceDrifts`, `config:DescribeConfigurationRecorders`,
    `config:DescribeDeliveryChannels`, `iam:GetRole`, `sns:ListTopics`,
    `logs:DescribeLogGroups`, `lambda:GetFunction`, `events:ListRules`,
    `cloudtrail:DescribeTrails`, `s3:ListAllMyBuckets` and `sts:GetCallerIdentity`.

- (Optional, for check #9) A role assumable in the Audit and Log Archive accounts. The tool
  defaults to `AWSControlTowerExecution`, which the management account can already assume. If that
  role is unavailable, the check reports `UNKNOWN` rather than failing.

## Installation

```bash
git clone <your-fork-url> sample-controltower-upgrade-precheck
cd sample-controltower-upgrade-precheck
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# From the management account, home Region (uses ambient credentials/role):
python3 Source/ct_preupgrade_precheck.py

# Explicit Region / named profile:
python3 Source/ct_preupgrade_precheck.py --region us-east-1 --profile my-mgmt-admin

# Emit a JSON report and also fail on WARNING (UNKNOWN already fails by default):
python3 Source/ct_preupgrade_precheck.py --json report.json --strict

# Fallback only: force the shared account ids when the manifest lookup is unavailable
python3 Source/ct_preupgrade_precheck.py \
    --audit-account 111111111111 --log-archive-account 222222222222

# Deeper scan — the opt-in checks compose, and are slower. Each one is described in
# "What it checks" above, with the APIs it calls and the severity it reports.
python3 Source/ct_preupgrade_precheck.py \
    --detect-drift --check-member-roles --check-kms-policy

# On a landing zone that looks broken: find leftovers that collide on Repair/Reset
python3 Source/ct_preupgrade_precheck.py --check-orphaned-resources

# Full flag reference, including the --color modes described below
python3 Source/ct_preupgrade_precheck.py --help
```

The text report is color-coded by severity (BLOCKER red, WARNING yellow, UNVERIFIED magenta,
INFO cyan, PASS green), with `[X]`/`[!]`/`[?]`/`[i]`/`[OK]` markers kept as an accessible,
color-independent fallback. Color is applied only when the output is an interactive terminal
(`--color auto`, the default); it is suppressed automatically when the output is piped or
redirected, when `--color never` is used, or when the `NO_COLOR` environment variable is set. The
`--json` report is never colorized.

A run makes hundreds of API calls and takes one to three minutes on a large organization, so it
prints its progress — a count of checks completed — to **stderr** while it works. The report
itself goes to stdout, so piping, redirecting and `--json` are unaffected; redirect stderr to
`/dev/null` if you want the progress gone.

### Exit codes (for pipeline gating)

| Code | Meaning |
|------|---------|
| `0` | No blockers, **and every check ran**. Review any warnings. |
| `2` | One or more blockers — **do not upgrade** until resolved — **or** one or more checks could not be evaluated (`UNKNOWN`). |
| `3` | The precheck could not run, so **no verdict was reached** — no landing zone in this account/Region, or an authentication or setup problem. The report says so explicitly rather than reporting a blocker. |

`UNKNOWN` counts toward exit `2` deliberately. A check that could not run is not evidence that the
environment is safe, and a landing-zone update is not something to start on an unverified report.
Two flags adjust this:

| Flag | Effect |
|------|--------|
| `--allow-unknown` | Exit `0` even when checks could not be evaluated. Use this only if you accept proceeding on an unverified report. |
| `--strict` | Also fail on `WARNING`. Off by default, because a warning means reviewed-and-not-blocking — for example drifted StackSet instances in member accounts, which do not block a landing-zone update. |

Gate an upgrade runbook simply:

```bash
python3 Source/ct_preupgrade_precheck.py || { echo "Precheck failed"; exit 1; }
```

## Sample output

```
==============================================================================
AWS Control Tower — Pre-Upgrade Precheck
  Management account : 123456789012
  Home region        : us-east-1
  Landing zone       : v3.3 (latest 4.0)
  Governed regions   : us-east-1, us-west-2
==============================================================================

[X] BLOCKER  (2)
------------------------------------------------------------------------------
  [X] Landing zone is DRIFTED (out-of-band change detected)
        Landing-zone level drift (e.g. a managed SCP was attached, detached, ...)
        FIX: Reset or update the landing zone to restore config. See .../drift.html
  [X] 1 provisioned product(s) still exist for suspended account(s)
        Account | Provisioned Product | Status
          - 333333333333 | account-factory-... | AVAILABLE
        FIX: Reopen+terminate the provisioned product, or remove orphaned StackSet instances.

[i] INFO  (2)
------------------------------------------------------------------------------
  [i] Update available: 3.3 -> 4.0

==============================================================================
RESULT: NOT SAFE TO UPGRADE — 2 blocker(s), 0 warning(s), 0 unverified.
==============================================================================
```

## How it works

1. **Discovery** — Finds the landing zone (`ListLandingZones` → `GetLandingZone`) and reads the
   landing-zone **manifest** to auto-discover the **governed Regions** and the **Audit** and
   **Log Archive** account IDs. No hard-coding required.
2. **Checks** — Runs each check independently. A check that errors is reported as `UNKNOWN`; it
   never crashes the run, so a single missing permission cannot hide the rest of the report.
3. **Report + gate** — Prints a grouped report (and optional JSON), then exits non-zero if any
   blocker is present, or any `UNKNOWN` unless you pass `--allow-unknown`, or — with
   `--strict` — any warning.

## Testing

The blocker-detection logic is proven offline with a mocked-response harness — no AWS account
or network needed. It feeds each check simulated good/bad API responses and asserts the correct
severity fires (e.g. INOPERABLE in a shared account → BLOCKER, DRIFTED → WARNING, OUTDATED StackSet → INFO, unreachable shared account →
UNKNOWN not PASS, a Deny SCP without an `AWSControlTowerExecution` exemption → WARNING).

```bash
python3 tests/test_blocker_paths.py      # 270 tests, plain unittest (no extra deps)
```

This complements a live run against a healthy landing zone (which only exercises the PASS/INFO
paths): the harness proves the BLOCKER/WARNING/UNKNOWN paths without needing a broken
environment.

## Limitations and scope

This tool reduces upgrade failures; it does not guarantee success. Be aware of the following:

- **Some failures only surface at deploy time.** Runtime issues — KMS key/permission edge cases,
  a blueprint entering `UPDATE_FAILED`, service throttling — cannot be predicted by a read-only
  precheck.
  [AWS Control Tower does not roll back a failed update](https://docs.aws.amazon.com/controltower/latest/userguide/troubleshooting.html),
  so always follow the
  [best practices for landing zone updates](https://docs.aws.amazon.com/controltower/latest/userguide/lz-update-best-practices.html).
- **`UNKNOWN` is not `PASS`.** If a permission is missing or an API errors, the affected check
  reports `UNKNOWN`. Unknowns gate the run **by default** — they mean "must verify manually," and
  the exit code reflects that without any flag. Pass `--allow-unknown` only if you accept
  proceeding on an unverified report.
- **The Config check requires cross-account access.** Check #9 assumes a role
  (`AWSControlTowerExecution` by default) into the shared accounts; without it the check is
  `UNKNOWN`, not silently skipped.
- **Customization detection is best-effort.** It uses naming heuristics (`CustomControlTower*`
  StackSets, AFT account naming) and can produce false negatives for heavily renamed deployments.
- **Region.** Control Tower is Region-scoped; run in the home Region or checks will not find the
  landing zone.
- **Service-internal state is invisible to a precheck.** Two failure modes seen repeatedly are
  not detectable from outside. A landing zone can hold a stale internal operation lock, so an
  update is rejected with `ConflictException` and *"cannot begin landing zone setup while another
  execution is in progress"* even when nothing is running and no Step Function is active; only
  AWS Support can clear it. Control Tower can also fail part-way through its own update because
  of a race between its internal modules, which no precondition predicts. A landing zone left in
  `FAILED` state by either is reported by check 1, but the cause is not.
- **Shared accounts already claimed by another landing zone.** An update can fail validation with
  *"The account specified for the AWS Config integration is in use for another Control Tower
  environment"* when a shared account is still registered to a landing zone in a different
  management account. That association is internal to Control Tower and no public API exposes it,
  so the check cannot see it.
- **Commercial partition only.** Member-account role ARNs and the STS endpoint are built for
  the `aws` partition, so the tool does not run in AWS GovCloud (`aws-us-gov`) or China
  (`aws-cn`), even though Control Tower is available in GovCloud. Adapt the ARN and endpoint
  construction in `Source/ct_preupgrade_precheck.py` before using it in another partition.

## FAQs

**Does this change anything in my environment?**
Not on the default path — every call is a `List*`/`Get*`/`Describe*`/`Search*`, and nothing is
created, modified or deleted.

There is one exception, and it is opt-in. `--detect-drift` calls
`cloudformation:DetectStackSetDrift`, which **starts** a CloudFormation drift-detection operation
on the `AWSControlTower*` StackSets. That is a state-changing API. It does not alter your
resources, but it does create an operation that runs for a while — and Control Tower cannot
update a landing zone while a StackSet operation on its StackSets is in progress (this tool's own
check #18 treats that as a BLOCKER). Leave `--detect-drift` off unless you specifically want
active drift detection.

**Where do I run it?**
The Control Tower **management account**, in the **home Region**.

If you run it anywhere else it says so rather than guessing. Control Tower's landing-zone
APIs return an *empty list* in a member account rather than an error, so an empty result on
its own cannot tell a member account apart from the wrong Region. The tool resolves that
with `organizations:DescribeOrganization`, which does answer in a member account, and then
reports which of the two it is: a member account, the management account in the wrong
Region, or an account that is not in an organization at all. It exits `3` in every case —
no verdict, because no check ran.

**It reported a blocker for drift — what now?**
Resolve drift first (reset/update the landing zone, re-register OUs, or reset enabled
controls/baselines), then re-run the precheck until it is clean. See
[Detect and resolve drift in AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/drift.html).

**Can I run it in a pipeline?**
Yes. Use `--json` for a machine-readable report and gate on the exit code (see
[Exit codes](#exit-codes-for-pipeline-gating)). Note that exit `2` covers two distinct cases — a
real blocker, and a check that could not be evaluated — and both should stop an upgrade. Add
`--allow-unknown` only if you deliberately want unverified checks to pass, and `--strict` if you
also want warnings to stop the pipeline.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for how to report a potential
security issue. This tool requires only read-only permissions; grant it a least-privilege,
read-only role and do not store long-lived credentials.

**Treat the report output as sensitive.** Both the console report and the optional `--json` file
contain your own infrastructure topology and identity metadata, specifically: management, audit,
log archive and member account IDs; OU names and IDs; StackSet names; stack instance Regions and
statuses; resource-level drift detail; IAM role names; the landing zone KMS key ARN; SCP names and
IDs; Service Catalog provisioned product names; delegated administrator account IDs; the governed
Region list; and verbatim AWS API error messages (one of which can include the calling
principal's ARN). No credential material, SCP policy content or account email addresses are
included.

Two practical consequences:

- The `--json` file is created mode `0600` and will not follow a symlink, but you still choose
  where it lands. Write it somewhere access-controlled, and remember `.gitignore` already excludes
  `report.json` and `*.report.json` so a report cannot be committed by accident.
- The console report goes to **stdout**. If you run this in a pipeline, that output lands in build
  logs, which typically have wider access and longer retention than an operator expects. Redirect
  it deliberately if that matters to you.

## Revisions

2026-10-01 - Initial release.

## Notices

Customers are responsible for making their own independent assessment of the information in this
sample. This sample: (a) is for informational purposes only, (b) represents current AWS product
offerings and practices, which are subject to change without notice, and (c) does not create any
commitments or assurances from AWS and its affiliates, suppliers, or licensors. AWS products or
services are provided "as is" without warranties, representations, or conditions of any kind,
whether express or implied.

## Authors

Prasanth Gutha

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
