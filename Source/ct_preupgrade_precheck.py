#!/usr/bin/env python3
"""
AWS Control Tower pre-upgrade / pre-repair precheck (standalone, read-only).

PURPOSE
-------
Run this from the AWS Control Tower MANAGEMENT account, in the HOME region, BEFORE
you click "Update"/"Repair"/"Reset" on the landing zone (or call UpdateLandingZone /
ResetLandingZone). It confirms the environment is in a known-good state and surfaces the
issues, drift, out-of-band changes and customizations that are documented or repeatedly
observed causes of landing-zone update failures — so they can be fixed first.

It is read-only by default: every AWS call on the default path is a List*/Get*/Describe*/
Search*, and nothing is mutated. The one exception is --detect-drift, which starts a
CloudFormation drift-detection operation. It exits non-zero when a BLOCKER is found, and
also when a check could not be evaluated, so an upgrade runbook can gate on it.

WHAT IT CHECKS
    Most checks run by default; a few are behind an opt-in flag. The authoritative
    per-check table — what each one detects, its data source and its severity — is in
    README.md, and the executable list is CHECKS near the bottom of this file. Both track
    the code, so prefer them to this summary. A count is deliberately not stated here: it
    went stale three times.

    Landing zone state     status ACTIVE, drift IN_SYNC, whether an update is available,
                           and the version-specific changes on the path to the target
    Accounts               suspended or failed managed accounts, a suspended account still
                           holding an Account Factory product (the classic "cannot assume
                           AWSControlTowerExecution" blocker), provisioned-product health
    Controls and baselines control drift, baseline drift, and baselines still targeting an
                           OU that no longer exists in AWS Organizations
    StackSets              AWSControlTower* stack-instance health, foundational StackSets
                           missing entirely, in-progress operations that would conflict,
                           and active drift detection (opt-in)
    Shared-account state   AWS Config recorders and delivery channels Control Tower did not
                           create, and CT-created resources orphaned by a deleted StackSet
                           that collide with "already exists" on Repair/Reset
    Organization config    trusted service access, delegated administrators, SCP headroom
                           against the 10-per-target limit, and SCP content that fails to
                           exempt AWSControlTowerExecution or restricts Regions
    Landing zone 4.0       the CloudTrail managed-policy prerequisite, service-integration
    prerequisites          accounts sharing one parent OU, the integration dependency
                           rules, and IAM Identity Center being in the home Region
    Identity and keys      required management-account IAM roles, the landing-zone KMS key
                           against every requirement one DescribeKey can decide, its key
                           policy (opt-in), STS activation in each governed Region, and
                           AWSControlTowerExecution in every enrolled account (opt-in)

    Severity model: only problems in the shared accounts — management, log archive, audit,
    and the 4.0 service-integration accounts — and in org-level configuration hard-BLOCK a
    landing-zone update. The same problem in a *member* account is a WARNING, because the
    update acts on the shared accounts and enrolled accounts are re-baselined separately by
    re-registering their OU. A failure whose reason shows Control Tower's intended end state
    is already true is not reported as a problem at all. With --detect-drift, active
    CloudFormation drift detection runs and owns DRIFTED reporting, and the stored-status
    check defers to it rather than counting the same instance twice.

USAGE
-----
    # From the management account, home region (uses ambient creds/role):
    python3 ct_preupgrade_precheck.py

    # Explicit region / profile:
    python3 ct_preupgrade_precheck.py --region us-east-1 --profile my-mgmt-admin

    # JSON report for a pipeline gate, and fail on warnings too:
    python3 ct_preupgrade_precheck.py --json report.json --strict

    # Cross-account Config check needs a role assumable in the shared accounts
    # (defaults to AWSControlTowerExecution, which the mgmt account can assume):
    python3 ct_preupgrade_precheck.py --member-role AWSControlTowerExecution

    # Opt-in deeper checks, slower or assuming into accounts. Compose as needed; each is
    # described in the README's opt-in table:
    python3 ct_preupgrade_precheck.py --detect-drift --check-member-roles \
                                      --check-kms-policy --check-orphaned-resources

EXIT CODES
    0 = no blockers, and every check ran (review any warnings)
    2 = one or more BLOCKERS, or one or more checks could not be evaluated (UNKNOWN).
        --allow-unknown exits 0 on unevaluated checks; --strict also fails on WARNING
    3 = the precheck could not run, so no verdict was reached: no landing zone in this
        account/Region, or an authentication or setup problem

REQUIRED PERMISSIONS (management account, read-only)
    controltower:ListLandingZones, GetLandingZone, ListEnabledControls, ListEnabledBaselines
    account:ListRegions (governed-Region opt-in status)
    organizations:DescribeOrganization (tells a member account apart from the management
                  account when no landing zone is found - it is the one Organizations
                  read that answers in a member account),
                  ListRoots, ListOrganizationalUnitsForParent,
                  ListAccounts, ListAccountsForParent, ListPoliciesForTarget, ListParents,
                  ListAWSServiceAccessForOrganization, ListDelegatedAdministrators,
                  ListDelegatedServicesForAccount, DescribePolicy
    servicecatalog:SearchProvisionedProducts
    cloudformation:ListStackSets, ListStackInstances, ListStacks, ListStackSetOperations,
                   DescribeStackSetOperation, DescribeStackResourceDrifts
    iam:GetRole, ListAttachedRolePolicies
    kms:DescribeKey, GetKeyPolicy
    sso:ListInstances (IAM Identity Center home-Region prerequisite check)
    sts:GetCallerIdentity, AssumeRole (AssumeRole only for the cross-account Config check)

    OPT-IN, STATE-CHANGING (only with --detect-drift)
    cloudformation:DetectStackSetDrift - starts a StackSet drift-detection operation
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    print("boto3 is required: pip install boto3", file=sys.stderr)
    sys.exit(3)


# --------------------------------------------------------------------------------------
# Finding model + severity
# --------------------------------------------------------------------------------------
BLOCKER = "BLOCKER"   # must fix before upgrade; gates the run
WARNING = "WARNING"   # should review; may cause partial issues
INFO = "INFO"         # informational (e.g. customizations you must be aware of)
PASS = "PASS"         # verified good  # nosec B105 - severity-level label, not a password
UNKNOWN = "UNKNOWN"   # could not verify (missing perms / API error) — never assume good


@dataclass
class Finding:
    check: str
    level: str
    summary: str
    detail: str = ""
    rows: List[List[str]] = field(default_factory=list)
    cols: List[str] = field(default_factory=list)
    remediation: str = ""
    doc: str = ""


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_level(self, level: str) -> List[Finding]:
        return [f for f in self.findings if f.level == level]

    @property
    def has_blockers(self) -> bool:
        return len(self.by_level(BLOCKER)) > 0

    @property
    def has_unknowns(self) -> bool:
        return len(self.by_level(UNKNOWN)) > 0

    @property
    def has_warnings(self) -> bool:
        return len(self.by_level(WARNING)) > 0


DOC = "https://docs.aws.amazon.com/controltower/latest/userguide"

# Per-check AWS Control Tower documentation references. Every URL below was verified to be a
# real page under the CT User Guide (no guessed slugs). Rendered as a "DOC:" line per finding
# and included in the JSON report so each section is traceable to authoritative guidance.
_CHECK_DOCS = {
    "discovery": f"{DOC}/troubleshooting.html",
    "lz_status": f"{DOC}/troubleshooting.html",
    "lz_drift": f"{DOC}/drift.html",
    "update_available": f"{DOC}/lz-version-selection.html",
    "upgrade_considerations": f"{DOC}/update-controltower.html",
    "managed_accounts": f"{DOC}/account-factory-considerations.html",
    "closed_with_pp": f"{DOC}/troubleshooting.html",
    "controls_drift": f"{DOC}/resolving-drift.html",
    "baselines_drift": f"{DOC}/resolve-drift.html",
    "stale_baseline_targets": f"{DOC}/troubleshooting.html",
    "stale_control_targets": f"{DOC}/remove-ou.html",
    "foundational_ou": f"{DOC}/drift.html",
    "foundational_ou_placement": f"{DOC}/drift.html",
    "foundational_ou_extra_accounts": f"{DOC}/drift.html",
    "foundational_ou_additional": f"{DOC}/drift.html",
    "governed_regions": f"{DOC}/region-how.html",
    "mgmt_stacks": f"{DOC}/drift.html",
    "mgmt_stacks_unhealthy": f"{DOC}/drift.html",
    "mgmt_stacks_in_progress": f"{DOC}/drift.html",
    "foundational_ou_nested": f"{DOC}/key-changes-lz-v4.html",
    "stacksets": f"{DOC}/drift.html",
    "stacksets_member": f"{DOC}/drift.html",
    "stacksets_expected": f"{DOC}/drift.html",
    "stacksets_drifted": f"{DOC}/resolve-drift.html",
    "stacksets_orphaned": f"{DOC}/shared-account-resources.html",
    "stackset_drift": f"{DOC}/drift.html",
    "stackset_drift_member": f"{DOC}/drift.html",
    "stackset_drift_orphaned": f"{DOC}/shared-account-resources.html",
    "stackset_ops": f"{DOC}/troubleshooting.html",
    "config_shared": f"{DOC}/existing-config-resources.html",
    "log_archive_buckets": f"{DOC}/configuration-updates.html",
    "customizations": f"{DOC}/configuration-updates.html",
    "trusted_access": f"{DOC}/governance-drift.html",
    "delegated_admins": f"{DOC}/governance-drift.html",
    "iam_roles": f"{DOC}/roles-how.html",
    "cloudtrail_role_v4": f"{DOC}/key-changes-lz-v4.html",
    "v4_integration_ou": f"{DOC}/key-changes-lz-v4.html",
    "v4_integration_deps": f"{DOC}/lz-api-launch.html",
    "identity_center": f"{DOC}/getting-started-prereqs.html",
    "kms_key": f"{DOC}/configure-shared-accounts.html",
    "kms_policy": f"{DOC}/configure-shared-accounts.html",
    "sts_regions": f"{DOC}/troubleshooting.html",
    "scp_headroom": f"{DOC}/resolve-drift.html",
    "scp_blocking": f"{DOC}/resolve-drift.html",
    "scp_custom": f"{DOC}/resolve-drift.html",
    "expected_stacksets": f"{DOC}/shared-account-resources.html",
    "orphaned_resources": f"{DOC}/existing-config-resources.html",
    "provisioned_products": f"{DOC}/updating-account-factory-accounts.html",
    "provisioned_products_inprogress": f"{DOC}/updating-account-factory-accounts.html",
    "member_roles": f"{DOC}/roles-how.html",
}


# --------------------------------------------------------------------------------------
# Helper: paginate any boto3 call safely
# --------------------------------------------------------------------------------------
def _collect(client, op: str, key: str, **kwargs) -> List[dict]:
    """Depaginate op if a paginator exists, else single call. Returns list under `key`.
    Robust against older botocore where can_paginate() raises for unknown operations."""
    out: List[dict] = []
    try:
        paginable = client.can_paginate(op)
    except Exception:
        paginable = False
    if paginable:
        for page in client.get_paginator(op).paginate(**kwargs):
            out.extend(page.get(key, []))
    else:
        resp = getattr(client, op)(**kwargs)
        out.extend(resp.get(key, []))
    return out


# --------------------------------------------------------------------------------------
# Discovery: landing zone, governed regions, shared account ids (all from mgmt account)
# --------------------------------------------------------------------------------------
# Every service-integration account a landing zone manifest can declare, with the path to its
# account id. The Backup integration nests TWO accounts under `configurations`, which is why a
# flat node.get("accountId") does not find them.
#   https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-launch.html
_SERVICE_INTEGRATION_ACCOUNTS = (
    ("centralizedLogging", "CentralizedLogging (Log archive)", ("accountId",)),
    ("securityRoles", "SecurityRoles (Audit)", ("accountId",)),
    ("config", "Config", ("accountId",)),
    ("backup", "Backup admin", ("configurations", "backupAdmin", "accountId")),
    ("backup", "Central backup", ("configurations", "centralBackup", "accountId")),
)


def service_integration_accounts(manifest: Dict[str, Any]) -> Dict[str, List[str]]:
    """{account id: [integration labels]} for every integration not EXPLICITLY disabled.

    An explicitly disabled integration is excluded deliberately: "If a service integration
    account displays a baseline status of 'Not Enabled' and the associated service integration
    is disabled, AWS Control Tower no longer manages that account" (key-changes-lz-v4.html). An
    account Control Tower has stopped managing must not be treated as one a landing-zone
    operation acts on - doing so would invert the defect and produce a false blocker.

    An ABSENT flag is not a disable. Manifests before 4.0 carry no `enabled` flags at all, so
    absence means "declared and managed", the same reading used for the CloudTrail role gate.
    """
    out: Dict[str, List[str]] = {}
    for key, label, path in _SERVICE_INTEGRATION_ACCOUNTS:
        node = (manifest.get(key) or manifest.get(key[:1].upper() + key[1:]) or {})
        if node.get("enabled") is False:
            continue
        cur: Any = node
        for part in path[:-1]:
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                break
        last = path[-1]
        acct = None
        if isinstance(cur, dict):
            acct = cur.get(last) or cur.get(last[:1].upper() + last[1:])
        if acct:
            out.setdefault(str(acct), []).append(label)
    return out


class Context:
    def __init__(self, session, region: str, member_role: str):
        self.session = session
        self.region = region
        self.member_role = member_role
        # Adaptive retries on the two highest fan-out clients: ListEnabledControls is called
        # once per OU and ListPoliciesForTarget once per target, so in a large organization
        # throttling is routine. Absorbing it here keeps a throttle from becoming a skipped
        # target, which would silently make a check's result partial.
        from botocore.config import Config as _BotoConfig
        _retry = _BotoConfig(retries={"mode": "adaptive", "max_attempts": 10})
        self.ct = session.client("controltower", region_name=region, config=_retry)
        self.orgs = session.client("organizations", region_name=region, config=_retry)
        self.lz_arn: Optional[str] = None
        self.lz: Dict[str, Any] = {}
        self.manifest: Dict[str, Any] = {}
        self.governed_regions: List[str] = []
        self.log_archive_account: Optional[str] = None
        self.audit_account: Optional[str] = None
        self.mgmt_account: Optional[str] = None
        # Whether the caller really is the landing zone's management account: True once
        # established, False when it is demonstrably a member account, None when it could
        # not be determined. mgmt_account is taken from the caller's own identity, so on its
        # own it is an assumption rather than a fact.
        self.caller_is_management: Optional[bool] = None
        self.kms_key_arn: Optional[str] = None
        self.detect_drift: bool = False
        self.drift_timeout: int = 900
        self.check_member_roles: bool = False
        self.check_kms_policy: bool = False
        self.check_orphaned_resources: bool = False

    def _caller_account_note(self) -> Optional[str]:
        """Explain an empty landing-zone result when the account itself may be the reason.

        Control Tower's landing-zone APIs only answer in the management account, and from a
        member account ListLandingZones returns an EMPTY LIST rather than an error. So an
        empty result cannot on its own tell "wrong account" apart from "no landing zone in
        this Region", and reporting only the Region sends the reader after the wrong thing.

        organizations:DescribeOrganization does answer in a member account and names the
        management account, so it can tell the two apart. ListRoots and ListAccounts are both
        denied to a member account, so this is specifically the call that works there.

        Sets self.caller_is_management. Returns a sentence to append to the finding, or None
        when there is nothing to add.
        """
        try:
            org = self.orgs.describe_organization().get("Organization", {})
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "") or "error"
            if code == "AWSOrganizationsNotInUseException":
                return ("This account is not part of an AWS Organization, so it cannot have a "
                        "Control Tower landing zone.")
            # Denied or throttled - an SCP can block this in a member account. Say it could
            # not be established rather than implying the account is fine, which would send
            # the reader to check Regions when the account may be the problem.
            return (f"Whether this is the management account could not be established "
                    f"({code} on organizations:DescribeOrganization), so the wrong account "
                    "cannot be ruled out as the cause.")
        except BotoCoreError as e:
            return (f"Whether this is the management account could not be established "
                    f"({type(e).__name__} on organizations:DescribeOrganization), so the "
                    "wrong account cannot be ruled out as the cause.")
        master = org.get("MasterAccountId")
        if not master or not self.mgmt_account:
            return None
        # mgmt_account holds the CALLER's account id at this point, taken from
        # sts:GetCallerIdentity. This comparison is what turns that into a fact.
        if master != self.mgmt_account:
            self.caller_is_management = False
            return ("This is a member account. Control Tower's landing-zone APIs only answer "
                    "in the management account, so nothing can be checked from here.")
        self.caller_is_management = True
        return None

    def discover(self, report: Report) -> bool:
        try:
            self.mgmt_account = self.session.client(
                "sts", region_name=self.region
            ).get_caller_identity()["Account"]
        except (ClientError, BotoCoreError) as e:
            report.add(Finding("discovery", UNKNOWN,
                               "Could not determine caller identity", str(e)))
            return False

        # Preflight: the SDK must be new enough to know the Control Tower LZ APIs.
        if not hasattr(self.ct, "list_landing_zones"):
            report.add(Finding("discovery", BLOCKER,
                               "Installed boto3/botocore is too old for Control Tower APIs",
                               "This SDK does not expose controltower:ListLandingZones / "
                               "GetLandingZone / ListEnabledBaselines.",
                               remediation="Upgrade the SDK:  pip install -U 'boto3>=1.34'"))
            return False

        try:
            lzs = _collect(self.ct, "list_landing_zones", "landingZones")
        except (ClientError, BotoCoreError) as e:
            note = self._caller_account_note()
            detail = str(e) + ((" " + note) if note else "")
            report.add(Finding("discovery", BLOCKER,
                               "This is not the Control Tower management account"
                               if self.caller_is_management is False
                               else "Could not list landing zones",
                               detail,
                               remediation="Run the precheck from the organization's "
                                           "management account, in the landing zone's home "
                                           "Region."))
            return False

        if not lzs:
            note = self._caller_account_note()
            detail = "ListLandingZones returned empty."
            if note:
                detail += " " + note
            if self.caller_is_management is False:
                summary = "This is not the Control Tower management account"
                fix = ("Run the precheck from the organization's management account, in the "
                       "landing zone's home Region.")
            elif self.caller_is_management is True:
                summary = "No landing zone found in this account/region"
                fix = ("This is the management account, so confirm you are in the landing "
                       "zone's home Region.")
            else:
                summary = "No landing zone found in this account/region"
                fix = ("Confirm you are in the landing zone's home Region, and that this is "
                       "the organization's management account.")
            report.add(Finding("discovery", BLOCKER, summary, detail, remediation=fix))
            return False

        # Only the management account gets a landing zone back, so this is now established.
        self.caller_is_management = True

        self.lz_arn = lzs[0].get("arn")
        try:
            self.lz = self.ct.get_landing_zone(
                landingZoneIdentifier=self.lz_arn
            ).get("landingZone", {})
        except (ClientError, BotoCoreError) as e:
            # ResourceNotFoundException here means the landing zone is not in THIS Region:
            # ListLandingZones answered, GetLandingZone did not. Saying "GetLandingZone
            # failed" with no remediation leaves the reader to work that out from the raw
            # API text.
            _code = (e.response.get("Error", {}).get("Code", "")
                     if isinstance(e, ClientError) else "")
            if _code == "ResourceNotFoundException":
                report.add(Finding("discovery", BLOCKER,
                                   f"No landing zone in {self.region}", str(e),
                                   remediation="Re-run with --region set to the landing "
                                               "zone's home Region."))
            else:
                report.add(Finding("discovery", BLOCKER, "GetLandingZone failed", str(e),
                                   remediation="Confirm the caller can read the landing zone "
                                               "(controltower:GetLandingZone) and that this "
                                               "is its home Region."))
            return False

        self.manifest = self.lz.get("manifest", {}) or {}
        # governedRegions + shared accounts are carried in the manifest
        self.governed_regions = (
            self.manifest.get("governedRegions")
            or self.manifest.get("GovernedRegions")
            or [self.region]
        )
        cl = self.manifest.get("centralizedLogging") or self.manifest.get("CentralizedLogging") or {}
        sr = self.manifest.get("securityRoles") or self.manifest.get("SecurityRoles") or {}
        self.log_archive_account = cl.get("accountId") or cl.get("AccountId")
        self.audit_account = sr.get("accountId") or sr.get("AccountId")
        # Optional customer-managed KMS key for the landing zone (from the manifest).
        cfg = cl.get("configurations") or cl.get("Configurations") or {}
        self.kms_key_arn = (cfg.get("kmsKeyArn") or cfg.get("KmsKeyArn")
                            or self.manifest.get("kmsKeyArn"))
        return True

    @property
    def shared_accounts(self) -> set:
        """Accounts a landing-zone operation acts on, used for severity tiering.

        The management account, plus every service-integration account the manifest declares and
        does not explicitly disable. Control Tower "manages service integration accounts through
        the landing zone, not through OU-level baselines" (key-changes-lz-v4.html), which is the
        same reason the Audit and Log archive accounts sit here.

        A property rather than a field so that the --audit-account / --log-archive-account
        overrides, which are applied after discovery, are picked up without a second call.
        """
        accts = {self.mgmt_account, self.audit_account, self.log_archive_account}
        accts |= set(service_integration_accounts(self.manifest))
        return {a for a in accts if a}

    def assume(self, account_id: str, region: str, service: str):
        """Return a read-only service client in a member/shared account, or None."""
        role_arn = f"arn:aws:iam::{account_id}:role/{self.member_role}"
        sts = self.session.client("sts", region_name=self.region)
        creds = sts.assume_role(RoleArn=role_arn,
                                RoleSessionName="ct-preupgrade-precheck")["Credentials"]
        return boto3.client(
            service,
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def all_ou_arns(self) -> List[Dict[str, str]]:
        """Every OU in the org (Id, Arn, Name), recursively from the root."""
        roots = _collect(self.orgs, "list_roots", "Roots")
        ous: List[Dict[str, str]] = []
        stack = [r["Id"] for r in roots]
        while stack:
            parent = stack.pop()
            children = _collect(self.orgs, "list_organizational_units_for_parent",
                                "OrganizationalUnits", ParentId=parent)
            for ou in children:
                ous.append({"Id": ou["Id"], "Arn": ou["Arn"], "Name": ou["Name"]})
                stack.append(ou["Id"])
        return ous


# --------------------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------------------
def check_lz_status(ctx: Context, report: Report) -> None:
    status = ctx.lz.get("status")
    if status == "ACTIVE":
        report.add(Finding("lz_status", PASS,
                           f"Landing zone status is ACTIVE (v{ctx.lz.get('version')})"))
    elif status in ("PROCESSING",):
        report.add(Finding("lz_status", BLOCKER,
                           "Landing zone has an operation IN PROGRESS",
                           "A landing zone operation is currently PROCESSING.",
                           remediation="Wait for the current operation to finish before upgrading."))
    elif status == "FAILED":
        report.add(Finding("lz_status", BLOCKER,
                           "Landing zone is in a FAILED state",
                           "GetLandingZone.status == FAILED. Updates do not roll back; "
                           "resolve the failed state first.",
                           remediation=f"See {DOC}/troubleshooting.html"))
    else:
        report.add(Finding("lz_status", UNKNOWN,
                           f"Unexpected landing zone status: {status}"))


def check_lz_drift(ctx: Context, report: Report) -> None:
    drift = (ctx.lz.get("driftStatus") or {}).get("status")
    if drift == "IN_SYNC":
        report.add(Finding("lz_drift", PASS, "Landing zone drift status is IN_SYNC"))
    elif drift == "DRIFTED":
        report.add(Finding("lz_drift", BLOCKER,
                           "Landing zone is DRIFTED (out-of-band change detected)",
                           "Landing-zone drift is narrower than account or control drift. It is "
                           "defined as IAM role drift, or organizational drift that specifically "
                           "affects Foundational OUs and shared accounts: a deleted Foundational "
                           "OU, trusted access disabled, or the audit / log archive account moved "
                           "or removed. Most of these leave Control Tower unusable until resolved "
                           "- role drift makes the landing zone unavailable, deleting the Security "
                           "OU blocks every other Control Tower action until a reset completes, and "
                           "removing a shared account from a Foundational OU blocks the console. "
                           "The exception is a MOVED shared account, which is resolved by updating "
                           "the landing zone, so for that sub-type this upgrade is the fix rather "
                           "than something to postpone. driftStatus alone does not say which "
                           "sub-type applies. (Since Aug 2025, an SCP merely attached to a managed "
                           "OU or member account is no longer counted as drift.)",
                           remediation="Identify the drift sub-type in the Control Tower console. "
                                       "Role drift has its own repair that restores the role "
                                       "without a full landing-zone reset. Otherwise reset or "
                                       f"update the landing zone. See {DOC}/governance-drift.html"))
    else:
        report.add(Finding("lz_drift", UNKNOWN,
                           f"Could not read landing zone drift status (got: {drift})"))


def check_update_available(ctx: Context, report: Report) -> None:
    cur = ctx.lz.get("version")
    latest = ctx.lz.get("latestAvailableVersion")
    if not latest:
        report.add(Finding("update_available", INFO,
                           f"Current landing zone version: {cur}",
                           "latestAvailableVersion not returned."))
        return
    if cur == latest:
        report.add(Finding("update_available", INFO,
                           f"Landing zone already on the latest version ({cur})",
                           "No landing-zone update is pending. (Baseline/control updates "
                           "may still be pending — see other checks.)"))
    else:
        report.add(Finding("update_available", INFO,
                           f"Update available: {cur} -> {latest}",
                           cols=["Current", "Latest"], rows=[[str(cur), str(latest)]],
                           remediation=f"Review {DOC}/lz-update-best-practices.html "
                                       "(2.x -> 3.x requires OU re-registration)."))


# --------------------------------------------------------------------------------------
# Version-path upgrade considerations (advisory checklist)
#
# For each landing zone version that requires an update, this catalogs the notable changes,
# risks, and known issues introduced AT that version — so that upgrading across a range
# (e.g. 2.9 -> 4.0) surfaces every boundary crossed. Each (change, action) pair and its doc
# URL is taken verbatim from the AWS Control Tower release notes / v4 migration docs (no
# guessed content). Surfaced as INFO findings in a normal run, or standalone via
# `--upgrade-notes CURRENT:LATEST` (no AWS calls needed — pure knowledge output).
# --------------------------------------------------------------------------------------
_VERSION_CONSIDERATIONS = [
    ("3.0", f"{DOC}/2022-all.html", [
        ("Organization-level CloudTrail replaces account-level trails",
         "On update to 3.0, Control Tower deletes the existing account-level trails for ENROLLED "
         "accounts after a 24-hour wait. If you rely on account-level trails, create your own "
         "BEFORE updating. A failure after the org trail is created can incur duplicate "
         "org+account trail charges until the update completes."),
        ("CloudTrail S3 log path changes",
         "Org-trail logs are stored under /org-id/AWSLogs/org-id/... (a different path than "
         "account-trail logs). If a third-party service consumes these logs, give it the new path."),
        ("AWS Config records global resources in the home Region only",
         "The Config baseline changes to record global resources only in the home Region."),
        ("Region deny control and AWSControlTowerServiceRolePolicy updated",
         "The Region deny control and the managed AWSControlTowerServiceRolePolicy are updated."),
        ("Per-account aws-controltower-CloudWatchLogsRole / log group no longer created",
         "With org trails, only one is created in the management account; the per-account role "
         "and log group are no longer created in each enrolled account."),
    ]),
    ("3.1", f"{DOC}/2023-all.html", [
        ("Server access logging deactivated on the access-logging bucket",
         "Control Tower stops access logging on the Log Archive access-logging bucket. This "
         "triggers Security Hub finding [S3.9] on that bucket - suppress it per Security Hub guidance."),
        ("Region deny control expanded for more global services",
         "Adds actions for account, activate, artifact, billingconductor, compute-optimizer, "
         "devicefarm, license-manager, lightsail, resource-explorer-2, savingsplans, sso, "
         "supportapp, supportplans, sustainability, tag, and more. Re-review custom Region-deny edits."),
    ]),
    ("3.2", f"{DOC}/2023-all.html", [
        ("New service-linked role AWSServiceRoleForAWSControlTower + EventBridge managed rule",
         "Control Tower creates the SLR and deploys AWSControlTowerManagedRule directly (not via a "
         "stack) in each member account to collect Security Hub Finding events for drift. A new "
         "management-account StackSet BP_BASELINE_SERVICE_LINKED_ROLE deploys the SLR."),
        ("Security Hub CSPM Service-Managed Standard generally available + drift status",
         "Control drift for this standard becomes viewable; Finding events are sent to the home Region only."),
        ("Region deny control updated",
         "Adds billing, cloudtrail:LookupEvents, consolidatedbilling, consoleapp, freetier, "
         "invoicing, iq, notifications(-contacts), payments, tax; removes invalid "
         "s3:GetAccountPublic / s3:PutAccountPublic."),
    ]),
    ("3.3", f"{DOC}/2023-all.html", [
        ("Audit-account S3 bucket policy now requires aws:SourceOrgID on writes",
         "CloudTrail can write logs only for accounts within your organization. Any external / "
         "cross-org writer to this bucket will be denied after the update."),
        ("AWS Config SNS topic policy adds aws:SourceOrgID condition",
         "Review any external subscribers/publishers to the Config SNS topic."),
        ("Region deny control updated",
         "Removes discovery-marketplace (covered by aws-marketplace:*); adds "
         "quicksight:DescribeAccountSubscription."),
        ("BASELINE-CLOUDTRAIL-MASTER template updated to not show drift without KMS",
         "If you did not enable KMS encryption for CloudTrail, this removes a spurious drift signal."),
    ]),
    ("4.0", f"{DOC}/key-changes-lz-v4.html", [
        ("PREREQUISITE (API upgrade): AWSControlTowerCloudTrailRole must use the managed policy",
         "Before upgrading to 4.0 via API, detach the legacy inline policy and attach managed policy "
         "AWSControlTowerCloudTrailRolePolicy, or the upgrade is blocked. (This tool's "
         "cloudtrail_role_v4 check verifies this.)"),
        ("Do NOT disable service integrations (AWS Config, SecurityRoles) during the upgrade",
         "Config and SecurityRoles were always implicit in 3.3 and earlier; 4.0 surfaces them as "
         "configurable options. Leave them enabled while upgrading - disable them only AFTER a "
         "successful upgrade to 4.0."),
        ("Security OU is no longer created or enforced by Control Tower",
         "4.0 does not create the designated Security OU; the OU containing your service-integration "
         "accounts becomes the Security OU. Existing Security OU setups keep working. That OU shows a "
         "baseline status of 'Not Applicable' (expected). Moving member accounts into it drifts "
         "enabled controls on that OU."),
        ("All integrations become optional, with baseline enable/disable dependencies",
         "Config, CloudTrail, SecurityRoles, and Backup can each be enabled/disabled. Baselines depend "
         "on one another - e.g. CentralSecurityRolesBaseline requires CentralConfigBaseline; "
         "IdentityCenter/Backup baselines require CentralSecurityRolesBaseline. Disable order is the "
         "reverse. Plan toggles accordingly."),
        ("AWS Config integration scope changed",
         "Enabling Config at the landing-zone level deploys recording to service-integration accounts "
         "only. To deploy Config (recorder + delivery channel) to member accounts, enable the Config "
         "baseline on each managed OU. LZ-level Config is a prerequisite for the OU Config baseline."),
        ("Drift notifications move to Amazon EventBridge",
         "Control Tower stops sending drift notifications to the SNS topic for ALL customers on "
         "landing zone 4.0 and later, and sends them to EventBridge in the management account "
         "instead. Create an EventBridge rule in the management account and update any consumers "
         "that watched the SNS topic."),
        ("CentralizedLogging disable now DELETES logging-account resources",
         "In 3.3 and earlier, disabling CentralizedLogging toggled the org CloudTrail off but kept "
         "resources. In 4.0, disabling it deletes the Config Recorder, Delivery Channel, and "
         "CloudTrail stack instances from the logging account, and Control Tower stops managing that "
         "account. (Relevant if you disable it post-upgrade.)"),
    ]),
]


def _ver_tuple(v) -> Optional[tuple]:
    """('3.2') -> (3, 2). None if unparseable. Compares correctly across 2.9 < 3.0 < ... < 4.0."""
    try:
        parts = str(v).split(".")
        return (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    except (ValueError, AttributeError, TypeError):
        return None


def upgrade_path_considerations(cur, latest):
    """Return [(version, doc, rows)] for every catalogued version strictly above `cur`
    and up to and including `latest`. Unknown bound => that side is not filtered."""
    ct, lt = _ver_tuple(cur), _ver_tuple(latest)
    out = []
    for ver, doc, rows in _VERSION_CONSIDERATIONS:
        vt = _ver_tuple(ver)
        if vt is None:
            continue
        if (ct is None or vt > ct) and (lt is None or vt <= lt):
            out.append((ver, doc, rows))
    return out


def check_upgrade_path_considerations(ctx: Context, report: Report) -> None:
    """Advisory: surface the notable changes/risks introduced at each landing zone version
    crossed on the way from the deployed version to the latest available version."""
    cur = ctx.lz.get("version")
    latest = ctx.lz.get("latestAvailableVersion")
    if not cur or not latest or cur == latest:
        return
    for ver, doc, rows in upgrade_path_considerations(cur, latest):
        report.add(Finding(
            "upgrade_considerations", INFO,
            f"Upgrade-path considerations for landing zone v{ver}",
            detail=f"Changes introduced at v{ver} on the path {cur} -> {latest}. "
                   "Advisory (not a blocker) — review before upgrading.",
            cols=["Change / consideration", "What it means / action"],
            rows=[[c, a] for c, a in rows],
            doc=doc,
        ))


def check_managed_accounts(ctx: Context, report: Report) -> None:
    # Landing-zone level managed-account health via Organizations account state.
    try:
        accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("managed_accounts", UNKNOWN,
                           "Could not list organization accounts", str(e)))
        return
    suspended = [a for a in accounts if a.get("Status") == "SUSPENDED"]
    if suspended:
        rows = [[a["Id"], a.get("Name", ""), a.get("Status")] for a in suspended]
        report.add(Finding("managed_accounts", WARNING,
                           f"{len(suspended)} SUSPENDED account(s) in the organization",
                           "Suspended accounts frequently block landing-zone updates when "
                           "they still have an Account Factory provisioned product "
                           "(see the provisioned-product check).",
                           cols=["Account", "Name", "Status"], rows=rows,
                           remediation=f"{DOC}/troubleshooting.html"))
    else:
        report.add(Finding("managed_accounts", PASS,
                           "No SUSPENDED accounts in the organization"))


# Account Factory products are the only Service Catalog provisioned products Control Tower
# owns. The management account's Service Catalog commonly also holds unrelated products —
# CFN_STACK, CFN_STACKSET, TERRAFORM_OPEN_SOURCE — whose health has nothing to do with a
# landing-zone update. On one test organization 31 of 32 unhealthy products were CFN_STACK,
# so every provisioned-product check filters on this type before judging anything.
_ACCOUNT_FACTORY_PP_TYPE = "CONTROL_TOWER_ACCOUNT"


def _account_factory_products(pps: List[dict]) -> List[dict]:
    """Only the provisioned products Account Factory created."""
    return [p for p in pps if p.get("Type") == _ACCOUNT_FACTORY_PP_TYPE]


def check_suspended_with_provisioned_product(ctx: Context, report: Report) -> None:
    """The classic upgrade blocker: a closed/suspended account whose Account Factory
    Service Catalog provisioned product was never terminated -> AWSControlTowerExecution
    can't be assumed -> the landing zone update fails."""
    try:
        accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
        suspended_ids = {a["Id"] for a in accounts if a.get("Status") == "SUSPENDED"}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("closed_with_pp", UNKNOWN,
                           "Could not list accounts to correlate provisioned products", str(e)))
        return
    if not suspended_ids:
        report.add(Finding("closed_with_pp", PASS,
                           "No suspended accounts, so no orphaned provisioned products"))
        return
    try:
        sc = ctx.session.client("servicecatalog", region_name=ctx.region)
        pps = _collect(sc, "search_provisioned_products", "ProvisionedProducts",
                       AccessLevelFilter={"Key": "Account", "Value": "self"})
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("closed_with_pp", UNKNOWN,
                           "Could not search Service Catalog provisioned products", str(e)))
        return
    # Only Account Factory products matter here. An unrelated product (a CFN_STACK, say)
    # that merely happens to mention a suspended account id would otherwise raise a
    # BLOCKER that has nothing to do with Control Tower.
    pps = _account_factory_products(pps)
    # Account Factory products carry the vended account id in PhysicalId / Name; match loosely.
    hits = []
    for pp in pps:
        blob = json.dumps(pp)
        for acct in suspended_ids:
            if acct in blob:
                hits.append([acct, pp.get("Name", ""), pp.get("Status", "")])
    if hits:
        report.add(Finding("closed_with_pp", BLOCKER,
                           f"{len(hits)} provisioned product(s) still exist for suspended account(s)",
                           "A suspended account with an un-terminated Account Factory "
                           "provisioned product causes 'AWSControlTowerExecution role can't "
                           "be assumed' and fails the landing-zone update.",
                           cols=["Suspended Account", "Provisioned Product", "Status"], rows=hits,
                           remediation="Reopen+terminate the provisioned product, or remove the "
                                       "orphaned StackSet instances (Retain Stacks). See "
                                       f"{DOC}/troubleshooting.html"))
    else:
        report.add(Finding("closed_with_pp", PASS,
                           "No provisioned products found for suspended accounts"))


def check_enabled_controls(ctx: Context, report: Report) -> None:
    try:
        ous = ctx.all_ou_arns()
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("controls_drift", UNKNOWN,
                           "Could not enumerate OUs for control drift check", str(e)))
        return
    drifted, failed = [], []
    no_status: List[List[str]] = []
    skipped: List[List[str]] = []
    checked = 0
    for ou in ous:
        try:
            controls = _collect(ctx.ct, "list_enabled_controls", "enabledControls",
                                 targetIdentifier=ou["Arn"])
        except (ClientError, BotoCoreError) as e:
            # An OU with no Control Tower controls returns an empty list, not an error, so a
            # failure here means the OU could not be READ (denied / throttled / transient) -
            # never that it legitimately has nothing. Record it rather than silently dropping
            # it from this check's scope.
            skipped.append([ou.get("Name", ou.get("Arn", "")), _error_code(e), _skip_note(e)])
            continue
        checked += 1
        for c in controls:
            ds = (c.get("driftStatusSummary") or {}).get("driftStatus")
            st = (c.get("statusSummary") or {}).get("status")
            cid = c.get("controlIdentifier", c.get("arn", ""))
            if ds == "DRIFTED":
                drifted.append([ou["Name"], cid, ds])
            if st and st not in ("SUCCEEDED",):
                failed.append([ou["Name"], cid, st])
            elif not st:
                # A missing statusSummary is not evidence of health.
                no_status.append([ou["Name"], cid, "statusSummary absent"])
    if not checked:
        report.add(Finding("controls_drift", UNKNOWN,
                           "No CT-registered OUs found / none queryable for enabled controls"))
        return
    _report_partial_scope(report, "controls_drift", "OU(s)", skipped)
    if no_status:
        report.add(Finding("controls_drift", UNKNOWN,
                           f"{len(no_status)} enabled control(s) reported no status",
                           "Control Tower returned no statusSummary for these controls, so their "
                           "state is unverified. They are NOT counted as healthy.",
                           cols=["OU", "Control", "Status"], rows=no_status))
    if drifted or failed:
        rows = drifted + failed
        report.add(Finding("controls_drift", WARNING,
                           f"{len(rows)} enabled control(s) drifted or not in SUCCEEDED state",
                           "Control drift is repairable drift, not drift to resolve right away. "
                           "drift.html lists only four urgent types - deleting the Security OU, "
                           "deleting a required management-account role, deleting all Additional "
                           "OUs, and removing a shared account - and control drift is not among "
                           "them. It is resolved with ResetEnabledControl or by re-registering the "
                           "OU, and for a landing zone on 3.1 or later \"drift is resolved as part "
                           "of the update process\". So this does not block the update. It does "
                           "need resolving: a drifted control is not enforcing what you think it "
                           "is, and while the landing zone is drifted the Enroll account feature "
                           "will not work.",
                           cols=["OU", "Control", "Status"], rows=rows,
                           remediation="Call ResetEnabledControl for the affected control, or "
                                       "re-register the OU. If the drift is on the Security OU or "
                                       "involves a required role or shared account, treat it as "
                                       f"urgent instead. See {DOC}/drift.html"))
    else:
        report.add(Finding("controls_drift", PASS,
                           f"All enabled controls SUCCEEDED and IN_SYNC across {checked} OU(s)"
                           f"{_scope_suffix(skipped + no_status)}"))


def check_enabled_baselines(ctx: Context, report: Report) -> None:
    """Enabled baselines must be healthy - but severity depends on WHICH target is unhealthy.

    A landing-zone update acts on the management account and the service-integration (Audit /
    Log archive) accounts. It does NOT update enrolled accounts: "When you perform a landing zone
    update, you must update your enrolled accounts to apply new controls to those accounts"
    (update-existing-accounts.html) - that is a separate Re-register / Reset step per OU. Account
    baseline drift is also classified as repairable drift, resolved by updating the account,
    rather than something that must be cleared before a landing-zone update.

    So an unhealthy baseline on a service-integration account BLOCKS the update, while one on a
    member account or OU is a WARNING to resolve during the account-update phase that follows.
    Treating every target as a blocker fails a whole landing zone over, for example, one test
    account parked in an unmanaged OU.

    NOT_APPLICABLE / NOT_ENABLED are expected, not failures: in landing zone 4.0 the Control Tower
    and Config baselines "are not applicable to the Security OU and the service integration
    accounts ... This status is expected", and a service-integration account whose integration is
    disabled reports Not Enabled by design (key-changes-lz-v4.html).
    """
    try:
        baselines = _collect(ctx.ct, "list_enabled_baselines", "enabledBaselines",
                             includeChildren=True)
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("baselines_drift", UNKNOWN,
                           "Could not list enabled baselines", str(e)))
        return
    # The accounts a landing-zone update actually acts on. Mirrors check_stacksets.
    shared = ctx.shared_accounts
    shared_bad: List[List[str]] = []
    member_bad: List[List[str]] = []
    no_status: List[List[str]] = []
    for b in baselines:
        st = (b.get("statusSummary") or {}).get("status")
        ds = (b.get("driftStatusSummary") or {}).get("driftStatus")
        tgt = b.get("targetIdentifier", b.get("arn", ""))
        ver = b.get("baselineVersion", "")
        if not st:
            # A missing statusSummary is not evidence of health.
            no_status.append([tgt, ver, "absent", ds or ""])
            continue
        if str(st).replace(" ", "_").upper() in _BASELINE_EXPECTED_ABSENT:
            continue  # expected on the Security OU / a disabled service integration
        if str(st).upper() != "SUCCEEDED" or ds == "DRIFTED":
            acct = _target_account_id(tgt)
            row = [tgt, ver, str(st), ds or ""]
            (shared_bad if acct and acct in shared else member_bad).append(row)
    if no_status:
        report.add(Finding("baselines_drift", UNKNOWN,
                           f"{len(no_status)} enabled baseline(s) reported no status",
                           "Control Tower returned no statusSummary for these baselines, so "
                           "their state is unverified. They are NOT counted as healthy.",
                           cols=["Target", "Version", "Status", "Drift"], rows=no_status))
    if shared_bad:
        report.add(Finding("baselines_drift", BLOCKER,
                           f"{len(shared_bad)} baseline(s) unhealthy on a service-integration "
                           "account",
                           "A landing-zone update acts on the management account and every "
                           "service-integration account the manifest declares (Audit, Log archive, "
                           "Config, Backup), so an unhealthy baseline on one of them must be "
                           "resolved before updating.",
                           cols=["Target", "Version", "Status", "Drift"], rows=shared_bad,
                           remediation="Reset the landing zone, or reset the enabled baseline on "
                                       f"the affected target. See {DOC}/resolve-drift.html"))
    if member_bad:
        report.add(Finding("baselines_drift", WARNING,
                           f"{len(member_bad)} baseline(s) unhealthy on a member account or OU",
                           "A landing-zone update does not update enrolled accounts, so this does "
                           "not block the update itself. It is repairable drift that must still be "
                           "resolved in the account-update phase that follows, or those accounts "
                           "will not receive the new controls.",
                           cols=["Target", "Version", "Status", "Drift"], rows=member_bad,
                           remediation="Update the account for account-level drift, or re-register "
                                       "the OU for OU-level drift. See "
                                       f"{DOC}/update-existing-accounts.html"))
    if not shared_bad and not member_bad:
        report.add(Finding("baselines_drift", PASS,
                           f"All {len(baselines)} enabled baselines SUCCEEDED / IN_SYNC"
                           f"{_scope_suffix(no_status)}"))


def check_stale_baseline_targets(ctx: Context, report: Report) -> None:
    """Enabled baselines whose target OU no longer exists in AWS Organizations.

    Deleting an OU in Organizations without first deregistering it from Control Tower
    leaves Control Tower holding a reference to an OU that is gone. A later
    landing-zone update calls ListPoliciesForTarget against the missing OU, fails with
    TargetNotFoundException, and leaves the landing zone FAILED — which also blocks
    registering OUs and enabling controls. Clearing the stale reference is done on the
    Control Tower side, so the customer cannot simply retry. Worth knowing before
    starting an update that does not roll back.
    """
    try:
        existing = {ou["Arn"] for ou in ctx.all_ou_arns()}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stale_baseline_targets", UNKNOWN,
                           "Could not enumerate OUs to validate baseline targets", str(e)))
        return
    try:
        baselines = _collect(ctx.ct, "list_enabled_baselines", "enabledBaselines",
                             includeChildren=True)
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stale_baseline_targets", UNKNOWN,
                           "Could not list enabled baselines", str(e)))
        return
    # A baseline target is either an OU ARN or an account ARN. Only OU targets can be
    # validated against the OU tree; account targets are covered by other checks.
    ou_targets = [b for b in baselines if ":ou/" in str(b.get("targetIdentifier") or "")]
    stale = [[str(b.get("targetIdentifier") or ""),
              str(b.get("baselineVersion") or ""),
              str((b.get("statusSummary") or {}).get("status") or "")]
             for b in ou_targets
             if str(b.get("targetIdentifier") or "") not in existing]
    if stale:
        report.add(Finding("stale_baseline_targets", WARNING,
                           f"{len(stale)} enabled baseline(s) target an OU that no longer exists",
                           "Control Tower still has a baseline enabled on an organizational unit "
                           "that is not present in AWS Organizations, which happens when an OU is "
                           "deleted directly in Organizations without being deregistered from "
                           "Control Tower first. A landing-zone update reads the policies attached "
                           "to each OU it knows about; when one is missing the update fails with "
                           "TargetNotFoundException and the landing zone is left in FAILED state, "
                           "which then also blocks registering OUs and enabling controls. Resolve "
                           "this before starting an update, because the update does not roll back.",
                           cols=["Baseline target (missing OU)", "Baseline version", "Status"],
                           rows=stale,
                           remediation="Confirm the OU is genuinely gone, then raise an AWS Support "
                                       "case to clear the stale reference from Control Tower's "
                                       "configuration. Deregister an OU in Control Tower BEFORE "
                                       "deleting it in Organizations to avoid this."))
    elif ou_targets:
        report.add(Finding("stale_baseline_targets", PASS,
                           f"All {len(ou_targets)} OU-targeted baseline(s) reference an OU that "
                           f"still exists"))
    else:
        report.add(Finding("stale_baseline_targets", PASS,
                           "No OU-targeted baselines to validate"))


# StackSets whose failed stack instances are NOT a reliable signal of a real problem.
#
# AWSControlTowerExecutionRole deploys the AWSControlTowerExecution role into accounts when
# an OU is registered or re-registered. That role is very often already present — AWS
# Organizations creates it with the account, or someone created it by hand — so the instance
# fails while the end state Control Tower wanted is already true. Both the Control Tower
# service team and an independent Control Tower SME state that failed instances on this
# StackSet are expected, do not block a landing-zone update or OU registration, and do not
# indicate that the role is missing; organizations with hundreds of them upgrade normally.
#
# So the instance state is the wrong thing to judge. Whether the role actually exists and is
# assumable is answered by check_member_execution_roles (--check-member-roles), which assumes
# into each account instead of inferring from a stack instance.
#
# Deliberately narrow: only this StackSet. A failure on a *baseline* StackSet is a real
# problem, and an "already exists" collision there usually means a previously deleted
# StackSet left resources behind — a common cause of repair failures on a broken landing zone.
_UNRELIABLE_FAILURE_STACKSETS = ("AWSControlTowerExecutionRole",)

# The one failure reason that is positively benign: the role Control Tower wanted to create
# is already there. Any other reason on the same StackSet is still not a blocker, but it is
# unexplained and worth a look rather than silence.
_BENIGN_FAILURE_REASON = "already exists"


def _is_unreliable_failure_signal(stackset: str) -> bool:
    """True when a failed stack instance on this StackSet does not indicate a real problem."""
    return stackset in _UNRELIABLE_FAILURE_STACKSETS


def _short_reason(text: str, limit: int = 100) -> str:
    """Collapse a CloudFormation StatusReason to one readable line for a report row."""
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def check_stacksets(ctx: Context, report: Report) -> None:
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        names = [s["StackSetName"] for s in
                 _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")
                 if s["StackSetName"].startswith("AWSControlTower")]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stacksets", UNKNOWN,
                           "Could not list CloudFormation StackSets", str(e)))
        return
    # Current org accounts — instances for accounts no longer in the org are
    # orphaned StackSet leftovers (StackSets don't auto-delete on account removal)
    # and are NOT acted on by a landing-zone update, so they must not block it.
    try:
        org_ids = {a["Id"] for a in _collect(ctx.orgs, "list_accounts", "Accounts")}
    except (ClientError, BotoCoreError):
        org_ids = None  # couldn't verify membership; don't suppress anything
    # Shared/core accounts (management, log archive, audit) are what a landing-zone
    # update/repair/reset actually acts on; member accounts are updated separately
    # afterward (Re-register OU). So only shared-account instances are hard blockers.
    shared = ctx.shared_accounts

    shared_bad, member_bad, outdated, orphaned = [], [], [], []
    expected, unexplained, drifted = [], [], []
    skipped: List[List[str]] = []
    for name in names:
        try:
            insts = _collect(cfn, "list_stack_instances", "Summaries", StackSetName=name)
        except (ClientError, BotoCoreError) as e:
            # This check emits only BLOCKER or PASS, so a silent skip here can turn a real
            # blocker into a clean report. Record the StackSet as unread instead.
            skipped.append([name, _error_code(e), _skip_note(e)])
            continue
        for i in insts:
            status = i.get("Status")  # summary status: CURRENT | OUTDATED | INOPERABLE
            detailed = (i.get("StackInstanceStatus") or {}).get("DetailedStatus")
            drift = i.get("DriftStatus")
            acct = i.get("Account", "")
            # Why the instance is in this state. Grading a failure without reading this
            # cannot tell an expected collision apart from a real problem.
            reason = i.get("StatusReason") or ""
            # Show summary + detailed when they differ (e.g. OUTDATED/FAILED) so the
            # real signal isn't hidden behind the summary status.
            status_disp = str(status or detailed)
            if detailed and detailed != status:
                status_disp = f"{status}/{detailed}"
            row = [name, acct, i.get("Region", ""), status_disp, str(drift)]
            # Orphaned: target account has left the org -> stale leftover, not a blocker.
            if org_ids is not None and acct and acct not in org_ids:
                orphaned.append(row)
                continue
            drift_bad = (drift == "DRIFTED" and not getattr(ctx, "detect_drift", False))
            # A failed/inoperable instance and a drifted one are different signals with
            # different severities, so they are classified separately. A hard failure wins
            # when an instance is both.
            hard_bad = (status == "INOPERABLE"
                        or detailed in ("FAILED", "INOPERABLE", "CANCELLED"))
            # Drift and failure are independent facts about the same instance, so a drifted
            # instance is recorded even when it also failed — otherwise a benign collision
            # would swallow a real out-of-band change.
            if drift_bad:
                drifted.append(row + [_short_reason(reason)])
            if hard_bad:
                # Severity follows the failure REASON and the StackSet, not the account tier.
                # A failed instance on AWSControlTowerExecutionRole is never a blocker in any
                # account, because the instance state does not tell you whether the role
                # exists.
                if _is_unreliable_failure_signal(name):
                    # Decide this on the FULL reason. _short_reason truncates for display and
                    # would cut the tail off a long CloudFormation reason string.
                    _bucket = (expected if _BENIGN_FAILURE_REASON in reason.lower()
                               else unexplained)
                    _bucket.append(row + [_short_reason(reason)])
                else:
                    (shared_bad if acct in shared else member_bad).append(
                        row + [_short_reason(reason)])
            elif not drift_bad and status == "OUTDATED":
                # Behind the current template. NOT refreshed by the landing-zone update itself —
                # enrolled accounts are updated separately, by re-registering/resetting the OU.
                outdated.append(row)
    _report_partial_scope(report, "stacksets", "AWSControlTower StackSet(s)", skipped)
    if shared_bad:
        report.add(Finding("stacksets", BLOCKER,
                           f"{len(shared_bad)} AWSControlTower* StackSet instance(s) inoperable/failed "
                           "in shared accounts",
                           "INOPERABLE/FAILED instances in the management account or a "
                           "service-integration account (Audit, Log archive, Config, Backup) block "
                           "the landing-zone update — Control Tower manages those accounts through "
                           "the landing zone, so they are exactly what the update/repair/reset "
                           "acts on.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift", "Reason"],
                           rows=shared_bad,
                           remediation="Repair or remove (Retain Stacks) the affected shared-account "
                                       "instances before upgrading."))
    if member_bad:
        report.add(Finding("stacksets_member", WARNING,
                           f"{len(member_bad)} AWSControlTower* StackSet instance(s) inoperable/failed "
                           "in member accounts",
                           "These are in member (non-shared) accounts. A landing-zone update/repair/reset "
                           "acts on the shared accounts first and does not touch member accounts, so this "
                           "does NOT block the landing-zone update. It can, however, affect that account "
                           "when you later update/re-register its OU — worth reconciling.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift", "Reason"],
                           rows=member_bad,
                           remediation="Reconcile (repair/revert) before you update or re-register that "
                                       "account's OU."))
    if expected or unexplained:
        _rows = expected + unexplained
        report.add(Finding("stacksets_expected", WARNING if unexplained else INFO,
                           f"{len(_rows)} AWSControlTowerExecutionRole instance(s) failed"
                           + (f", {len(unexplained)} for a reason other than an expected collision"
                              if unexplained else " with an expected \"already exists\" collision"),
                           "This StackSet deploys the AWSControlTowerExecution role when an OU "
                           "is registered. The role is frequently already present — AWS "
                           "Organizations creates it with the account — so the instance fails "
                           "while the end state Control Tower wanted is already true. Failed "
                           "instances here are expected, are not a landing-zone-update or OU "
                           "registration blocker in any account, and do NOT show that the role "
                           "is missing: the instance state is not a reliable signal either way. "
                           + ("Some failed for another reason, which is worth understanding even "
                              "though it still does not block an update. " if unexplained else ""),
                           cols=["StackSet", "Account", "Region", "Status", "Drift", "Reason"],
                           rows=_rows,
                           remediation="Do not delete the role to \"fix\" this — that would break "
                                       "Control Tower's access to the account. To confirm the role "
                                       "really exists and is assumable, re-run with "
                                       "--check-member-roles, which assumes into each account "
                                       "instead of inferring from stack-instance state."))
    if drifted:
        report.add(Finding("stacksets_drifted", WARNING,
                           f"{len(drifted)} AWSControlTower* StackSet instance(s) report "
                           "DRIFTED",
                           "Stored drift status on Control Tower's own StackSet instances. This "
                           "is a repairable change, not one of the four drift types "
                           "drift.html says to resolve right away, and on landing zone 3.1 and "
                           "later \"drift is resolved as part of the update process\" "
                           "(resolve-drift.html) — a landing-zone update was observed "
                           "succeeding with drifted instances present in a shared account. So "
                           "this does not block the update, in any account. It is still worth "
                           "reconciling: the update resolves drift by reasserting Control "
                           "Tower's intent, which means an out-of-band change you wanted to "
                           "keep is the thing that gets reverted. The drift types that DO block "
                           "are covered separately — missing required IAM roles (check 13) and "
                           "in-progress StackSet operations (check 18).",
                           cols=["StackSet", "Account", "Region", "Status", "Drift", "Reason"],
                           rows=drifted,
                           remediation="Review what changed out of band and decide whether to "
                                       "revert it or update the StackSet to match, before the "
                                       "upgrade reasserts Control Tower's version. Run with "
                                       "--detect-drift for resource-level detail; stored status "
                                       "is only as fresh as the last detection."))
    if orphaned:
        report.add(Finding("stacksets_orphaned", INFO,
                           f"{len(orphaned)} stale StackSet instance(s) target accounts no longer in the org",
                           "These instances belong to account(s) that have left the organization. "
                           "Control Tower does not act on them during a landing-zone update, so they "
                           "do NOT block it — but they are safe to clean up.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift"], rows=orphaned,
                           remediation="Optionally delete these stale instances "
                                       "(DeleteStackInstances with RetainStacks) to tidy up."))
    if not shared_bad and not member_bad and not drifted:
        if outdated:
            report.add(Finding("stacksets", INFO,
                               f"{len(outdated)} StackSet instance(s) are OUTDATED (expected)",
                               "OUTDATED means the instances are behind the current template. A "
                               "landing-zone update does NOT refresh them: \"When you perform a "
                               "landing-zone update, you must update your enrolled accounts to "
                               "apply new controls to those accounts.\" Re-register or reset each "
                               "registered OU after the update, or those accounts keep the old "
                               "template. No inoperable/failed/drifted instances were found.",
                               cols=["StackSet", "Account", "Region", "Status", "Drift"],
                               rows=outdated))
        elif not orphaned and not expected and not unexplained:
            report.add(Finding("stacksets", PASS,
                               f"All instances CURRENT across {len(names)} AWSControlTower "
                               f"StackSet(s){_scope_suffix(skipped)}"))


def _resource_drift_detail(ctx: "Context", acct: str, region: str, stack_id) -> str:
    """Best-effort resource-level drift detail for a drifted instance.

    Assumes ctx.member_role (default AWSControlTowerExecution) into the account and
    reads describe_stack_resource_drifts. If the role is missing/not assumable, or
    anything else goes wrong, returns a fallback pointing the operator at the stack
    to inspect in-account (never raises)."""
    if not stack_id:
        return "no StackId on instance — inspect the stack in that account's CloudFormation console"
    try:
        cfn = ctx.assume(acct, region, "cloudformation")
        drifts = _collect(cfn, "describe_stack_resource_drifts", "StackResourceDrifts",
                          StackName=stack_id,
                          StackResourceDriftStatusFilters=["MODIFIED", "DELETED"])
    except Exception as e:  # role missing / AccessDenied / any SDK error -> fall back
        return (f"'{ctx.member_role}' not assumable in {acct} ({type(e).__name__}) — "
                f"inspect stack {stack_id} in that account directly")
    if not drifts:
        return ("drift reported but no MODIFIED/DELETED resources returned — "
                "inspect the stack in-account")
    parts = []
    for d in drifts[:5]:
        props = ",".join(p.get("PropertyPath", "")
                         for p in (d.get("PropertyDifferences") or [])[:4])
        parts.append(f"{d.get('ResourceType')}/{d.get('LogicalResourceId')}:"
                     f"{d.get('StackResourceDriftStatus')}" + (f"[{props}]" if props else ""))
    return "; ".join(parts) + ("" if len(drifts) <= 5 else f" (+{len(drifts) - 5} more)")


def _progress(msg: str) -> None:
    """Transient progress to stderr. stdout carries only the report, so a caller piping or
    redirecting output, or reading --json, is unaffected. On a terminal this redraws one
    line; otherwise it writes plain lines, which is what a CI log wants."""
    if sys.stderr.isatty():
        print(f"\r  {msg:<74.74}", end="", file=sys.stderr, flush=True)
    else:
        print(f"  {msg}", file=sys.stderr, flush=True)


def check_stackset_active_drift(ctx: Context, report: Report) -> None:
    """OPT-IN (--detect-drift): actively run CloudFormation StackSet drift detection on
    the AWSControlTower* StackSets to catch out-of-band changes to CT-deployed stack
    resources. The default (off) only reads stored DriftStatus, which stays NOT_CHECKED
    until a detection has actually been run — so out-of-band stack edits are otherwise
    invisible. This launches StackSet drift operations and can take several minutes."""
    if not getattr(ctx, "detect_drift", False):
        report.add(Finding("stackset_drift", INFO,
                           "Active StackSet drift detection skipped (opt-in)",
                           "The StackSet DriftStatus reported above is only as fresh as the last "
                           "drift-detection run (frequently NOT_CHECKED). Out-of-band edits to "
                           "resources inside CT-deployed stacks are NOT detected without this.",
                           remediation="Re-run with --detect-drift to actively detect drift "
                                       "(slower; launches StackSet drift operations)."))
        return

    import time
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        names = [s["StackSetName"] for s in
                 _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")
                 if s["StackSetName"].startswith("AWSControlTower")]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stackset_drift", UNKNOWN,
                           "Could not list StackSets for drift detection", str(e)))
        return
    try:
        org_ids = {a["Id"] for a in _collect(ctx.orgs, "list_accounts", "Accounts")}
    except (ClientError, BotoCoreError):
        org_ids = None

    # One shared budget across all StackSets, not per StackSet: a precheck that can run for
    # an unbounded time is useless in a pipeline. The loop below must therefore check it
    # BEFORE starting each detection, or it would fire a real CloudFormation operation and
    # then abandon it immediately, reporting a timeout it never had a chance to beat.
    deadline = time.time() + getattr(ctx, "drift_timeout", 900)
    failed = []
    in_flight = []  # operations known to be still running when the budget ran out
    for _n, name in enumerate(names, 1):
        remaining = deadline - time.time()
        if remaining <= 0:
            # Budget spent. Do not start this one at all.
            failed.append([name, "not_started",
                           "the --drift-timeout budget was spent on earlier StackSets; "
                           "no operation was started for this one"])
            continue
        _progress(f"drift detection [{_n}/{len(names)}] {name} "
                  f"({int(remaining)}s of budget left)")
        try:
            op = cfn.detect_stack_set_drift(StackSetName=name)["OperationId"]
        except (ClientError, BotoCoreError) as e:
            failed.append([name, "detect_start_failed", str(e)[:80]])
            continue
        while True:
            try:
                st = cfn.describe_stack_set_operation(
                    StackSetName=name, OperationId=op)["StackSetOperation"]["Status"]
            except (ClientError, BotoCoreError) as e:
                failed.append([name, "poll_failed", str(e)[:80]])
                break
            if st in ("SUCCEEDED", "FAILED", "STOPPED"):
                if st != "SUCCEEDED":
                    failed.append([name, f"operation_{st}", ""])
                break
            if time.time() > deadline:
                in_flight.append(name)
                failed.append([name, "timeout",
                               "still running at timeout; deliberately not stopped - see the "
                               "finding detail and check #18 below"])
                break
            # Never sleep past the budget: otherwise each StackSet can overshoot it by a
            # whole poll interval, and with several StackSets that adds up.
            time.sleep(max(0.0, min(10.0, deadline - time.time())))

    shared = ctx.shared_accounts
    shared_drifted, member_drifted, orphaned_drifted = [], [], []
    for name in names:
        try:
            insts = _collect(cfn, "list_stack_instances", "Summaries", StackSetName=name)
        except (ClientError, BotoCoreError) as e:
            # Route into `failed`, which already suppresses the PASS below, so an unread
            # StackSet cannot read as "no drift".
            failed.append([name, "list_instances_failed", _skip_note(e)])
            continue
        for i in insts:
            if i.get("DriftStatus") != "DRIFTED":
                continue
            acct = i.get("Account", "")
            region = i.get("Region", "")
            status = str(i.get("Status") or (i.get("StackInstanceStatus") or {}).get("DetailedStatus"))
            if org_ids is not None and acct and acct not in org_ids:
                orphaned_drifted.append([name, acct, region, status, "DRIFTED"])
                continue
            # Drill into what actually drifted (assume role); fall back if the
            # AWSControlTowerExecution role isn't there.
            detail = _resource_drift_detail(ctx, acct, region, i.get("StackId"))
            row = [name, acct, region, status, "DRIFTED", detail]
            (shared_drifted if acct in shared else member_drifted).append(row)

    if shared_drifted:
        report.add(Finding("stackset_drift", WARNING,
                           f"{len(shared_drifted)} AWSControlTower* StackSet instance(s) DRIFTED in "
                           "shared accounts (out-of-band changes)",
                           "Active drift detection found resource-level drift in CT-deployed stacks "
                           "in the management account or a service-integration account (Audit, Log "
                           "archive, Config, Backup). This does NOT block the update: drift.html "
                           "lists four drift types to resolve right away and resource drift inside "
                           "a StackSet is not among them, and on landing zone 3.1 and later "
                           "\"drift is resolved as part of the update process\" "
                           "(resolve-drift.html) — a landing-zone update was observed succeeding "
                           "with drifted instances present in a shared account. Reconcile it "
                           "anyway, and before the upgrade: the update resolves drift by "
                           "reasserting Control Tower's intent, so an out-of-band change you "
                           "meant to keep is what gets reverted. The last column shows the "
                           "drifted resource(s) when the role is assumable, else where to look.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift",
                                 "Drifted resources / where to look"], rows=shared_drifted,
                           remediation="Decide per resource whether to revert the out-of-band "
                                       "change or update the StackSet to match, before upgrading."))
    if member_drifted:
        report.add(Finding("stackset_drift_member", WARNING,
                           f"{len(member_drifted)} AWSControlTower* StackSet instance(s) DRIFTED in "
                           "member accounts (out-of-band changes)",
                           "Drift in member (non-shared) accounts. A landing-zone update/repair/reset "
                           "acts on the shared accounts first and does not touch member accounts, so "
                           "this does NOT block the landing-zone update — but it will matter when you "
                           "later update/re-register that account's OU. The last column shows the "
                           "drifted resource(s) when the role is assumable, else where to look.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift",
                                 "Drifted resources / where to look"], rows=member_drifted,
                           remediation="Reconcile before updating or re-registering that account's OU."))
    if orphaned_drifted:
        report.add(Finding("stackset_drift_orphaned", INFO,
                           f"{len(orphaned_drifted)} DRIFTED instance(s) target accounts no longer in the org",
                           "Drifted, but for departed accounts — stale leftovers, not a blocker.",
                           cols=["StackSet", "Account", "Region", "Status", "Drift"],
                           rows=orphaned_drifted))
    if failed:
        _not_started = [r[0] for r in failed if r[1] == "not_started"]
        _detail = (
            "Their drift state is unverified (detection failed, timed out, or was never "
            "started).\n"
            "--drift-timeout is one budget shared across all StackSets, not a per-StackSet "
            "allowance. When it runs out, remaining StackSets are listed as 'not_started' "
            "and no operation is launched for them, so nothing is reported as a timeout it "
            "never had a chance to beat. Raise --drift-timeout to cover them.\n"
            "A timeout does NOT stop an operation that had already started, and that is "
            "deliberate: drift detection makes no changes to your resources and finishes on "
            "its own, whereas calling StopStackSetOperation would leave the StackSet in "
            "STOPPING - a state that blocks a landing-zone update exactly as RUNNING does. "
            "Control Tower cannot update a landing zone while any operation on its StackSets "
            "is in progress, so an operation still active here is reported as a BLOCKER by "
            "check #18 (in-progress StackSet operations), which runs immediately after this "
            "check in the same invocation. This finding is itself UNKNOWN, which fails the "
            "exit code by default.")
        if in_flight:
            _detail += ("\nStill running when this check gave up, and very likely still "
                        "running now: " + ", ".join(in_flight) + ". They will finish on "
                        "their own; re-run the precheck to confirm.")
        if _not_started:
            _detail += (f"\nNever started for want of budget: {len(_not_started)} StackSet(s).")
        report.add(Finding("stackset_drift", UNKNOWN,
                           f"Drift detection did not complete for {len(failed)} StackSet(s)",
                           _detail,
                           cols=["StackSet", "Reason", "Detail"], rows=failed,
                           remediation="Re-run the precheck to confirm any in-flight operation "
                                       "has finished, and raise --drift-timeout so the budget "
                                       "covers every StackSet. Do not start the upgrade while "
                                       "check #18 reports an in-progress operation, or check "
                                       "StackSet drift-detection permissions if detection "
                                       "failed outright."))
    if not shared_drifted and not member_drifted and not failed:
        report.add(Finding("stackset_drift", PASS,
                           f"Active drift detection: no drift across {len(names)} "
                           "AWSControlTower StackSet(s)"))


def check_config_in_shared_accounts(ctx: Context, report: Report) -> None:
    """Flag AWS Config recorders and delivery channels in the Audit/Log Archive shared accounts
    that Control Tower did not create, which can block a landing-zone update.

    Control Tower names its own resources aws-controltower-*, so anything otherwise named is
    pre-existing or foreign and is flagged regardless of how many exist. That matters: the
    canonical documented blocker is a Region newly entering governance where the customer already
    has a Config recorder and Control Tower has not deployed its own yet - a count-based test
    ("more than one recorder") cannot see that case.

    On landing zone 4.0+ the AWS Config integration is optional and may use a dedicated Config
    account, so the absence of a Control Tower recorder is not itself a problem. The check
    degrades to UNKNOWN when the shared accounts cannot be resolved or assumed.
    """
    targets = []
    if ctx.audit_account:
        targets.append(("Audit", ctx.audit_account))
    if ctx.log_archive_account:
        targets.append(("LogArchive", ctx.log_archive_account))
    if not targets:
        report.add(Finding("config_shared", UNKNOWN,
                           "Could not determine Audit/Log Archive account IDs from the LZ "
                           "manifest; skipped shared-account Config check.",
                           remediation="Pass --audit-account / --log-archive-account to force it."))
        return
    findings_rows = []
    unknown = False
    for label, acct in targets:
        for region in ctx.governed_regions:
            try:
                cfg = ctx.assume(acct, region, "config")
                # Control Tower names its own resources aws-controltower-*; anything else is
                # pre-existing or foreign. Counting recorders (> 1) misses the canonical
                # documented blocker: in a Region newly entering governance, Control Tower has
                # not deployed its own recorder yet, so a single pre-existing customer recorder
                # counts as 1 and would not be flagged - which is exactly the case that blocks
                # the update.
                for rec in cfg.describe_configuration_recorders().get(
                        "ConfigurationRecorders", []):
                    nm = rec.get("name") or ""
                    if "aws-controltower" not in nm:
                        findings_rows.append([label, acct, region,
                                              "Config recorder", nm or "(unnamed)"])
                for dc in cfg.describe_delivery_channels().get("DeliveryChannels", []):
                    nm = dc.get("name") or ""
                    if "aws-controltower" not in nm:
                        findings_rows.append([label, acct, region,
                                              "Config delivery channel", nm or "(unnamed)"])
            except (ClientError, BotoCoreError):
                unknown = True
    if findings_rows:
        report.add(Finding("config_shared", WARNING,
                           f"{len(findings_rows)} non-Control Tower AWS Config resource(s) in "
                           "shared accounts",
                           "AWS Config recorders or delivery channels that Control Tower did not "
                           "create (name is not aws-controltower-*) in the Audit or Log Archive "
                           "accounts can block a landing-zone update. This is most commonly hit "
                           "when a Region is newly brought into governance and a pre-existing "
                           "customer recorder is already present there.",
                           cols=["Account Type", "Account", "Region", "Resource", "Name"],
                           rows=findings_rows,
                           remediation=f"{DOC}/existing-config-resources.html - remove or "
                                       "reconcile the pre-existing Config resource(s) before "
                                       "upgrading."))
    elif unknown:
        report.add(Finding("config_shared", UNKNOWN,
                           "Could not assume role into one or more shared accounts to inspect "
                           "AWS Config. Verify manually.",
                           remediation="Grant the precheck --member-role in the shared accounts."))
    else:
        report.add(Finding("config_shared", PASS,
                           "No non-Control Tower Config recorders or delivery channels in the "
                           "Audit/Log Archive shared accounts"))


_CT_BUCKET_PREFIX = "aws-controltower-"

# Buckets the AWSControlTowerLoggingResources StackSet creates, so CloudFormation owns them
# and they carry its automatic aws:cloudformation:* tags. Control Tower creates other
# aws-controltower-* buckets outside CloudFormation, so the unmanaged-bucket test is confined
# to these two families to avoid flagging a healthy landing zone.
_CFN_MANAGED_BUCKET_PREFIXES = (
    "aws-controltower-logs-",
    "aws-controltower-s3-access-logs-",
)


def check_log_archive_bucket_state(ctx: Context, report: Report) -> None:
    """S3 state on the Control Tower logging buckets that blocks an update or reset.

    Three conditions, each with its own severity:

    - Requester Pays, a documented hard prerequisite. configuration-updates.html:
      "Before you update or reset your landing zone, be sure that the Amazon S3 logging
      bucket for the Log Archive account does not have the Requester Pays feature enabled.
      You must turn off that feature before you begin the Update or Reset process."
      Graded BLOCKER, because the documentation makes it a precondition rather than a risk.

    - S3 Object Lock carrying a default retention rule. AWS Config cannot deliver to such a
      bucket, so the delivery channel fails with InsufficientDeliveryPolicyException and the
      Config baseline stack fails with it. Graded BLOCKER: the failure is in the baseline
      the update deploys. Object Lock with the flag on but no default retention rule is a
      WARNING instead - it does not break delivery, but the flag cannot be turned off again,
      which blocks using the bucket as an access-logging destination and means a later reset
      can collide on the persisted bucket name.

    - A CloudFormation-managed logging bucket that carries no CloudFormation stack tag. If
      the bucket exists outside the StackSet's control, the StackSet fails with AlreadyExists
      when it tries to create it. CloudFormation applies aws:cloudformation:* tags to the
      resources it creates automatically, so their absence is the available signal - but tags
      can also be removed by hand, so this is a WARNING to verify, not a blocker.

    Read-only throughout. Requires the precheck role in the Log Archive account; without it
    the check reports UNKNOWN rather than silently passing.
    """
    # On landing zone 4.0+ the CentralizedLogging integration is optional. When it is
    # explicitly disabled there is no Log Archive account and no Control Tower logging
    # bucket, so there is nothing to verify - that is "not applicable", not "unverified",
    # and must not gate the run. An absent flag is not a disabled flag: earlier manifests
    # omit it entirely, so only an explicit False skips the check.
    if _integration_enabled(ctx, "centralizedLogging") is False:
        report.add(Finding("log_archive_buckets", INFO,
                           "CentralizedLogging integration is disabled, so there is no Control "
                           "Tower logging bucket to check"))
        return

    acct = ctx.log_archive_account
    if not acct:
        report.add(Finding("log_archive_buckets", UNKNOWN,
                           "Could not determine the Log Archive account id; skipped the S3 "
                           "logging-bucket checks",
                           "The account id comes from the landing-zone manifest. The "
                           "CentralizedLogging integration is enabled (or its state is not "
                           "stated), so the logging buckets should exist and could not be "
                           "verified.",
                           remediation="Pass --log-archive-account to force it."))
        return

    try:
        s3_home = ctx.assume(acct, ctx.region, "s3")
        buckets = [b["Name"] for b in s3_home.list_buckets().get("Buckets", [])
                   if str(b.get("Name", "")).startswith(_CT_BUCKET_PREFIX)]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("log_archive_buckets", UNKNOWN,
                           "Could not list S3 buckets in the Log Archive account", str(e),
                           remediation=f"Grant the precheck --member-role in {acct} with "
                                       "s3:ListAllMyBuckets, or verify manually that Requester "
                                       "Pays is off and Object Lock is not enabled on the "
                                       "Control Tower logging buckets."))
        return

    if not buckets:
        report.add(Finding("log_archive_buckets", UNKNOWN,
                           "No aws-controltower-* buckets found in the Log Archive account",
                           "A landing zone normally has at least one. Either the account id is "
                           "wrong or the buckets are not visible to the precheck role.",
                           remediation="Confirm the Log Archive account id and the role's "
                                       "s3:ListAllMyBuckets permission."))
        return

    blockers: List[List[str]] = []
    warnings: List[List[str]] = []
    skipped: List[List[str]] = []
    clients: Dict[str, Any] = {ctx.region: s3_home}

    for name in sorted(buckets):
        try:
            loc = s3_home.get_bucket_location(Bucket=name).get("LocationConstraint")
            region = loc or "us-east-1"          # the API returns None for us-east-1
            if region not in clients:
                clients[region] = ctx.assume(acct, region, "s3")
            s3 = clients[region]
        except (ClientError, BotoCoreError) as e:
            skipped.append([name, _error_code(e), _skip_note(e)])
            continue

        try:
            payer = s3.get_bucket_request_payment(Bucket=name).get("Payer")
            if payer == "Requester":
                blockers.append([name, region, "Requester Pays is enabled"])
        except (ClientError, BotoCoreError) as e:
            skipped.append([name, _error_code(e), _skip_note(e)])

        try:
            olc = s3.get_object_lock_configuration(Bucket=name).get(
                "ObjectLockConfiguration", {})
            if olc.get("ObjectLockEnabled") == "Enabled":
                if olc.get("Rule"):
                    blockers.append([name, region,
                                     "Object Lock enabled with a default retention rule"])
                else:
                    warnings.append([name, region,
                                     "Object Lock enabled (no default retention rule)"])
        except (ClientError, BotoCoreError) as e:
            # Not enabled is reported as an error condition, which is the healthy case.
            if _error_code(e) not in ("ObjectLockConfigurationNotFoundError",):
                skipped.append([name, _error_code(e), _skip_note(e)])

        if name.startswith(_CFN_MANAGED_BUCKET_PREFIXES):
            try:
                tags = {t["Key"] for t in
                        s3.get_bucket_tagging(Bucket=name).get("TagSet", [])}
                if not any(k.startswith("aws:cloudformation:") for k in tags):
                    warnings.append([name, region,
                                     "No aws:cloudformation:* tag, so it may exist outside "
                                     "StackSet control"])
            except (ClientError, BotoCoreError) as e:
                if _error_code(e) in ("NoSuchTagSet", "NoSuchTagSetError"):
                    warnings.append([name, region,
                                     "No tags at all, so it may exist outside StackSet control"])
                else:
                    skipped.append([name, _error_code(e), _skip_note(e)])

    _report_partial_scope(report, "log_archive_buckets", "Log Archive bucket(s)", skipped)

    if blockers:
        report.add(Finding("log_archive_buckets", BLOCKER,
                           f"{len(blockers)} Control Tower logging bucket(s) in a state that "
                           "blocks an update",
                           "Requester Pays must be turned off before an update or reset - the "
                           "documentation states it as a precondition, not a risk. S3 Object "
                           "Lock with a default retention rule stops AWS Config delivering to "
                           "the bucket, so the Config delivery channel fails with "
                           "InsufficientDeliveryPolicyException and the baseline stack fails "
                           "with it.",
                           cols=["Bucket", "Region", "Problem"], rows=blockers,
                           remediation="Turn off Requester Pays on the logging bucket. For a "
                                       "default retention rule, remove the rule with "
                                       "PutObjectLockConfiguration (keeping ObjectLockEnabled); "
                                       "existing locked objects stay protected. Note that "
                                       "Control Tower treats a direct change as drift and may "
                                       "revert it, so engage AWS Support for a durable fix."))
    if warnings:
        report.add(Finding("log_archive_buckets", WARNING,
                           f"{len(warnings)} Control Tower logging bucket(s) need review",
                           "The Object Lock flag cannot be turned off once enabled. A bucket "
                           "carrying it cannot be a server-access-logging destination, and a "
                           "reset reuses the persisted bucket name, so a later reset can fail "
                           "on a name collision. A CloudFormation-created bucket with no "
                           "aws:cloudformation:* tag may exist outside the StackSet's control, "
                           "in which case the StackSet fails with AlreadyExists when it tries "
                           "to create it - though the tags may simply have been removed.",
                           cols=["Bucket", "Region", "Problem"], rows=warnings,
                           remediation="Confirm in CloudFormation whether the bucket belongs to "
                                       "the AWSControlTowerLoggingResources StackSet, and engage "
                                       "AWS Support before an update if Object Lock is on."))
    if not blockers and not warnings and not skipped:
        report.add(Finding("log_archive_buckets", PASS,
                           f"{len(buckets)} Control Tower logging bucket(s) checked: Requester "
                           "Pays off, no Object Lock, CloudFormation-managed"))


def check_customizations(ctx: Context, report: Report) -> None:
    """Detect CfCT / AFT / custom StackSets so the operator knows to prune region-scoped
    custom stack instances before a region-expanding upgrade."""
    signals = []
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        stacks = _collect(cfn, "list_stacks", "StackSummaries")
        names = [s["StackName"] for s in stacks
                 if s.get("StackStatus") not in ("DELETE_COMPLETE",)]
        if any("CustomControlTower" in n or "customizations-for" in n.lower() for n in names):
            signals.append(["CfCT", "Customizations for Control Tower stack present"])
        custom_ss = [s["StackSetName"] for s in
                     _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")
                     if s["StackSetName"].startswith("CustomControlTower")
                     or not s["StackSetName"].startswith("AWSControlTower")]
        if custom_ss:
            signals.append(["Custom StackSets", ", ".join(custom_ss[:10])])
    except (ClientError, BotoCoreError):
        pass
    try:
        accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
        if any("AFT" in (a.get("Name") or "") or "account-factory-for-terraform"
               in (a.get("Name") or "").lower() for a in accounts):
            signals.append(["AFT", "An AFT management account appears to exist"])
    except (ClientError, BotoCoreError):
        pass
    if signals:
        report.add(Finding("customizations", INFO,
                           "Customizations detected — review before upgrading",
                           "If any custom StackSet deploys into a region you are about to add "
                           "to governance, delete those stack instances first or the upgrade "
                           "will fail.",
                           cols=["Type", "Detail"], rows=signals,
                           remediation="See the CfCT/AFT docs and "
                                       f"{DOC}/lz-update-best-practices.html"))
    else:
        report.add(Finding("customizations", INFO,
                           "No CfCT/AFT/custom StackSet signals detected (best-effort)"))


# Required Control Tower management-account IAM roles (must exist for updates/repairs).
# Core Control Tower management-account service roles — required on every landing zone version.
_CORE_MGMT_ROLES = [
    "AWSControlTowerAdmin",
    "AWSControlTowerStackSetRole",
]
# The CloudTrail service role exists only while the CloudTrail / CentralizedLogging integration is
# enabled. It was implicit (and so always present) on landing zone 3.3 and earlier; from 4.0 the
# integration is optional. The version alone is not enough to decide: disabling CentralizedLogging
# on 3.3 and earlier toggled the organization trail off but RETAINED the deployed resources, while
# on 4.0 it DELETES them. So the role is only legitimately absent on a 4.0+ landing zone whose
# manifest explicitly disables CentralizedLogging, and only then must its absence not block.
#   https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html
_CLOUDTRAIL_ROLE = "AWSControlTowerCloudTrailRole"
# The organization AWS Config aggregator role is required only on landing zone versions < 4.0.
# In landing zone 4.0+ the AWS Config integration is optional, and the organization/account
# aggregators (and this role) are replaced by a service-linked Config aggregator — so the role is
# legitimately absent and its absence must NOT block an update.
#   https://docs.aws.amazon.com/controltower/latest/userguide/config-updates-v4.html
#   https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html
_CONFIG_AGGREGATOR_ROLE = "AWSControlTowerConfigAggregatorRoleForOrganizations"
# Back-compat alias: the full pre-4.0 required set.
_REQUIRED_ROLES = _CORE_MGMT_ROLES + [_CLOUDTRAIL_ROLE, _CONFIG_AGGREGATOR_ROLE]


def _lz_major_version(ctx: Context) -> Optional[int]:
    """Major version of the deployed landing zone ('4.0' -> 4). None if unknown/unparseable."""
    try:
        return int(str(ctx.lz.get("version")).split(".")[0])
    except (ValueError, AttributeError, TypeError):
        return None


def _latest_major_version(ctx: Context) -> Optional[int]:
    """Major version of the latest available landing zone. None if unknown/unparseable."""
    try:
        return int(str(ctx.lz.get("latestAvailableVersion")).split(".")[0])
    except (ValueError, AttributeError, TypeError):
        return None

# Trusted (service) access that an operating Control Tower landing zone relies on.
# The only principal AWS documents as used by Control Tower itself.
_CT_SERVICE_PRINCIPAL = "controltower.amazonaws.com"

_REQUIRED_TRUSTED_SERVICES = [
    _CT_SERVICE_PRINCIPAL,
    "member.org.stacksets.cloudformation.amazonaws.com",
    "config.amazonaws.com",
    "sso.amazonaws.com",
]


def check_trusted_access(ctx: Context, report: Report) -> None:
    """Control Tower relies on trusted (service) access in AWS Organizations.

    Only `controltower.amazonaws.com` is documented as the principal Control Tower itself uses
    (Organizations, "Service principals used by AWS Control Tower"). Its absence is a named drift
    type with a documented resolution: governance-drift.html shows the notification carrying
    DriftType TRUSTED_ACCESS_DISABLED and RemediationStep "Reset Control Tower landing zone", and
    the Organizations page states that re-enabling trusted access does NOT clear the drift. So the
    remediation for that one is a landing zone reset, not simply switching the access back on.

    The other principals are required by Control Tower's use of those services rather than by any
    documented statement, so they are listed but not attributed the same drift consequence.
    """
    try:
        enabled = {s["ServicePrincipal"] for s in _collect(
            ctx.orgs, "list_aws_service_access_for_organization", "EnabledServicePrincipals")}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("trusted_access", UNKNOWN,
                           "Could not read trusted service access", str(e)))
        return
    missing = [s for s in _REQUIRED_TRUSTED_SERVICES if s not in enabled]
    if missing:
        ct_access_missing = _CT_SERVICE_PRINCIPAL in missing
        rows = [[m, "documented Control Tower principal" if m == _CT_SERVICE_PRINCIPAL
                 else "required by Control Tower's use of this service"] for m in missing]
        if ct_access_missing:
            detail = ("Control Tower records this as TRUSTED_ACCESS_DISABLED drift. While trusted "
                      "access is off, Control Tower stops receiving organizational change events "
                      "and can miss account and OU changes.")
            remediation = ("Reset the landing zone - that is the documented resolution for this "
                           "drift type. Re-enabling trusted access in AWS Organizations does NOT "
                           "clear the drift on its own, so do not treat a subsequent PASS from "
                           f"this check as evidence the landing zone is healthy. See {DOC}"
                           "/governance-drift.html")
        else:
            detail = ("Control Tower needs trusted access for these service principals. Unlike "
                      f"{_CT_SERVICE_PRINCIPAL}, their absence is not a documented drift type.")
            remediation = ("Re-enable trusted access for the listed service principals, then "
                           "re-run this check.")
        report.add(Finding("trusted_access", BLOCKER,
                           "Required trusted access is disabled in AWS Organizations",
                           detail, cols=["Missing service principal", "Basis"], rows=rows,
                           remediation=remediation))
    else:
        report.add(Finding("trusted_access", PASS,
                           "All required trusted service access is enabled"))


def check_delegated_admins(ctx: Context, report: Report) -> None:
    """Inventory delegated administrators. Conflicting delegated admins for CloudFormation
    StackSets or Config can interfere with a landing-zone update."""
    try:
        das = _collect(ctx.orgs, "list_delegated_administrators", "DelegatedAdministrators")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("delegated_admins", UNKNOWN,
                           "Could not list delegated administrators", str(e)))
        return
    if not das:
        report.add(Finding("delegated_admins", PASS, "No delegated administrators configured"))
        return
    rows = []
    for da in das:
        try:
            svcs = _collect(ctx.orgs, "list_delegated_services_for_account",
                            "DelegatedServices", AccountId=da["Id"])
            sp = ", ".join(s.get("ServicePrincipal", "") for s in svcs)
        except (ClientError, BotoCoreError):
            sp = "(could not read services)"
        rows.append([da.get("Id", ""), da.get("Name", ""), sp])
    report.add(Finding("delegated_admins", INFO,
                       f"{len(das)} delegated administrator account(s) configured — review",
                       "Confirm these are intentional; a delegated admin for CloudFormation "
                       "StackSets or Config other than the CT-expected account can conflict "
                       "with the update.",
                       cols=["Account", "Name", "Delegated services"], rows=rows))


def check_required_iam_roles(ctx: Context, report: Report) -> None:
    """The Control Tower management-account service roles must exist for updates/repairs.

    Two roles are required on every landing zone version: AWSControlTowerAdmin and
    AWSControlTowerStackSetRole.

    Two are conditional, because landing zone 4.0 made their integrations optional, and a role
    that is legitimately absent must never produce a BLOCKER:

      * AWSControlTowerCloudTrailRole - required unless the manifest EXPLICITLY disables
        CentralizedLogging on a 4.0+ landing zone. A pre-4.0 disable only toggled the
        organization trail off and retained the deployed resources, so the role is still
        expected there.
      * AWSControlTowerConfigAggregatorRoleForOrganizations - required only below 4.0; from 4.0
        AWS Config is optional and the aggregator is service-linked.

    See config-updates-v4 / key-changes-lz-v4.
    """
    try:
        iam = ctx.session.client("iam", region_name=ctx.region)
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("iam_roles", UNKNOWN, "Could not create IAM client", str(e)))
        return
    major = _lz_major_version(ctx)
    roles = list(_CORE_MGMT_ROLES)
    # CloudTrail integration is implicit pre-4.0 and optional from 4.0, and only a 4.0+ disable
    # actually deletes the resources. So require the role unless the manifest EXPLICITLY disables
    # CentralizedLogging on a 4.0+ (or unknown-version) landing zone. Conservative in both
    # directions: an absent or true `enabled` keeps the role required, and an explicit disable on
    # a known pre-4.0 landing zone also keeps it required, because those resources were retained.
    cl = (ctx.manifest.get("centralizedLogging")
          or ctx.manifest.get("CentralizedLogging")
          or {})
    logging_disabled = cl.get("enabled") is False
    cloudtrail_required = not (logging_disabled and (major is None or major >= 4))
    if cloudtrail_required:
        roles.append(_CLOUDTRAIL_ROLE)
    # Only require the org Config aggregator role on a known pre-4.0 landing zone. On 4.0+ (or an
    # unknown version, to avoid a false blocker) its absence is not treated as a problem.
    aggregator_required = major is not None and major < 4
    if aggregator_required:
        roles.append(_CONFIG_AGGREGATOR_ROLE)
    missing, unknown = [], []
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                missing.append([role])
            else:
                unknown.append(role)
        except BotoCoreError:
            unknown.append(role)
    if missing:
        report.add(Finding("iam_roles", BLOCKER,
                           f"{len(missing)} required Control Tower IAM role(s) missing",
                           "Control Tower cannot perform an update without these service roles.",
                           cols=["Missing role"], rows=missing,
                           remediation=f"Recreate the role(s). See {DOC}/roles-how.html"))
    # Reported independently of `missing`: a role that could not be checked is unverified whether
    # or not another role is absent, and must not be dropped when a BLOCKER is also emitted.
    if unknown:
        report.add(Finding("iam_roles", UNKNOWN,
                           f"Could not verify {len(unknown)} required IAM role(s)",
                           ", ".join(unknown)))
    if not missing and not unknown:
        note = "All required Control Tower management-account roles present"
        gated = []
        if not cloudtrail_required:
            gated.append(
                f"{_CLOUDTRAIL_ROLE} not required: this landing zone "
                f"(v{ctx.lz.get('version')}) explicitly disables CentralizedLogging, so the "
                "CloudTrail resources are not deployed")
        if not aggregator_required:
            gated.append(
                f"{_CONFIG_AGGREGATOR_ROLE} not required on landing zone "
                f"v{ctx.lz.get('version')}: AWS Config aggregator is service-linked in v4.0+")
        if gated:
            note += " (" + "; ".join(gated) + ")"
        report.add(Finding("iam_roles", PASS, note))


def check_cloudtrail_role_v4_policy(ctx: Context, report: Report) -> None:
    """v4.0 upgrade prerequisite: `AWSControlTowerCloudTrailRole` must use the AWS managed policy
    `AWSControlTowerCloudTrailRolePolicy` (not the legacy inline policy) before a landing zone is
    updated to version 4.0 via the API. Only evaluated when an upgrade to 4.0+ is actually
    available (deployed < 4.0 and latest >= 4.0).
    Doc: key-changes-lz-v4.html."""
    deployed = _lz_major_version(ctx)
    latest = _latest_major_version(ctx)
    if latest is None or latest < 4 or (deployed is not None and deployed >= 4):
        return  # not upgrading into 4.0 — prerequisite does not apply
    role = "AWSControlTowerCloudTrailRole"
    managed = "AWSControlTowerCloudTrailRolePolicy"
    try:
        iam = ctx.session.client("iam", region_name=ctx.region)
        attached = iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return  # a missing role is reported by check_required_iam_roles
        report.add(Finding("cloudtrail_role_v4", UNKNOWN,
                           f"Could not read attached policies on {role}", str(e)))
        return
    except BotoCoreError as e:
        report.add(Finding("cloudtrail_role_v4", UNKNOWN,
                           f"Could not read attached policies on {role}", str(e)))
        return
    if managed in {p.get("PolicyName") for p in attached}:
        report.add(Finding("cloudtrail_role_v4", PASS,
                           f"{role} uses the managed policy {managed} "
                           "(landing zone v4.0 upgrade prerequisite met)"))
    else:
        report.add(Finding("cloudtrail_role_v4", WARNING,
                           f"{role} does not have the {managed} managed policy attached",
                           "Updating the landing zone to v4.0 via the API requires "
                           f"{role} to use the AWS managed policy {managed} instead of the legacy "
                           "inline policy. Attach the managed policy (and remove the legacy inline "
                           "policy) before starting the update.",
                           remediation=f"Attach the AWS managed policy {managed} to {role}, then "
                                       "detach the legacy inline policy."))


# Manifest keys that name a service-integration account are declared once, in
# _SERVICE_INTEGRATION_ACCOUNTS near Context, together with the path to each account id. The
# earlier flat form of this constant listed "backup" with no path and so never reached the two
# accounts nested under backup.configurations, which made the same-parent-OU check compare only
# a subset and still report PASS.


# Baseline statuses that are EXPECTED rather than failures. In landing zone 4.0 the Control Tower
# Baseline and the AWS Config Baseline "are not applicable to the Security OU and the service
# integration accounts. The Security OU displays a baseline status of 'Not Applicable' ... This
# status is expected." A service-integration account whose integration is disabled likewise
# reports Not Enabled by design, and Control Tower no longer manages it.
#   https://docs.aws.amazon.com/controltower/latest/userguide/key-changes-lz-v4.html
_BASELINE_EXPECTED_ABSENT = ("NOT_APPLICABLE", "NOT_ENABLED")


def _arn_account(arn: str) -> Optional[str]:
    """Account-id field of an ARN, or None if it is absent or not a well-formed account id.

    Returning None on anything unparseable matters: callers compare this against the management
    account, and a partial read must not be turned into a confident mismatch.
    """
    parts = str(arn or "").split(":")
    if len(parts) > 5 and parts[4].isdigit() and len(parts[4]) == 12:
        return parts[4]
    return None


def _target_account_id(target: str) -> Optional[str]:
    """Account id for an Organizations account target, or None for an OU / root target.

    Targets arrive as ARNs and occasionally as a bare account id. Note the resource separator
    is a colon, not a slash:
        arn:aws:organizations::<mgmt>:account/<org-id>/<account-id>   -> the account id
        arn:aws:organizations::<mgmt>:ou/<org-id>/<ou-id>             -> None
    """
    t = str(target or "")
    if t.isdigit() and len(t) == 12:
        return t
    resource = t.rsplit(":", 1)[-1]
    if not resource.startswith("account/"):
        return None
    tail = resource.rsplit("/", 1)[-1]
    return tail if tail.isdigit() and len(tail) == 12 else None


def _error_code(e: Exception) -> str:
    """Best-effort AWS error code for a botocore exception ('' if not a ClientError)."""
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "") or ""
    return type(e).__name__


def _skip_note(e: Exception) -> str:
    """Short human-readable detail for a per-target failure."""
    if isinstance(e, ClientError):
        return (e.response.get("Error", {}).get("Message", "") or "")[:120]
    return str(e)[:120]


def _scope_suffix(skipped: List[List[str]]) -> str:
    """Suffix for a PASS summary when part of the check's scope could not be read."""
    return f" ({len(skipped)} target(s) skipped - see UNKNOWN)" if skipped else ""


def _note_skip(skipped: Optional[List[List[str]]], what: str, e: Exception) -> None:
    """Record a per-resource probe failure, if the caller is collecting them."""
    if skipped is not None:
        skipped.append([what, _error_code(e), _skip_note(e)])


def _report_partial_scope(report: Report, check: str, what: str,
                          skipped: List[List[str]]) -> None:
    """Emit an UNKNOWN naming targets a check could not read.

    A per-target API failure inside a check's loop silently shrinks that check's scope: the
    check then reports only on the targets it reached, which can produce a PASS that hides a
    real problem in the ones it skipped. Recording every skip and surfacing it here keeps the
    check honest and gives --strict something to act on.
    """
    if not skipped:
        return
    report.add(Finding(check, UNKNOWN,
                       f"{len(skipped)} {what} could not be read - this check's result is partial",
                       "These targets were skipped because the AWS call for them failed, so any "
                       "problem inside them would NOT appear in this check. Treat the result as "
                       "incomplete rather than as a pass, and re-run once the cause is resolved.",
                       cols=["Target", "Error", "Detail"], rows=skipped,
                       remediation="Grant the missing read permission, or re-run if the calls "
                                   "were throttled."))


def check_v4_integration_accounts_same_ou(ctx: Context, report: Report) -> None:
    """v4.0 requirement: every account configured for a service integration must sit under
    the same parent OU.

    Doc (key-changes-lz-v4.html): "AWS Control Tower will require all accounts that are
    configured for each AWS service integration to be under the same parent OU." In 4.0 the
    OU holding those accounts *becomes* the designated Security OU, so a split across OUs is
    an unsupported layout.

    Evaluated when the landing zone is already 4.0+ (live requirement) or when an upgrade into
    4.0+ is available (upgrade prerequisite). Reported as WARNING, consistent with how
    check_cloudtrail_role_v4_policy treats the other documented 4.0 prerequisite.

    Explicitly disabled integrations are skipped: a disabled integration names no account and
    therefore has no OU to place. Accounts whose parent cannot be read are reported as UNKNOWN
    rather than being dropped from the comparison.
    """
    latest = _latest_major_version(ctx)
    if latest is None or latest < 4:
        return  # 4.0 is not in play for this landing zone

    # One account can serve several integrations (Config and CentralizedLogging commonly share
    # one), so this is grouped per account: what matters is how many distinct accounts there are
    # and which OU each sits in, not how many integrations point at them. Uses the shared
    # extractor, which reaches the two Backup accounts nested under `configurations` - a flat
    # node.get("accountId") silently missed them, so a landing zone with Backup enabled was
    # reported as compliant having compared only two of its four integration accounts.
    by_account = service_integration_accounts(ctx.manifest)

    if len(by_account) < 2:
        report.add(Finding("v4_integration_ou", PASS,
                           "Same-parent-OU requirement not applicable "
                           f"({len(by_account)} service-integration account(s) configured)",
                           "Landing zone 4.0 requires all service-integration accounts to share "
                           "one parent OU. With fewer than two such accounts there is nothing to "
                           "compare."))
        return

    resolved: Dict[str, List[str]] = {}   # accountId -> [integrations, parentId, parentType]
    unresolved: List[List[str]] = []
    for acct, labels in by_account.items():
        joined = ", ".join(labels)
        try:
            parents = _collect(ctx.orgs, "list_parents", "Parents", ChildId=acct)
        except (ClientError, BotoCoreError) as e:
            unresolved.append([joined, acct, _error_code(e) or "error"])
            continue
        if not parents:
            unresolved.append([joined, acct, "no parent returned"])
            continue
        resolved[acct] = [joined, parents[0].get("Id", ""), parents[0].get("Type", "")]

    if unresolved:
        report.add(Finding("v4_integration_ou", UNKNOWN,
                           f"Could not determine the parent OU of {len(unresolved)} "
                           "service-integration account(s)",
                           "The landing zone 4.0 same-parent-OU requirement could not be fully "
                           "evaluated. Treat this as not checked, not as a pass.",
                           cols=["Integration", "Account", "Error"], rows=unresolved,
                           remediation="Grant organizations:ListParents and re-run."))

    distinct = {v[1] for v in resolved.values()}
    if len(distinct) > 1:
        rows = [[v[0], acct, v[1], v[2]] for acct, v in sorted(resolved.items())]
        report.add(Finding("v4_integration_ou", WARNING,
                           f"Service-integration accounts span {len(distinct)} different parent "
                           "OUs (landing zone 4.0 requires one)",
                           "Landing zone 4.0 requires all accounts configured for a service "
                           "integration to be under the same parent OU - that OU becomes the "
                           "designated Security OU. Accounts split across OUs is an unsupported "
                           "layout and should be reconciled before upgrading to 4.0.",
                           cols=["Integration", "Account", "Parent", "Type"], rows=rows,
                           remediation="Move the service-integration accounts under a single "
                                       "parent OU before upgrading. See "
                                       f"{DOC}/key-changes-lz-v4.html"))
    elif resolved and not unresolved:
        parent = next(iter(distinct))
        report.add(Finding("v4_integration_ou", PASS,
                           f"All {len(resolved)} service-integration account(s) share one parent "
                           f"OU ({parent})"))


def check_kms_key(ctx: Context, report: Report) -> None:
    """Validate the landing zone's customer-managed KMS key against Control Tower's own pre-check.

    configure-kms-keys.html: "AWS Control Tower performs a pre-check to validate your KMS key.
    The key must meet these requirements: Enabled / Symmetric / Not a multi-Region key / Has
    correct permissions added to the policy / Key is in the management account." The same page
    states plainly that "AWS Control Tower does not support multi-Region keys or asymmetric keys".

    Four of those five are decided by the single kms:DescribeKey response this check already
    makes, so all four are validated here. The fifth, the key policy, needs kms:GetKeyPolicy and
    is handled by check_kms_key_policy behind --check-kms-policy.
    """
    if not ctx.kms_key_arn:
        report.add(Finding("kms_key", INFO,
                           "No customer-managed KMS key referenced in the landing zone manifest",
                           "Control Tower is using AWS-owned encryption or none was configured."))
        return
    try:
        kms = ctx.session.client("kms", region_name=ctx.region)
        meta = kms.describe_key(KeyId=ctx.kms_key_arn)["KeyMetadata"]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("kms_key", BLOCKER,
                           "Landing zone KMS key could not be described",
                           f"{ctx.kms_key_arn}: {e}",
                           remediation="Ensure the key exists and the precheck role has "
                                       "kms:DescribeKey."))
        return

    problems: List[List[str]] = []
    state = meta.get("KeyState")
    if state != "Enabled":
        problems.append(["Enabled", f"KeyState is {state}"])
    # Asymmetric keys are unsupported. KeySpec is current; CustomerMasterKeySpec is the older name.
    spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec") or ""
    usage = meta.get("KeyUsage") or ""
    if spec and spec != "SYMMETRIC_DEFAULT":
        problems.append(["Symmetric", f"KeySpec is {spec}"])
    elif usage and usage != "ENCRYPT_DECRYPT":
        problems.append(["Symmetric", f"KeyUsage is {usage}"])
    if meta.get("MultiRegion") is True:
        problems.append(["Not a multi-Region key", "MultiRegion is true"])
    key_account = _arn_account(meta.get("Arn") or ctx.kms_key_arn)
    if key_account and ctx.mgmt_account and key_account != ctx.mgmt_account:
        problems.append(["Key is in the management account",
                         f"key is in account {key_account}, management account is "
                         f"{ctx.mgmt_account}"])

    if problems:
        report.add(Finding("kms_key", BLOCKER,
                           f"Landing zone KMS key fails {len(problems)} of Control Tower's "
                           "documented key requirements",
                           f"{ctx.kms_key_arn} does not satisfy Control Tower's KMS pre-check, so "
                           "a landing-zone operation using this key is expected to fail. Control "
                           "Tower does not support asymmetric or multi-Region keys at all.",
                           cols=["Requirement not met", "Observed"], rows=problems,
                           remediation="Re-enable the key or cancel its deletion; otherwise "
                                       "generate a symmetric, single-Region key in the management "
                                       f"account and select it. See {DOC}/configure-kms-keys.html"))
    else:
        report.add(Finding("kms_key", PASS,
                           "Landing zone KMS key meets Control Tower's requirements "
                           "(enabled, symmetric, single-Region, in the management account)"))


def check_sts_regional_activation(ctx: Context, report: Report) -> None:
    """STS must be activated in the management account for every governed Region, or the
    update can fail midway through configuration."""
    disabled, unknown = [], []
    creds = ctx.session.get_credentials()
    for region in ctx.governed_regions:
        try:
            frozen = creds.get_frozen_credentials()
            sts = boto3.client(
                "sts", region_name=region,
                endpoint_url=f"https://sts.{region}.amazonaws.com",
                aws_access_key_id=frozen.access_key,
                aws_secret_access_key=frozen.secret_key,
                aws_session_token=frozen.token,
            )
            sts.get_caller_identity()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            # Only a genuinely disabled Region makes STS unusable there. AccessDenied
            # (missing sts:GetCallerIdentity / an SCP) is a permissions gap, not proof
            # the Region's STS is off — don't raise a false "STS not active" blocker.
            if code in ("RegionDisabledException", "InvalidClientTokenId", "AuthFailure"):
                disabled.append([region, code])
            else:
                unknown.append(region)
        except BotoCoreError:
            unknown.append(region)
    if disabled:
        report.add(Finding("sts_regions", BLOCKER,
                           "STS is not active in one or more governed Regions",
                           "AWS STS must be activated in the management account for every "
                           "governed Region or the update can fail midway.",
                           cols=["Region", "Error"], rows=disabled,
                           remediation="Activate STS for the Region(s) in IAM > Account settings."))
    elif unknown:
        report.add(Finding("sts_regions", UNKNOWN,
                           "Could not verify STS activation for some Regions",
                           ", ".join(unknown)))
    else:
        report.add(Finding("sts_regions", PASS,
                           f"STS active across all {len(ctx.governed_regions)} governed Region(s)"))


def check_scp_headroom(ctx: Context, report: Report) -> None:
    """AWS Organizations allows a maximum of 10 SCPs attached per root/OU/account (hard limit;
    increased from 5). If a governed OU is at/near the limit, Control Tower may be unable to
    attach/update its managed SCP during the upgrade. Also inventories customer-managed SCPs."""
    try:
        ous = ctx.all_ou_arns()
        roots = _collect(ctx.orgs, "list_roots", "Roots")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("scp_headroom", UNKNOWN, "Could not enumerate OUs for SCP check", str(e)))
        return
    targets = [{"Id": r["Id"], "Name": f"(root) {r.get('Name', r['Id'])}"} for r in roots]
    targets += [{"Id": o["Id"], "Name": o["Name"]} for o in ous]
    at_limit, near_limit, custom_rows = [], [], []
    skipped: List[List[str]] = []
    checked = 0
    for t in targets:
        try:
            scps = _collect(ctx.orgs, "list_policies_for_target", "Policies",
                            TargetId=t["Id"], Filter="SERVICE_CONTROL_POLICY")
        except (ClientError, BotoCoreError) as e:
            skipped.append([t["Name"], _error_code(e), _skip_note(e)])
            continue
        checked += 1
        count = len(scps)
        if count >= 10:
            at_limit.append([t["Name"], str(count)])
        elif count >= 8:
            near_limit.append([t["Name"], str(count)])
        for p in scps:
            name = p.get("Name", "")
            # aws-guardrails-* are Control Tower's own managed preventive-control SCPs
            # (they report AwsManaged=false because CT creates them in your account).
            # Count them toward the SCP limit, but do not label them "customer-managed".
            is_ct_managed = name.startswith("aws-guardrails")
            if not p.get("AwsManaged", False) and name != "FullAWSAccess" and not is_ct_managed:
                custom_rows.append([t["Name"], name, p.get("Id", "")])
    if not checked:
        report.add(Finding("scp_headroom", UNKNOWN, "No targets queryable for SCPs"))
        return
    _report_partial_scope(report, "scp_headroom", "SCP target(s)", skipped)
    if at_limit:
        report.add(Finding("scp_headroom", WARNING,
                           f"{len(at_limit)} target(s) at the 10-SCP attachment limit",
                           "AWS Organizations allows max 10 SCPs per target (hard limit). A "
                           "target at the limit can prevent Control Tower from attaching/updating "
                           "its managed SCP during the upgrade.",
                           cols=["Target", "SCPs attached"], rows=at_limit + near_limit,
                           remediation="Consolidate or detach a custom SCP to free a slot."))
    elif near_limit:
        report.add(Finding("scp_headroom", WARNING,
                           f"{len(near_limit)} target(s) near the 10-SCP limit (8+ attached)",
                           cols=["Target", "SCPs attached"], rows=near_limit))
    else:
        report.add(Finding("scp_headroom", PASS,
                           f"All {checked} targets have SCP headroom (<8 of 10 attached)"
                           f"{_scope_suffix(skipped)}"))
    if custom_rows:
        report.add(Finding("scp_custom", INFO,
                           f"{len(custom_rows)} customer-managed SCP attachment(s) on governed targets",
                           "Review custom SCPs before upgrading; ensure they do not conflict "
                           "with the controls the new landing-zone version will apply.",
                           cols=["Target", "SCP Name", "SCP Id"], rows=custom_rows))


# The AWS services Control Tower actually acts on inside MEMBER accounts during a
# landing-zone update, and therefore the only services a Deny can interfere with.
#
# This is not a guess: it is the set of service prefixes Control Tower's own
# aws-guardrails-* SCPs deny while carrying an AWSControlTowerExecution exemption. Control
# Tower exempts itself for exactly the actions it must perform, so its guardrails are a
# statement of what it needs. Counted across live organizations: config, lambda, iam, sns,
# events, s3, cloudtrail, logs, cloudformation. "controltower" appears in none of them.
#
# Why that matters: the controltower:* APIs are org-level control-plane calls
# (UpdateLandingZone, EnableControl, ListEnabledBaselines) issued from the MANAGEMENT
# account, where SCPs never apply - "SCPs affect only member accounts in the organization.
# They have no effect on users or roles in the management account."
# (organizations/latest/userguide/orgs_manage_policies_scps.html). Control Tower never calls
# them from inside a member account, so a Deny on controltower:* cannot affect an update.
# Verified: a 3.3 -> 4.0 landing-zone upgrade completed successfully with
# `Deny controltower:* on *` attached to the organization root throughout, with zero
# access-denied events - confirmed enforced on the Security OU's accounts at the time.
_CT_MEMBER_ACCOUNT_SERVICES = frozenset((
    "cloudformation", "cloudtrail", "config", "events", "iam",
    "lambda", "logs", "s3", "sns",
))


def _denied_action_services(stmt: dict) -> Optional[Set[str]]:
    """Service prefixes a Deny statement restricts.

    Returns None when the statement cannot be reduced to a service set and must therefore
    be treated as risky regardless: a NotAction deny is inverted (it denies everything
    EXCEPT what it lists), and an Action of "*" denies everything. Both occur in practice.
    """
    if "NotAction" in stmt:
        return None
    actions = stmt.get("Action")
    if actions is None:
        return None
    if isinstance(actions, str):
        actions = [actions]
    services = set()
    for a in actions:
        a = str(a)
        if a.strip() == "*":
            return None
        if ":" in a:
            services.add(a.split(":", 1)[0].lower())
    return services


def _is_unconditional_total_deny(stmt: dict) -> bool:
    """True only for a Deny of every action on every resource, with no condition.

    This is the one SCP shape that needs no policy simulation to judge. Organizations
    states that an SCP "restricts permissions for IAM users and roles in member
    accounts", that a permission denied at any level above the account cannot be used
    "even if the account administrator attaches the AdministratorAccess IAM policy with
    */* permissions", and that only service-linked roles are exempt. AWSControlTowerExecution
    is not a service-linked role, so a total deny reaching a member account also denies the
    CloudFormation, Config, S3, SNS, CloudTrail and IAM calls Control Tower makes there.

    Anything narrower stays a heuristic and is reported as WARNING instead: a Condition may
    exempt Control Tower by a means this function cannot evaluate, and NotAction/NotResource
    invert the statement.
    """
    if stmt.get("Effect") != "Deny":
        return False
    if "NotAction" in stmt or "NotResource" in stmt:
        return False
    if stmt.get("Condition"):
        return False

    def _is_star(value: Any) -> bool:
        if isinstance(value, str):
            return value.strip() == "*"
        if isinstance(value, (list, tuple)):
            return any(isinstance(v, str) and v.strip() == "*" for v in value)
        return False

    # Resource is mandatory in an SCP statement; treat its absence as un-evaluable.
    return _is_star(stmt.get("Action")) and _is_star(stmt.get("Resource"))


def check_scp_blocking(ctx: Context, report: Report) -> None:
    """SCP *content* can block a Control Tower update, per AWS guidance:
      - The `FullAWSAccess` SCP must remain attached (its removal breaks CT access).
      - A custom Deny on a service Control Tower acts on in member accounts, without an
        AWSControlTowerExecution exemption, can block the work the update does there.
      - Restricting Regions via SCP (instead of the CT Region deny control) puts CT in an
        'undefined state'.

    Severity depends on WHICH actions are denied, not merely on whether the statement names
    the Control Tower role. A Deny that touches none of the services CT uses in member
    accounts cannot interfere - most notably a Deny on controltower:* itself, since those
    are management-account control-plane calls and SCPs never apply to the management
    account. See _CT_MEMBER_ACCOUNT_SERVICES for the service set and the evidence behind it.

    This is a heuristic (it does not fully simulate policy evaluation), so risky SCPs are
    reported as WARNING for human review, not auto-BLOCKER."""
    try:
        ous = ctx.all_ou_arns()
        roots = _collect(ctx.orgs, "list_roots", "Roots")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("scp_blocking", UNKNOWN, "Could not enumerate targets for SCP content check", str(e)))
        return
    targets = [{"Id": r["Id"], "Name": f"(root) {r.get('Name', r['Id'])}"} for r in roots]
    targets += [{"Id": o["Id"], "Name": o["Name"]} for o in ous]

    missing_fullaccess, risky, blocking = [], [], []
    doc_cache: Dict[str, Any] = {}
    skipped: List[List[str]] = []
    checked = 0

    # Which attachment points can reach the accounts the update actually works in?
    # The org root, because SCPs inherit down to every member account, and whichever OU
    # each shared account currently sits in. A total deny anywhere else still gets
    # reported, just not as a blocker: the landing zone update operates on the management
    # and shared accounts, and SCPs never apply to the management account.
    reaches_shared = {r["Id"] for r in roots}
    for _acct in sorted({a for a in ctx.shared_accounts if a and a != ctx.mgmt_account}):
        try:
            for _p in _collect(ctx.orgs, "list_parents", "Parents", ChildId=_acct):
                reaches_shared.add(_p["Id"])
        except (ClientError, BotoCoreError) as e:
            # Without the parent we cannot tell whether an OU holds a shared account, so a
            # total deny on it stays WARNING. Record it so the scope is reported honestly.
            skipped.append([f"parent OU of shared account {_acct}", _error_code(e), _skip_note(e)])
    for t in targets:
        try:
            scps = _collect(ctx.orgs, "list_policies_for_target", "Policies",
                            TargetId=t["Id"], Filter="SERVICE_CONTROL_POLICY")
        except (ClientError, BotoCoreError) as e:
            skipped.append([t["Name"], _error_code(e), _skip_note(e)])
            continue
        checked += 1
        names = {p.get("Name", "") for p in scps}
        if "FullAWSAccess" not in names:
            missing_fullaccess.append([t["Name"]])
        for p in scps:
            name = p.get("Name", "")
            pid = p.get("Id", "")
            # Skip AWS-managed FullAWSAccess and Control Tower's own guardrail SCPs.
            if name == "FullAWSAccess" or name.startswith("aws-guardrails") or p.get("AwsManaged"):
                continue
            if pid not in doc_cache:
                try:
                    pol = ctx.orgs.describe_policy(PolicyId=pid)["Policy"]
                    doc_cache[pid] = pol.get("Content", "")
                except (ClientError, BotoCoreError) as e:
                    # Unreadable SCP content cannot be declared safe. Record it once per
                    # policy so it surfaces as UNKNOWN instead of being skipped below.
                    doc_cache[pid] = None
                    skipped.append([f"SCP {name} ({pid})", _error_code(e), _skip_note(e)])
            content = doc_cache.get(pid)
            if not content:
                continue
            try:
                doc = json.loads(content)
            except (ValueError, TypeError):
                continue
            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for stmt in stmts:
                if stmt.get("Effect") != "Deny":
                    continue
                blob = json.dumps(stmt)
                exempts_ct = "AWSControlTowerExecution" in blob
                restricts_region = "aws:RequestedRegion" in blob
                services = _denied_action_services(stmt)
                if services is not None and not (services & _CT_MEMBER_ACCOUNT_SERVICES):
                    # Nothing Control Tower does in a member account is denied here, so an
                    # AWSControlTowerExecution exemption would change nothing. Report the
                    # Region restriction if present; otherwise this statement is not a
                    # finding. A Deny on controltower:* lands here: those are management
                    # account control-plane calls, and SCPs never apply there.
                    if restricts_region:
                        risky.append([t["Name"], name,
                                      "Region restriction via SCP (use CT Region deny)"])
                        break
                    continue
                if not exempts_ct:
                    total_deny = _is_unconditional_total_deny(stmt)
                    if total_deny:
                        scope = ('denies every action on every resource ("Action": "*", '
                                 '"Resource": "*") with no condition')
                    elif services is None:
                        scope = ("denies all actions, or uses NotAction, so it cannot be "
                                 "evaluated by action")
                    else:
                        hit = sorted(services & _CT_MEMBER_ACCOUNT_SERVICES)
                        scope = "denies " + ", ".join(f"{s}:*" for s in hit)
                    reason = (f"Deny does not exempt AWSControlTowerExecution and {scope}"
                              + ("; also restricts Regions" if restricts_region else ""))
                    if total_deny and t["Id"] in reaches_shared:
                        blocking.append([t["Name"], name, reason])
                    else:
                        risky.append([t["Name"], name, reason])
                    break  # one row per SCP/target is enough
                elif restricts_region:
                    risky.append([t["Name"], name, "Region restriction via SCP (use CT Region deny)"])
                    break
    if not checked:
        report.add(Finding("scp_blocking", UNKNOWN, "No targets queryable for SCP content"))
        return
    _report_partial_scope(report, "scp_blocking", "SCP target(s)/policy document(s)", skipped)
    if missing_fullaccess:
        report.add(Finding("scp_blocking", WARNING,
                           f"FullAWSAccess SCP not attached to {len(missing_fullaccess)} target(s)",
                           "AWS Control Tower expects the FullAWSAccess SCP to remain attached; "
                           "its removal can cut off access that CT needs during the update.",
                           cols=["Target"], rows=missing_fullaccess,
                           remediation="Re-attach the AWS-managed FullAWSAccess SCP to the target."))
    if blocking:
        report.add(Finding("scp_blocking", BLOCKER,
                           f"{len(blocking)} SCP attachment(s) deny every action where the "
                           "update does its work",
                           "These SCPs deny every action on every resource, with no condition "
                           "and no AWSControlTowerExecution exemption, and are attached to the "
                           "organization root or to an OU holding a shared account. Control "
                           "Tower performs the update's work in the shared accounts by assuming "
                           "AWSControlTowerExecution and calling CloudFormation, AWS Config, "
                           "S3, SNS, CloudTrail and IAM. An SCP denies those calls in a member "
                           "account even when the role holds AdministratorAccess, and only "
                           "service-linked roles are exempt - AWSControlTowerExecution is not "
                           "one. Unlike a Deny scoped to controltower:* itself, which cannot "
                           "interfere, this reaches the calls the update depends on.",
                           cols=["Target", "SCP", "Risk"], rows=blocking,
                           remediation="Detach the SCP for the duration of the upgrade, or add "
                                       "an AWSControlTowerExecution exemption (ArnNotLike on "
                                       "aws:PrincipalArn), or narrow it so it no longer denies "
                                       "every action."))
    if risky:
        report.add(Finding("scp_blocking", WARNING,
                           f"{len(risky)} custom SCP attachment(s) may block Control Tower",
                           "These custom SCPs deny a service Control Tower acts on inside member "
                           "accounts without exempting AWSControlTowerExecution, deny everything "
                           "(Action \"*\" or NotAction) so they cannot be evaluated by action, or "
                           "restrict Regions via SCP. Any of those can cause the update to fail. "
                           "The Risk column names which services are denied. A Deny that touches "
                           "none of the services CT uses in a member account is not reported, "
                           "including a Deny on controltower:* - those are management-account "
                           "calls, and SCPs never apply to the management account.",
                           cols=["Target", "SCP", "Risk"], rows=risky,
                           remediation="For a Deny on a service CT uses, add an "
                                       "AWSControlTowerExecution exemption (ArnNotLike on "
                                       "aws:PrincipalArn) or detach the SCP for the upgrade. For a "
                                       "Region restriction, use the Control Tower Region deny "
                                       "control instead."))
    if not missing_fullaccess and not risky and not blocking:
        report.add(Finding("scp_blocking", PASS,
                           f"FullAWSAccess present and no CT-blocking custom SCP patterns "
                           f"found across {checked} target(s){_scope_suffix(skipped)}"))


def check_stale_control_targets(ctx: Context, report: Report) -> None:
    """Enabled controls whose target OU no longer exists in AWS Organizations.

    The sibling of check_stale_baseline_targets, and a distinct blind spot. The control
    drift check walks the OUs that exist and asks what is enabled on each, so a control
    left pointing at a deleted OU is never asked about and cannot be seen that way. Listing
    enabled controls without a target identifier returns every one of them with the target
    it holds, which is what makes the stale reference visible.

    Observed: an administrator deleted an OU in Organizations without first deregistering
    it from Control Tower; the landing zone update then failed while enabling mandatory
    controls, with ParentNotFoundException naming the deleted OU, and the landing zone was
    left FAILED. AWS has stated that it has since fixed the service-side handling of this
    case, which is why it is reported as a WARNING rather than a blocker - the stale
    reference is worth clearing before an update that does not roll back, but it is no
    longer a demonstrated hard failure.
    """
    try:
        existing = {ou["Arn"] for ou in ctx.all_ou_arns()}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stale_control_targets", UNKNOWN,
                           "Could not enumerate OUs to validate control targets", str(e)))
        return
    try:
        # No targetIdentifier: returns every enabled control with the target it holds,
        # including targets that no longer exist.
        controls = _collect(ctx.ct, "list_enabled_controls", "enabledControls")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stale_control_targets", UNKNOWN,
                           "Could not list enabled controls without a target filter", str(e),
                           remediation="Grant controltower:ListEnabledControls and re-run."))
        return

    stale = []
    for c in controls:
        target = str(c.get("targetIdentifier") or "")
        # Only OU targets can go stale this way; an account target is covered elsewhere.
        if ":ou/" not in target or target in existing:
            continue
        stale.append([target.rsplit("/", 1)[-1],
                      str(c.get("controlIdentifier") or "").rsplit("/", 1)[-1],
                      (c.get("statusSummary") or {}).get("status") or "unknown"])

    if stale:
        report.add(Finding("stale_control_targets", WARNING,
                           f"{len(stale)} enabled control(s) target an OU that no longer exists",
                           "Deleting an OU in Organizations without first deregistering it from "
                           "Control Tower leaves Control Tower holding a reference to an OU that "
                           "is gone. An update that enables mandatory controls has been seen to "
                           "fail on exactly this, with ParentNotFoundException naming the deleted "
                           "OU and the landing zone left FAILED. The control drift check cannot "
                           "see these, because it asks what is enabled on each OU that exists.",
                           cols=["Missing OU", "Control", "Status"], rows=stale,
                           remediation=f"{DOC}/remove-ou.html - deregister an OU in Control Tower "
                                       "before deleting it in Organizations. Clearing an existing "
                                       "stale reference is done on the Control Tower side, so "
                                       "engage AWS Support if an update fails on one."))
    else:
        report.add(Finding("stale_control_targets", PASS,
                           "Every enabled control targets an OU that still exists"))


def check_foundational_ou_structure(ctx: Context, report: Report) -> None:
    """Three of the four drift types drift.html says to resolve right away, all of which are
    management/shared-account scope and readable from data already fetched.

    drift.html, "Types of drift to resolve right away":
      - "Don't delete the Security OU ... you'll see an error message instructing you to
        reset the landing zone immediately. You won't be able to take any other actions in
        AWS Control Tower until the reset is complete."
      - "Don't delete all Additional OUs: At least one Additional OU is required for AWS
        Control Tower to operate, but it doesn't have to be the Sandbox OU."
      - "Don't remove shared accounts: If you remove shared accounts from Foundational OUs
        ... To remediate this type of drift, you must update the landing zone."

    Separately, Control Tower's own update validator rejects extra accounts in the Security
    OU outright: "AWS Control Tower could not complete your setup because the Security OU
    contains accounts other than the shared accounts. Remove these accounts from the
    Security OU, then try again." That is a hard block, so it is graded BLOCKER; the two
    drift conditions above are WARNING, since the documented remediation for a moved shared
    account is itself a landing-zone update.

    The Foundational OU is identified by WHERE the shared accounts live, never by name.
    Renaming the Security OU is explicitly permitted ("Change the name of the Security OU"),
    and on 4.0 the OU holding the service-integration accounts becomes the Security OU.
    """
    shared = {a for a in ctx.shared_accounts if a and a != ctx.mgmt_account}
    if not shared:
        report.add(Finding("foundational_ou", UNKNOWN,
                           "No shared accounts discovered, so OU structure cannot be checked",
                           "The Audit and Log Archive account ids come from the landing-zone "
                           "manifest. Without them the Foundational OU cannot be identified.",
                           remediation="Pass --audit-account / --log-archive-account, or check "
                                       "that the manifest declares the service integrations."))
        return
    try:
        all_accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
        ous = ctx.all_ou_arns()
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("foundational_ou", UNKNOWN,
                           "Could not read the organization's OUs and accounts", str(e)))
        return

    # Where does each shared account sit?
    parents: Dict[str, str] = {}
    unresolved: List[List[str]] = []
    for acct in sorted(shared):
        try:
            p = _collect(ctx.orgs, "list_parents", "Parents", ChildId=acct)
        except (ClientError, BotoCoreError) as e:
            unresolved.append([acct, _error_code(e) or "error", _skip_note(e)])
            continue
        if not p:
            unresolved.append([acct, "no parent returned", ""])
            continue
        parents[acct] = p[0].get("Id", "")
    if unresolved:
        report.add(Finding("foundational_ou", UNKNOWN,
                           f"Could not locate {len(unresolved)} shared account(s) in the OU tree",
                           "The Foundational OU checks could not be fully evaluated. Treat this "
                           "as not checked rather than as a pass.",
                           cols=["Account", "Error", "Detail"], rows=unresolved,
                           remediation="Grant organizations:ListParents and re-run."))
    if not parents:
        return

    ou_names = {o["Id"]: o["Name"] for o in ous}
    distinct = sorted(set(parents.values()))

    # 1. Shared accounts must sit together in a Foundational OU, not split and not at root.
    at_root = [a for a, p in parents.items() if p not in ou_names]
    if len(distinct) > 1 or at_root:
        rows = [[a, p, ou_names.get(p, "(root - not an OU)")] for a, p in sorted(parents.items())]
        report.add(Finding("foundational_ou_placement", WARNING,
                           "Shared accounts are not together in one Foundational OU",
                           "drift.html: \"Don't remove shared accounts: If you remove shared "
                           "accounts from Foundational OUs with the AWS Organizations console or "
                           "APIs, such as removing the logging account from the Security OU. "
                           "Moving these accounts creates a type of Move Account drift that must "
                           "be remediated. To remediate this type of drift, you must update the "
                           "landing zone.\" A landing-zone update is the documented remediation, "
                           "so this does not block the update - but the resulting layout is "
                           "unsupported and worth confirming was intentional before you start.",
                           cols=["Shared account", "Parent id", "Parent name"], rows=rows,
                           remediation="Move the shared accounts back under a single Foundational "
                                       f"OU. See {DOC}/drift.html"))
        return  # the checks below assume one identifiable Foundational OU

    foundational = distinct[0]
    f_name = ou_names.get(foundational, foundational)

    # 2. That OU should contain ONLY the shared accounts. Control Tower's update validator
    #    rejects anything else outright.
    #
    #    But this can only be judged when the manifest names EVERY shared account. A disabled
    #    service integration names no account while its account usually still exists and still
    #    sits in the Foundational OU - a landing zone with centralizedLogging disabled keeps
    #    its Log Archive account there. Judging against an incomplete set would report that
    #    account as foreign, which is a false blocker on a healthy landing zone. So when any
    #    integration is explicitly disabled, this particular test is skipped and said to be
    #    skipped, rather than guessed at.
    # An absent `enabled` flag is NOT "disabled" - pre-4.0 manifests omit it entirely - so only
    # an explicit False counts. Keys are deduplicated because Backup contributes two entries.
    disabled = []
    for key, label, _ in _SERVICE_INTEGRATION_ACCOUNTS:
        if _integration_enabled(ctx, key) is False and key not in [d[0] for d in disabled]:
            disabled.append((key, label.split(" (")[0]))
    disabled_labels = [d[1] for d in disabled]
    extra: List[List[str]] = []
    in_ou = None
    if disabled:
        report.add(Finding("foundational_ou_extra_accounts", INFO,
                           "Not checked whether the Foundational OU holds only shared accounts",
                           "Control Tower rejects a landing-zone update when the Security OU "
                           "contains accounts other than the shared accounts. Deciding that needs "
                           "the full list of shared accounts, and this manifest has "
                           f"{len(disabled)} service integration(s) disabled ("
                           + ", ".join(disabled_labels) + "), which name no account. A disabled "
                           "integration's account commonly still exists and still sits in the "
                           "Foundational OU - disabling an integration does not move or remove it "
                           "- so comparing against an incomplete list would report a legitimate "
                           "shared account as foreign.",
                           remediation="Pass --audit-account / --log-archive-account to name the "
                                       "shared accounts explicitly, then re-run to have this "
                                       "checked."))
    else:
        try:
            in_ou = _collect(ctx.orgs, "list_accounts_for_parent", "Accounts",
                             ParentId=foundational)
        except (ClientError, BotoCoreError) as e:
            report.add(Finding("foundational_ou", UNKNOWN,
                               f"Could not list the accounts in the Foundational OU ({f_name})",
                               str(e),
                               remediation="Grant organizations:ListAccountsForParent and re-run."))
        if in_ou is not None:
            extra = [[a.get("Id", ""), a.get("Name", ""), a.get("Status", "")]
                     for a in in_ou if a.get("Id") not in shared]
            if extra:
                report.add(Finding("foundational_ou_extra_accounts", BLOCKER,
                                   f"{len(extra)} account(s) in the Foundational OU ({f_name}) are "
                                   "not shared accounts",
                                   "Control Tower validates this during a landing-zone update and "
                                   "rejects it: \"AWS Control Tower could not complete your setup "
                                   "because the Security OU contains accounts other than the "
                                   "shared accounts. Remove these accounts from the Security OU, "
                                   "then try again.\" Every service integration in this manifest "
                                   "is enabled, so the shared-account list is complete and these "
                                   "accounts are genuinely foreign to the Foundational OU.",
                                   cols=["Account", "Name", "Status"], rows=extra,
                                   remediation="Move these accounts to a registered OU outside the "
                                               "Foundational OU before upgrading."))

    # 3. At least one OU must exist besides the Foundational one.
    additional = [o for o in ous if o["Id"] != foundational]
    if not additional:
        report.add(Finding("foundational_ou_additional", WARNING,
                           "No Additional OU exists besides the Foundational OU",
                           "drift.html: \"Don't delete all Additional OUs: At least one "
                           "Additional OU is required for AWS Control Tower to operate, but it "
                           "doesn't have to be the Sandbox OU.\" With only the Foundational OU "
                           "present, Control Tower has nowhere to place enrolled accounts.",
                           remediation="Create and register at least one Additional OU."))

    if not extra and additional:
        scope = "" if in_ou is not None else " (shared-account contents not compared - see above)"
        report.add(Finding("foundational_ou", PASS,
                           f"Shared accounts are together in one Foundational OU ({f_name}) and "
                           f"{len(additional)} other OU(s) exist{scope}"))


def check_foundational_ou_not_nested(ctx: Context, report: Report) -> None:
    """The OU holding the service-integration accounts must not itself be nested.

    On landing zone 4.0+ Control Tower resolves the foundational OU from where the
    service-integration accounts sit, then rejects the operation outright if that OU is nested
    under another OU rather than sitting directly under the organization root. It also rejects
    those accounts being left at the root - that case is check 26.

    Because the rejection happens during input validation rather than mid-deployment, it is a
    BLOCKER: the update does not start, and no partial state is left behind. Evaluated only
    when 4.0 is deployed or available, since the requirement arrived with 4.0.
    """
    deployed = _lz_major_version(ctx) or 0
    latest = _latest_major_version(ctx) or 0
    if deployed < 4 and latest < 4:
        report.add(Finding("foundational_ou_nested", INFO,
                           "Nested-OU check skipped: landing zone 4.0 is neither deployed nor "
                           "available, and the requirement arrived with 4.0"))
        return
    # The requirement is evaluated against the version already DEPLOYED, not the version being
    # moved to. A 3.x landing zone therefore is not rejected at all, not even by the update that
    # takes it to 4.0 - so a nested OU is only a hard blocker once 4.0 is deployed. Below that it
    # is an advisory warning about the operation after this one.
    level = BLOCKER if deployed >= 4 else WARNING

    shared = {a for a in ctx.shared_accounts if a and a != ctx.mgmt_account}
    if not shared:
        report.add(Finding("foundational_ou_nested", UNKNOWN,
                           "No shared accounts discovered, so the foundational OU cannot be\n"
                           "identified",
                           remediation="Pass --audit-account / --log-archive-account."))
        return

    found_ous, skipped = set(), []
    for acct in sorted(shared):
        try:
            parents = _collect(ctx.orgs, "list_parents", "Parents", ChildId=acct)
        except (ClientError, BotoCoreError) as e:
            skipped.append([f"account {acct}", _error_code(e), _skip_note(e)])
            continue
        for par in parents:
            if par.get("Type") == "ORGANIZATIONAL_UNIT":
                found_ous.add(par.get("Id", ""))

    nested, ou_names = [], {}
    try:
        ou_names = {o["Id"]: o.get("Name", o["Id"]) for o in ctx.all_ou_arns()}
    except (ClientError, BotoCoreError):
        pass
    for ou in sorted(o for o in found_ous if o):
        try:
            gp = _collect(ctx.orgs, "list_parents", "Parents", ChildId=ou)
        except (ClientError, BotoCoreError) as e:
            skipped.append([f"OU {ou}", _error_code(e), _skip_note(e)])
            continue
        for g in gp:
            if g.get("Type") == "ORGANIZATIONAL_UNIT":
                nested.append([ou_names.get(ou, ou), ou,
                               ou_names.get(g.get("Id", ""), g.get("Id", ""))])

    _report_partial_scope(report, "foundational_ou_nested", "OU parent lookup(s)", skipped)
    if nested:
        detail = ("On landing zone 4.0+ Control Tower resolves the foundational OU from where the "
                  "service-integration accounts sit, and rejects the operation when that OU is "
                  "not directly under the organization root. The rejection happens during input "
                  "validation, so the operation will not start.")
        if level == WARNING:
            detail += (" Reported as a warning rather than a blocker because the validation is "
                       f"gated on the deployed version, which is {ctx.lz.get('version')}: this "
                       "update is not affected, but operations after 4.0 is deployed will be.")
        report.add(Finding("foundational_ou_nested", level,
                           f"{len(nested)} foundational OU is nested under another OU",
                           detail,
                           cols=["Foundational OU", "OU id", "Nested under"], rows=nested,
                           remediation="Move the OU holding the service-integration accounts so "
                                       "that it sits directly under the organization root, or "
                                       "move those accounts into an OU that already does."))
    elif not found_ous:
        report.add(Finding("foundational_ou_nested", UNKNOWN,
                           "Could not resolve the foundational OU from the shared accounts"))
    elif not skipped:
        report.add(Finding("foundational_ou_nested", PASS,
                           "The foundational OU sits directly under the organization root"))


# Control Tower creates a small number of CloudFormation stacks DIRECTLY in the management
# account, rather than through a StackSet. Verified across six landing zones: no AWSControlTower*
# StackSet targets the management account at all, so check 8 (StackSet health) cannot see these.
_MGMT_CLOUDTRAIL_STACK = "AWSControlTowerBP-BASELINE-CLOUDTRAIL-MASTER"
_MGMT_CONFIG_STACK = "AWSControlTowerBP-BASELINE-CONFIG-MASTER"
_MGMT_STACK_PREFIX = "AWSControlTower"
# A stack in one of these states is not serving its purpose, whatever the resources inside it say.
_UNHEALTHY_STACK_STATES = (
    "CREATE_FAILED", "ROLLBACK_IN_PROGRESS", "ROLLBACK_FAILED", "ROLLBACK_COMPLETE",
    "DELETE_FAILED", "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS",
    "UPDATE_ROLLBACK_FAILED", "UPDATE_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_IN_PROGRESS", "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
)


def check_management_account_stacks(ctx: Context, report: Report) -> None:
    """Control Tower's own CloudFormation stacks in the management account.

    Check 8 reads StackSet INSTANCES. Across six landing zones not one AWSControlTower* StackSet
    targets the management account, so the stacks Control Tower creates there directly are outside
    its reach. A customer who deletes one out of band gets no signal from the StackSet check.

    Reported as WARNING, never as a blocker: a landing zone update or reset recreates these, so a
    missing stack is something to tell the customer about rather than a reason to stop.

    Which stacks to expect is derived from observation, not from documentation, so the rules are
    deliberately narrow and are stated here so a wrong call is visible:

      - The CloudTrail stack is expected when the CentralizedLogging integration is enabled. Seen
        present on four landing zones with it enabled, and absent on one with it disabled.
      - The Config stack is expected below landing zone 4.0. Seen present on all three 3.x landing
        zones and absent on both 4.0 ones, where Config is delivered differently.

    Anything else matching the AWSControlTower prefix is reported on health only, never on absence,
    because there is no basis for predicting whether it should be there.
    """
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        stacks = {st["StackName"]: st.get("StackStatus", "")
                  for st in _collect(cfn, "list_stacks", "StackSummaries")
                  if st.get("StackName", "").startswith(_MGMT_STACK_PREFIX)
                  and st.get("StackStatus") != "DELETE_COMPLETE"}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("mgmt_stacks", UNKNOWN,
                           "Could not list CloudFormation stacks in the management account", str(e),
                           remediation="Grant cloudformation:ListStacks and re-run."))
        return

    expected = {}
    if _integration_enabled(ctx, "centralizedLogging") is True:
        expected[_MGMT_CLOUDTRAIL_STACK] = "CentralizedLogging integration is enabled"
    if (_lz_major_version(ctx) or 0) < 4:
        expected[_MGMT_CONFIG_STACK] = "landing zone is below 4.0"

    missing = [[n, why] for n, why in sorted(expected.items()) if n not in stacks]
    unhealthy = [[n, st] for n, st in sorted(stacks.items()) if st in _UNHEALTHY_STACK_STATES]
    in_progress = [[n, st] for n, st in sorted(stacks.items()) if st.endswith("_IN_PROGRESS")
                   and st not in _UNHEALTHY_STACK_STATES]

    if missing:
        report.add(Finding("mgmt_stacks", WARNING,
                           f"{len(missing)} Control Tower stack(s) missing from the management account",
                           "Control Tower created these stacks in the management account, and they "
                           "are most often absent because they were removed out of band. A landing "
                           "zone update or reset recreates them, so this does not block the "
                           "upgrade. It does mean the environment is not in the state Control "
                           "Tower last left it, and that the upgrade will change that.",
                           cols=["Missing stack", "Expected because"], rows=missing,
                           remediation="No action needed before upgrading; the update or reset "
                                       "recreates these. If you would rather restore them first, "
                                       "repair or reset the landing zone."))
    if unhealthy:
        report.add(Finding("mgmt_stacks_unhealthy", WARNING,
                           f"{len(unhealthy)} Control Tower stack(s) in the management account are "
                           "in a failed or rolled-back state",
                           "A rolled-back or failed stack is not serving its purpose regardless of "
                           "what the resources inside it report. An update reasserts Control "
                           "Tower's intent over these, so this is worth resolving but does not "
                           "block the upgrade.",
                           cols=["Stack", "Status"], rows=unhealthy,
                           remediation="Review the stack events for the failure, then repair or "
                                       "reset the landing zone to have Control Tower reassert it."))
    if in_progress:
        report.add(Finding("mgmt_stacks_in_progress", WARNING,
                           f"{len(in_progress)} Control Tower stack(s) in the management account "
                           "have an operation in progress",
                           "A stack operation is still running. Starting a landing zone update "
                           "while Control Tower's own stacks are mid-operation risks the two "
                           "colliding.",
                           cols=["Stack", "Status"], rows=in_progress,
                           remediation="Wait for the stack operation to finish."))
    if not missing and not unhealthy and not in_progress:
        if stacks:
            report.add(Finding("mgmt_stacks", PASS,
                               f"{len(stacks)} Control Tower stack(s) in the management account are "
                               "healthy, and every expected stack is present"))
        else:
            report.add(Finding("mgmt_stacks", INFO,
                               "No Control Tower stacks found in the management account, and none "
                               "are expected for this landing zone version and configuration"))


def check_governed_region_availability(ctx: Context, report: Report) -> None:
    """Every governed Region must be usable by this account.

    A governed Region that is not enabled in the management account has been observed
    blocking a landing-zone update. Reported as WARNING rather than BLOCKER because opt-in
    status is only one of the reasons a Region can be unusable: a service-side regional
    event can block an update while every Region still reports as enabled here, and that is
    not detectable from the account. So a finding here is a real problem, but a clean result
    is not proof the Regions are healthy.
    """
    if not ctx.governed_regions:
        report.add(Finding("governed_regions", UNKNOWN,
                           "No governed Regions found in the landing-zone manifest",
                           "Region availability could not be evaluated."))
        return
    try:
        acct = ctx.session.client("account", region_name=ctx.region)
        regions = {r["RegionName"]: r.get("RegionOptStatus", "")
                   for r in _collect(acct, "list_regions", "Regions")}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("governed_regions", UNKNOWN,
                           "Could not read Region opt-in status", str(e),
                           remediation="Grant account:ListRegions and re-run."))
        return
    usable = ("ENABLED", "ENABLED_BY_DEFAULT")
    bad = [[r, regions.get(r) or "not returned by ListRegions"]
           for r in ctx.governed_regions if regions.get(r) not in usable]
    if bad:
        report.add(Finding("governed_regions", WARNING,
                           f"{len(bad)} governed Region(s) are not enabled for this account",
                           "The landing zone governs these Regions, but they are not enabled in "
                           "the management account. A Region that Control Tower cannot operate "
                           "in has been observed failing a landing-zone update. Note the inverse "
                           "does not hold: a Region can be enabled here and still be unusable "
                           "because of a service-side regional event, which this check cannot "
                           "see.",
                           cols=["Governed Region", "Opt-in status"], rows=bad,
                           remediation="Enable the Region for the organization, or remove it from "
                                       "the landing zone's governed Regions before upgrading."))
    else:
        report.add(Finding("governed_regions", PASS,
                           f"All {len(ctx.governed_regions)} governed Region(s) are enabled for "
                           "this account"))


def check_stackset_operations_in_progress(ctx: Context, report: Report) -> None:
    """A landing-zone update cannot run concurrently with an in-progress StackSet operation
    on the CT-managed StackSets — it conflicts and fails. Flag RUNNING/STOPPING operations."""
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        names = [s["StackSetName"] for s in
                 _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")
                 if s["StackSetName"].startswith("AWSControlTower")]
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("stackset_ops", UNKNOWN,
                           "Could not list StackSets for in-progress operations", str(e)))
        return
    active = []
    skipped: List[List[str]] = []
    for name in names:
        try:
            ops = _collect(cfn, "list_stack_set_operations", "Summaries", StackSetName=name)
        except (ClientError, BotoCoreError) as e:
            # BLOCKER-or-PASS check: an unread StackSet must not read as "no operations".
            skipped.append([name, _error_code(e), _skip_note(e)])
            continue
        for o in ops:
            if o.get("Status") in ("RUNNING", "STOPPING", "QUEUED"):
                active.append([name, o.get("Action", ""), o.get("Status", ""),
                               o.get("OperationId", "")])
    _report_partial_scope(report, "stackset_ops", "AWSControlTower StackSet(s)", skipped)
    if active:
        report.add(Finding("stackset_ops", BLOCKER,
                           f"{len(active)} in-progress operation(s) on AWSControlTower* StackSets",
                           "A landing-zone update cannot run while a StackSet operation on the "
                           "CT-managed StackSets is RUNNING/STOPPING/QUEUED — it will conflict and fail.",
                           cols=["StackSet", "Action", "Status", "OperationId"], rows=active,
                           remediation="Wait for the in-progress StackSet operation(s) to finish "
                                       "before upgrading."))
    else:
        report.add(Finding("stackset_ops", PASS,
                           f"No in-progress operations on {len(names)} AWSControlTower "
                           f"StackSet(s){_scope_suffix(skipped)}"))


# Foundational AWSControlTower StackSets present in EVERY Control Tower landing zone,
# across versions. Deliberately conservative — version/config-specific StackSets
# (BASELINE-CONFIG/CLOUDTRAIL in older versions, VPC-ACCOUNT-FACTORY, guardrails,
# SERVICE-LINKED-ROLE, CLOUDWATCH) are intentionally NOT asserted here to avoid false
# positives on a healthy landing zone.
_EXPECTED_STACKSETS = [
    "AWSControlTowerBP-BASELINE-ROLES",
    "AWSControlTowerBP-BASELINE-SERVICE-ROLES",
]
# Deliberately NOT asserted here: "AWSControlTowerExecutionRole". StackSet presence is the wrong
# proxy for what actually matters, which is whether the AWSControlTowerExecution role exists and
# is assumable in each enrolled account. The StackSet can be deleted with stacks retained (roles
# survive, nothing is wrong) or absent because the roles were created another way, so its absence
# produces a false warning. check_member_execution_roles tests the role directly instead.


def check_expected_stacksets(ctx: Context, report: Report) -> None:
    """Detect a broken / partially-deleted landing zone by confirming the foundational
    AWSControlTower StackSets still exist. The other checks validate the HEALTH of
    StackSets that exist; this catches ones that are entirely MISSING."""
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        present = {s["StackSetName"] for s in
                   _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")}
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("expected_stacksets", UNKNOWN,
                           "Could not list StackSets to verify foundational ones", str(e)))
        return
    missing = [e for e in _EXPECTED_STACKSETS if e not in present]
    if missing:
        major = _lz_major_version(ctx)
        # On landing zone 4.0+ the SecurityRoles integration is optional; if it is disabled, these
        # role StackSets are legitimately absent. Downgrade to INFO there (confirm the integration
        # is intended to be off) rather than warning about a "broken" landing zone.
        v4 = major is not None and major >= 4
        detail = ("These core StackSets are expected in a Control Tower landing zone; their absence "
                  "can indicate the landing zone is broken or was partially deleted. All "
                  "landing-zone operations (Update/upgrade, Reset, Repair, and the console Retry on "
                  "a failed dashboard) run the same UpdateLandingZone backend workflow, which "
                  "re-creates these baseline StackSets.")
        if v4:
            detail += (" NOTE: on landing zone 4.0+ the SecurityRoles integration is optional — if it "
                       "is disabled these role StackSets are expected to be absent (not a problem). "
                       "Confirm whether SecurityRoles is intentionally disabled.")
        report.add(Finding("expected_stacksets", INFO if v4 else WARNING,
                           f"{len(missing)} foundational AWSControlTower StackSet(s) appear missing",
                           detail,
                           cols=["Missing StackSet"], rows=[[m] for m in missing],
                           remediation="Retry/resolve the failed landing-zone operation to re-create "
                                       "the missing StackSets (all landing-zone operations run the "
                                       "same UpdateLandingZone workflow). On 4.0+ first confirm the "
                                       "SecurityRoles integration is meant to be enabled. AWS Control "
                                       "Tower does not roll back a failed update and can leave the "
                                       "landing zone in an indeterminate state — if retrying does not "
                                       "resolve it, contact AWS Support."))
    else:
        report.add(Finding("expected_stacksets", PASS,
                           f"Foundational AWSControlTower StackSets are present "
                           f"({len(present)} AWSControlTower* StackSet(s) total)"))


# Well-known Control Tower-created resources that a Repair/Reset/Update will try to
# RE-create. If a baseline StackSet was deleted (esp. with "retain stacks") these can
# linger and then collide ("already exists") when CT recreates them. Names are stable
# across recent CT versions (see the CT "shared account resources" / "existing resources"
# docs); the list is intentionally curated (not exhaustive) to stay low-false-positive.
# StackSets that manage each class of baseline resource (from the CT "Resources created in
# the shared accounts" doc). A resource is only a recreate-collision risk if it EXISTS but
# ALL of its managing StackSets are MISSING — if a managing StackSet is present, CT updates
# the resource in place (no "already exists"). This keeps the scan false-positive-safe.
_SS_EXEC = ["AWSControlTowerExecutionRole"]
_SS_ROLES = ["AWSControlTowerBP-BASELINE-ROLES", "AWSControlTowerBP-BASELINE-SERVICE-ROLES"]
_SS_SECURITY = ["AWSControlTowerSecurityResources", "AWSControlTowerBP-SECURITY-TOPICS"]
_SS_CONFIG = ["AWSControlTowerBP-BASELINE-CONFIG"]
_SS_CLOUDWATCH = ["AWSControlTowerBP-BASELINE-CLOUDWATCH"]
_SS_CLOUDTRAIL = ["AWSControlTowerBP-BASELINE-CLOUDTRAIL", "AWSControlTowerLoggingResources"]
_SS_S3 = ["AWSControlTowerLoggingResources", "AWSControlTowerBP-CONFIG-CENTRAL-S3-BUCKET"]

# CT-created IAM roles -> the StackSet(s) that manage them.
_ORPHAN_ROLE_GUARDS = {
    "AWSControlTowerExecution": _SS_EXEC,
    "aws-controltower-AdministratorExecutionRole": _SS_ROLES,
    "aws-controltower-ReadOnlyExecutionRole": _SS_ROLES,
    "aws-controltower-ConfigRecorderRole": _SS_ROLES,
    "aws-controltower-ForwardSnsNotificationRole": _SS_ROLES,
    "aws-controltower-CloudWatchLogsRole": _SS_ROLES,
    "aws-controltower-AuditAdministratorRole": _SS_SECURITY + _SS_ROLES,   # audit account
    "aws-controltower-AuditReadOnlyRole": _SS_SECURITY + _SS_ROLES,        # audit account
}
_ORPHAN_SNS_TOPICS = ["aws-controltower-SecurityNotifications",
                      "aws-controltower-AggregateSecurityNotifications",
                      "aws-controltower-AllConfigNotifications"]
_ORPHAN_S3_PREFIXES = ("aws-controltower-logs-", "aws-controltower-s3-access-logs-",
                       "aws-controltower-config-logs-", "aws-controltower-config-access-logs-")


def _probe_orphaned_resources(ctx: Context, acct: str, present: set,
                              skipped: Optional[List[List[str]]] = None) -> List[List[str]]:
    """Read-only probe of one shared account for baseline-created resources that still exist
    even though the StackSet that manages them is gone (a recreate-collision risk on
    Repair/Reset). Returns rows [resource type, name]. Raises only if the account can't be
    assumed at all (caller marks it UNKNOWN).

    Individual service probes can fail independently (denied, throttled, service not enabled).
    Each failure is appended to `skipped` so the caller can report that this scan's coverage is
    incomplete - a probe that could not run is not evidence that nothing is orphaned.
    Regional resources are checked in the home region."""
    def _orphaned(guards: List[str]) -> bool:
        return not any(g in present for g in guards)

    iam = ctx.assume(acct, ctx.region, "iam")  # may raise -> caller handles (UNKNOWN)
    rows: List[List[str]] = []

    for role, guards in _ORPHAN_ROLE_GUARDS.items():
        if not _orphaned(guards):
            continue
        try:
            iam.get_role(RoleName=role)
            rows.append(["IAM role", role])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                _note_skip(skipped, f"IAM role {role}", e)
        except BotoCoreError as e:
            _note_skip(skipped, f"IAM role {role}", e)

    if _orphaned(_SS_CONFIG):
        try:
            cfg = ctx.assume(acct, ctx.region, "config")
            for rec in cfg.describe_configuration_recorders().get("ConfigurationRecorders", []):
                if "aws-controltower" in (rec.get("name") or ""):
                    rows.append(["Config recorder", rec.get("name", "")])
            for dc in cfg.describe_delivery_channels().get("DeliveryChannels", []):
                if "aws-controltower" in (dc.get("name") or ""):
                    rows.append(["Config delivery channel", dc.get("name", "")])
        except (ClientError, BotoCoreError) as e:
            _note_skip(skipped, "AWS Config recorders / delivery channels", e)

    if _orphaned(_SS_SECURITY):
        try:
            sns = ctx.assume(acct, ctx.region, "sns")
            for t in _collect(sns, "list_topics", "Topics"):
                name = t.get("TopicArn", "").split(":")[-1]
                if name in _ORPHAN_SNS_TOPICS:
                    rows.append(["SNS topic", name])
        except (ClientError, BotoCoreError) as e:
            _note_skip(skipped, "SNS topics", e)

    try:
        logs = ctx.assume(acct, ctx.region, "logs")
        if _orphaned(_SS_CLOUDTRAIL):
            for lg in _collect(logs, "describe_log_groups", "logGroups",
                               logGroupNamePrefix="aws-controltower/CloudTrailLogs"):
                rows.append(["CloudWatch log group", lg.get("logGroupName", "")])
        if _orphaned(_SS_CLOUDWATCH):
            for lg in _collect(logs, "describe_log_groups", "logGroups",
                               logGroupNamePrefix="/aws/lambda/aws-controltower-NotificationForwarder"):
                rows.append(["CloudWatch log group", lg.get("logGroupName", "")])
    except (ClientError, BotoCoreError) as e:
        _note_skip(skipped, "CloudWatch log groups", e)

    if _orphaned(_SS_CLOUDWATCH):
        try:
            lam = ctx.assume(acct, ctx.region, "lambda")
            try:
                lam.get_function(FunctionName="aws-controltower-NotificationForwarder")
                rows.append(["Lambda function", "aws-controltower-NotificationForwarder"])
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") not in ("ResourceNotFoundException", "404"):
                    _note_skip(skipped, "Lambda aws-controltower-NotificationForwarder", e)
            except BotoCoreError as e:
                _note_skip(skipped, "Lambda aws-controltower-NotificationForwarder", e)
        except (ClientError, BotoCoreError) as e:
            _note_skip(skipped, "Lambda (assume role)", e)
        try:
            ev = ctx.assume(acct, ctx.region, "events")
            for r in _collect(ev, "list_rules", "Rules",
                              NamePrefix="aws-controltower-ConfigComplianceChangeEventRule"):
                rows.append(["EventBridge rule", r.get("Name", "")])
        except (ClientError, BotoCoreError) as e:
            _note_skip(skipped, "EventBridge rules", e)

    if _orphaned(_SS_CLOUDTRAIL):
        try:
            ct_cli = ctx.assume(acct, ctx.region, "cloudtrail")
            for tr in ct_cli.describe_trails(
                    trailNameList=["aws-controltower-BaselineCloudTrail"]).get("trailList", []):
                rows.append(["CloudTrail trail", tr.get("Name", "aws-controltower-BaselineCloudTrail")])
        except (ClientError, BotoCoreError) as e:
            _note_skip(skipped, "CloudTrail trails", e)

    if _orphaned(_SS_S3):
        try:
            s3 = ctx.assume(acct, ctx.region, "s3")
            for b in s3.list_buckets().get("Buckets", []):
                nm = b.get("Name", "")
                if nm.startswith(_ORPHAN_S3_PREFIXES):
                    rows.append(["S3 bucket", nm])
        except (ClientError, BotoCoreError) as e:
            _note_skip(skipped, "S3 buckets", e)

    return rows


def check_orphaned_ct_resources(ctx: Context, report: Report) -> None:
    """OPT-IN (--check-orphaned-resources): when the landing zone looks broken (FAILED, or a
    foundational StackSet is missing), CT-created resources left behind by a deleted baseline
    StackSet will collide ('already exists') when Repair/Reset/Update recreates them. Scans the
    shared accounts for the well-known CT resources so they can be cleaned up first.

    Gated on breakage on purpose: on a HEALTHY landing zone these resources are stack-managed and
    are NOT collision risks, so we don't probe/flag them (avoids false positives)."""
    if not getattr(ctx, "check_orphaned_resources", False):
        report.add(Finding("orphaned_resources", INFO,
                           "Orphaned CT-resource (recreate-collision) scan skipped (opt-in)",
                           "After a baseline StackSet is deleted, CT-created resources can linger "
                           "and then collide ('already exists') when Repair/Reset/Update recreates "
                           "them (a common cause of repair failures on a broken landing zone).",
                           remediation="Re-run with --check-orphaned-resources (assumes into the "
                                       "shared accounts; run this when the LZ is broken)."))
        return
    # Fetch present AWSControlTower StackSets — used to detect breakage AND to know which
    # resources are still stack-managed (not orphaned).
    try:
        cfn = ctx.session.client("cloudformation", region_name=ctx.region)
        present = {s["StackSetName"] for s in
                   _collect(cfn, "list_stack_sets", "Summaries", Status="ACTIVE")}
    except (ClientError, BotoCoreError):
        present = set()
    broken = (ctx.lz.get("status") != "ACTIVE"
              or any(e not in present for e in _EXPECTED_STACKSETS))
    if not broken:
        report.add(Finding("orphaned_resources", PASS,
                           "Landing zone healthy; CT resources are stack-managed "
                           "(no recreate-collision scan needed)"))
        return
    targets = []
    if ctx.audit_account:
        targets.append(("Audit", ctx.audit_account))
    if ctx.log_archive_account:
        targets.append(("LogArchive", ctx.log_archive_account))
    rows, unknown, skipped = [], [], []
    for label, acct in targets:
        acct_skips: List[List[str]] = []
        try:
            found = _probe_orphaned_resources(ctx, acct, present, acct_skips)
        except Exception:
            unknown.append(f"{label} ({acct})")
            continue
        for kind, name in found:
            rows.append([label, acct, kind, name])
        for s in acct_skips:
            skipped.append([f"{label} ({acct}): {s[0]}", s[1], s[2]])
    _report_partial_scope(report, "orphaned_resources", "resource probe(s)", skipped)
    if rows:
        report.add(Finding("orphaned_resources", WARNING,
                           f"{len(rows)} leftover Control Tower resource(s) may collide on Repair/Reset",
                           "The landing zone looks broken and these CT-created resources still exist in "
                           "the shared accounts even though the StackSet that manages them is gone. When "
                           "Control Tower recreates them during Repair/Reset/Update, CloudFormation can "
                           "fail with 'already exists'. Reconcile/remove them first. (Only resources "
                           "whose managing StackSet is missing are flagged; regional resources are "
                           "checked in the home region.)",
                           cols=["Account Type", "Account", "Resource type", "Name"], rows=rows,
                           remediation="Remove or reconcile the leftover resource(s) (see the CT "
                                       "'existing resources' guidance) before Repair/Reset."))
    elif unknown:
        report.add(Finding("orphaned_resources", UNKNOWN,
                           f"Could not assume into {', '.join(unknown)} to scan for orphaned resources",
                           "The execution role may itself be missing (part of the breakage).",
                           remediation="Verify the --member-role exists/assumable in the shared accounts."))
    else:
        report.add(Finding("orphaned_resources", PASS,
                           "No orphaned CT resources (managing StackSet missing) in the shared "
                           f"accounts{_scope_suffix(skipped)}"))


def check_provisioned_product_health(ctx: Context, report: Report) -> None:
    """Account Factory provisions accounts via Service Catalog. Products in ERROR/TAINTED are
    accounts in an inconsistent state that cannot be updated via Account Factory/Service Catalog
    (and can block enabling controls on their OU) — an account-re-baselining WARNING, not a
    landing-zone-update blocker. The documented hard block is a provisioned product on a
    CLOSED/SUSPENDED account, which is handled by check_suspended_with_provisioned_product.
    UNDER_CHANGE/PLAN_IN_PROGRESS means an Account Factory operation is mid-flight."""
    try:
        sc = ctx.session.client("servicecatalog", region_name=ctx.region)
        pps = _collect(sc, "search_provisioned_products", "ProvisionedProducts",
                       AccessLevelFilter={"Key": "Account", "Value": "self"})
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("provisioned_products", UNKNOWN,
                           "Could not search Account Factory provisioned products", str(e)))
        return
    # Judge only the products Account Factory created. Unrelated Service Catalog products in
    # the management account have no bearing on a landing-zone update or on re-baselining.
    pps = _account_factory_products(pps)
    bad = [p for p in pps if p.get("Status") in ("ERROR", "TAINTED")]
    inprog = [p for p in pps if p.get("Status") in ("UNDER_CHANGE", "PLAN_IN_PROGRESS")]
    if bad:
        report.add(Finding("provisioned_products", WARNING,
                           f"{len(bad)} Account Factory provisioned product(s) in ERROR/TAINTED",
                           "These accounts are in an inconsistent state and cannot be updated via "
                           "Account Factory / Service Catalog; a TAINTED account can also block "
                           "enabling controls on its OU. This affects account re-baselining (the "
                           "per-account / Re-register OU phase), not the landing-zone update itself, "
                           "so it is a WARNING. (The documented hard blocker is a provisioned product "
                           "on a CLOSED/SUSPENDED account — see the suspended-account check.)",
                           cols=["Product", "Status", "Type"],
                           rows=[[p.get("Name", ""), p.get("Status", ""), p.get("Type", "")]
                                 for p in bad],
                           remediation="Repair or terminate the failed provisioned product(s) before "
                                       "re-baselining the affected accounts."))
    if inprog:
        report.add(Finding("provisioned_products_inprogress", WARNING,
                           f"{len(inprog)} provisioned product(s) UNDER_CHANGE/PLAN_IN_PROGRESS",
                           "An Account Factory operation is in progress; let it finish before upgrading.",
                           cols=["Product", "Status"],
                           rows=[[p.get("Name", ""), p.get("Status", "")] for p in inprog],
                           remediation="Wait for the Account Factory operation to complete."))
    if not bad and not inprog:
        report.add(Finding("provisioned_products", PASS,
                           f"All {len(pps)} Account Factory provisioned product(s) are healthy"
                           if pps else
                           "No Account Factory provisioned products found"))


# Landing zone 4.0 service-integration dependency rules.
#
# The config rule is stated in manifest terms in lz-api-launch.html "Important Notes": "If you
# disable AWS Config integration ("config.enabled": false), you must also disable the following
# integrations: Security Roles ("securityRoles.enabled": false), Access Management
# ("accessManagement.enabled": false), Backup ("backup.enabled": false)."
#
# The securityRoles rule follows from the baseline dependency graph in key-changes-lz-v4.html,
# where IdentityCenterBaseline, BackupAdminBaseline and BackupCentralVaultBaseline each require
# CentralSecurityRolesBaseline to be enabled. accessManagement is the IAM Identity Center
# integration and backup is the AWS Backup integration, so disabling securityRoles requires
# disabling both.
#
# centralizedLogging is deliberately absent: LogArchiveBaseline and CentralConfigBaseline are
# documented as independent, with no dependencies in either direction.
#   key -> (label, integrations that must ALSO be disabled when `key` is disabled)
_V4_INTEGRATION_DEPENDENCIES = (
    ("config", "AWS Config", ("securityRoles", "accessManagement", "backup")),
    ("securityRoles", "Security Roles", ("accessManagement", "backup")),
)
_V4_INTEGRATION_LABELS = {
    "accessManagement": "Access Management (IAM Identity Center)",
    "backup": "AWS Backup",
    "centralizedLogging": "Centralized Logging",
    "config": "AWS Config",
    "securityRoles": "Security Roles",
}


def _integration_enabled(ctx: Context, key: str) -> Optional[bool]:
    """Explicit `enabled` flag for a manifest integration: True, False, or None if absent.

    None is a distinct answer and matters. Landing zone 4.0 requires an `enabled` flag on every
    integration, but earlier manifests omit it (and omit `config` entirely), so an absent flag
    must never be read as "disabled".
    """
    node = (ctx.manifest.get(key)
            or ctx.manifest.get(key[:1].upper() + key[1:])
            or {})
    value = node.get("enabled")
    return value if isinstance(value, bool) else None


def check_v4_integration_dependencies(ctx: Context, report: Report) -> None:
    """v4.0: a disabled service integration requires its dependents to be disabled too.

    Landing zone 4.0 made every service integration individually switchable, but they are not
    independent. lz-api-launch.html states that disabling AWS Config requires also disabling
    Security Roles, Access Management and Backup; key-changes-lz-v4.html's baseline dependency
    graph additionally makes Access Management and Backup depend on Security Roles. A manifest
    holding a contradictory combination is invalid, so an update submitting it is rejected.

    Only an explicit `enabled: false` triggers a rule. An absent flag is treated as "not stated"
    rather than "disabled", because pre-4.0 manifests have no flags at all and omit `config`
    entirely - reading absence as disabled would fire on every 3.x landing zone.

    WARNING, consistent with the other two documented 4.0 prerequisite checks
    (check_cloudtrail_role_v4_policy and check_v4_integration_accounts_same_ou). All three
    arguably warrant BLOCKER, since each describes a condition that stops the upgrade; that is a
    single decision about the set rather than something to change for one of them.
    """
    latest = _latest_major_version(ctx)
    if latest is None or latest < 4:
        return  # the `enabled` flags are a 4.0 concept

    # Keyed by dependent so a single offending integration is reported once, even when it
    # violates both rules (disabling config also implies securityRoles is disabled).
    violations: Dict[str, List[str]] = {}
    for key, label, dependents in _V4_INTEGRATION_DEPENDENCIES:
        if _integration_enabled(ctx, key) is not False:
            continue  # enabled, or not stated - the rule does not apply
        for dep in dependents:
            if _integration_enabled(ctx, dep) is True and dep not in violations:
                violations[dep] = [f"{label} is disabled",
                                   f"{_V4_INTEGRATION_LABELS[dep]} is still enabled",
                                   f"set {dep}.enabled to false"]

    stated = [k for k in _V4_INTEGRATION_LABELS if _integration_enabled(ctx, k) is not None]
    if violations:
        report.add(Finding("v4_integration_deps", WARNING,
                           f"{len(violations)} service integration(s) enabled despite a disabled "
                           "dependency",
                           "Landing zone 4.0 service integrations have documented dependencies. "
                           "This manifest holds a combination the documentation forbids, so an "
                           "update that submits it is expected to be rejected.",
                           cols=["Disabled", "Still enabled", "Required change"],
                           rows=[violations[k] for k in sorted(violations)],
                           remediation="Disable the dependent integrations, or re-enable the one "
                                       "they depend on. Disable order is the reverse of enable "
                                       f"order. See {DOC}/lz-api-launch.html"))
    elif stated:
        report.add(Finding("v4_integration_deps", PASS,
                           f"Service-integration dependencies are consistent "
                           f"({len(stated)} integration(s) declare an enabled flag)"))
    else:
        report.add(Finding("v4_integration_deps", INFO,
                           "No service-integration enabled flags declared in the manifest",
                           "Landing zone 4.0 requires an `enabled` flag on every integration. "
                           "This manifest declares none, which is expected before the upgrade to "
                           "4.0 - the flags are added as part of moving to that version."))


def check_identity_center_region(ctx: Context, report: Report) -> None:
    """Documented prerequisite: IAM Identity Center must live in the landing zone's home Region.

    getting-started-prereqs.html: "If AWS IAM Identity Center (IAM Identity Center) is already set
    up, the AWS Control Tower home Region must be the same as the IAM Identity Center Region.
    However, if IAM Identity Center is set up in the US East (N. Virginia) Region (us-east-1),
    AWS Control Tower uses that instance regardless of the home Region you select." Prerequisites
    matter for an update, not only a first launch: "A landing zone update must meet the same
    prerequisites as a landing zone setup" (troubleshooting.html).

    ListInstances is regional and returns an instance only in the Region where Identity Center is
    deployed, so alignment is established by where the call succeeds. us-east-1 is never reported
    as a mismatch because the documentation explicitly exempts it.

    Absence is not a finding. An organization with no Identity Center instance is a valid
    configuration and the prerequisite simply does not apply, so "not found" is INFO rather than a
    warning - and deliberately not UNKNOWN, which fails closed by default and would gate every
    landing zone that does not use Identity Center.
    """
    if _integration_enabled(ctx, "accessManagement") is False:
        report.add(Finding("identity_center", INFO,
                           "Access Management integration is disabled; Identity Center Region "
                           "alignment not applicable",
                           "The manifest sets accessManagement.enabled to false, so Control Tower "
                           "does not manage IAM Identity Center for this landing zone."))
        return

    # Home Region first, then the documented us-east-1 exemption, then the remaining governed
    # Regions - finding an instance in one of those is the only way to prove a real mismatch.
    order = [ctx.region]
    if ctx.region != "us-east-1":
        order.append("us-east-1")
    order += [r for r in (ctx.governed_regions or []) if r not in order]

    errors: List[List[str]] = []
    for region in order:
        try:
            sso = ctx.session.client("sso-admin", region_name=region)
            instances = sso.list_instances().get("Instances", [])
        except (ClientError, BotoCoreError) as e:
            errors.append([region, _error_code(e), _skip_note(e)])
            continue
        if not instances:
            continue
        if region == ctx.region:
            report.add(Finding("identity_center", PASS,
                               "IAM Identity Center is in the landing zone home Region "
                               f"({ctx.region})"))
            return
        if region == "us-east-1":
            report.add(Finding("identity_center", PASS,
                               "IAM Identity Center is in us-east-1, which Control Tower uses "
                               f"regardless of the home Region ({ctx.region})",
                               "Documented exemption: Control Tower uses an Identity Center "
                               "instance in us-east-1 whatever home Region you select."))
            return
        report.add(Finding("identity_center", WARNING,
                           f"IAM Identity Center is in {region}, not the home Region "
                           f"({ctx.region})",
                           "The home Region must match the Identity Center Region. Only us-east-1 "
                           "is exempt. Identity Center can be installed only in the management "
                           "account of the organization.",
                           cols=["Identity Center Region", "Landing zone home Region"],
                           rows=[[region, ctx.region]],
                           remediation="Align the Regions before updating. See "
                                       f"{DOC}/getting-started-prereqs.html"))
        return

    if errors and len(errors) == len(order):
        report.add(Finding("identity_center", UNKNOWN,
                           "Could not determine the IAM Identity Center Region",
                           "Every ListInstances call failed, so alignment with the home Region is "
                           "unverified.",
                           cols=["Region", "Error", "Detail"], rows=errors))
        return
    report.add(Finding("identity_center", INFO,
                       "No IAM Identity Center instance found in the home Region, us-east-1, or "
                       "any governed Region",
                       "An organization without Identity Center is a valid configuration and this "
                       "prerequisite does not apply to it. If Identity Center IS set up in some "
                       f"other Region, it must match the home Region ({ctx.region}) - only "
                       "us-east-1 is exempt." + _scope_suffix(errors),
                       cols=["Region", "Error", "Detail"], rows=errors or None))


def check_member_execution_roles(ctx: Context, report: Report) -> None:
    """OPT-IN (--check-member-roles): the AWSControlTowerExecution role must exist and be
    assumable in every enrolled account. A missing/modified role is 'role drift' that can make
    the landing zone unavailable. This assumes into each account (slower), so it is opt-in."""
    if not getattr(ctx, "check_member_roles", False):
        report.add(Finding("member_roles", INFO,
                           "Member-account execution-role sweep skipped (opt-in)",
                           "The AWSControlTowerExecution role must exist in every enrolled "
                           "account; a missing/unassumable role is 'role drift' that can make "
                           "the landing zone unavailable.",
                           remediation="Re-run with --check-member-roles to verify (slower; "
                                       "assumes into each account)."))
        return
    try:
        accounts = _collect(ctx.orgs, "list_accounts", "Accounts")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("member_roles", UNKNOWN, "Could not list accounts", str(e)))
        return
    not_assumable, checked = [], 0
    for a in accounts:
        acct = a.get("Id")
        # The management account does not host the execution role; skip it and non-active accounts.
        if acct == ctx.mgmt_account or a.get("Status") != "ACTIVE":
            continue
        checked += 1
        try:
            ctx.assume(acct, ctx.region, "sts").get_caller_identity()
        except Exception as e:  # AssumeRole denied / role missing / any error
            not_assumable.append([acct, a.get("Name", ""), type(e).__name__])
    if not_assumable:
        report.add(Finding("member_roles", WARNING,
                           f"{len(not_assumable)} enrolled account(s): {ctx.member_role} not assumable",
                           "Could not assume the execution role in these accounts. This may be role "
                           "drift (missing/modified AWSControlTowerExecution — which can make the LZ "
                           "unavailable) or an SCP/permission boundary. Verify before upgrading.",
                           cols=["Account", "Name", "Error"], rows=not_assumable,
                           remediation="Confirm the AWSControlTowerExecution role exists and is "
                                       "assumable. Deletion of this role is drift to resolve "
                                       "immediately. Control Tower offers role drift repair, which "
                                       "restores a required role without a full landing-zone "
                                       f"repair; see {DOC}/roles-how.html. Otherwise repair via "
                                       "Reset/Re-register."))
    else:
        report.add(Finding("member_roles", PASS,
                           f"{ctx.member_role} assumable in all {checked} enrolled member account(s)"))


def check_kms_key_policy(ctx: Context, report: Report) -> None:
    """OPT-IN (--check-kms-policy): if the landing zone uses a customer-managed KMS key, its key
    policy must allow Control Tower's Config and CloudTrail integration to use the key, or the
    update can fail with a KMS error. Heuristic string check (key policies vary), so opt-in."""
    if not ctx.kms_key_arn:
        return  # no CMK -> the enabled-state check already reported INFO
    if not getattr(ctx, "check_kms_policy", False):
        report.add(Finding("kms_policy", INFO,
                           "KMS key-policy check skipped (opt-in)",
                           "A customer-managed KMS key is configured; its policy must allow CT's "
                           "Config/CloudTrail integration.",
                           remediation="Re-run with --check-kms-policy to heuristically verify it."))
        return
    try:
        kms = ctx.session.client("kms", region_name=ctx.region)
        pol = kms.get_key_policy(KeyId=ctx.kms_key_arn, PolicyName="default").get("Policy", "")
    except (ClientError, BotoCoreError) as e:
        report.add(Finding("kms_policy", UNKNOWN, "Could not read the KMS key policy", str(e)))
        return
    missing = [s for s in ("config.amazonaws.com", "cloudtrail.amazonaws.com") if s not in pol]
    if missing:
        report.add(Finding("kms_policy", WARNING,
                           "Landing zone KMS key policy may not grant required CT services",
                           "The key policy does not reference: " + ", ".join(missing) + ". "
                           "Control Tower's Config/CloudTrail integration must be allowed to use "
                           "the key or the update can fail with a KMS error. (Heuristic check — "
                           "confirm the policy, e.g. access may be granted via grants/conditions.)",
                           remediation="Ensure the key policy allows config.amazonaws.com and "
                                       "cloudtrail.amazonaws.com to use the key."))
    else:
        report.add(Finding("kms_policy", PASS,
                           "KMS key policy references Config and CloudTrail service principals"))


CHECKS = [
    check_lz_status,
    check_lz_drift,
    check_update_available,
    check_upgrade_path_considerations,
    check_managed_accounts,
    check_suspended_with_provisioned_product,
    check_provisioned_product_health,
    check_enabled_controls,
    check_enabled_baselines,
    check_stale_baseline_targets,
    check_stale_control_targets,
    check_foundational_ou_structure,
    check_governed_region_availability,
    check_management_account_stacks,
    check_foundational_ou_not_nested,
    check_stacksets,
    check_expected_stacksets,
    check_stackset_active_drift,
    check_stackset_operations_in_progress,
    check_config_in_shared_accounts,
    check_log_archive_bucket_state,
    check_orphaned_ct_resources,
    check_customizations,
    check_trusted_access,
    check_delegated_admins,
    check_required_iam_roles,
    check_cloudtrail_role_v4_policy,
    check_v4_integration_accounts_same_ou,
    check_v4_integration_dependencies,
    check_identity_center_region,
    check_member_execution_roles,
    check_kms_key,
    check_kms_key_policy,
    check_sts_regional_activation,
    check_scp_headroom,
    check_scp_blocking,
]


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------
# Maximum table rows printed per finding. The full set is always kept on the Finding (and so
# reaches the --json report); the console view is capped and says how many were withheld.
_MAX_DISPLAY_ROWS = 50


def _strip_controls(text: str, keep_newlines: bool = False) -> str:
    """Replace C0/C1 control characters with spaces.

    Resource names, OU names, SCP names and AWS error messages all reach the report from API
    responses, and anyone with organization write access chooses those names. An embedded ANSI
    escape or carriage return could reposition the cursor, recolour output, or forge a report
    line - including a fake "[OK]" - so control characters never reach the terminal verbatim.
    JSON output needs no equivalent guard: json.dump escapes control characters itself.
    """
    return "".join(
        c if (keep_newlines and c == "\n")
        else (" " if (ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0) else c)
        for c in str(text)
    )


def _safe_cell(value: Any) -> str:
    """Render one table cell from possibly API-derived data.

    Also replaces the column separator, so a resource name containing "|" cannot fake a column
    break and misalign the table.
    """
    return _strip_controls(value).replace("|", "/")


ICON = {BLOCKER: "[X]", WARNING: "[!]", INFO: "[i]", PASS: "[OK]", UNKNOWN: "[?]"}

# ANSI colors per severity. Emitted only when writing to an interactive terminal
# (see _supports_color); piped/redirected output and the --json file stay plain, so
# pipeline logs and downstream parsing are never polluted with escape codes.
_RESET = "\033[0m"
_BOLD = "\033[1m"
COLOR = {
    BLOCKER: "\033[1;31m",  # bold red
    WARNING: "\033[33m",    # yellow
    UNKNOWN: "\033[35m",    # magenta
    INFO:    "\033[36m",    # cyan
    PASS:    "\033[32m",    # green
}


def _supports_color(mode: str) -> bool:
    """Whether to emit ANSI color. mode: 'auto' | 'always' | 'never'."""
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR") is not None:  # https://no-color.org/
        return False
    if mode == "always":
        return True
    return sys.stdout.isatty()  # auto: only for an interactive terminal


def _c(text: str, level: str, use_color: bool, bold: bool = False) -> str:
    """Wrap text in the severity color when coloring is enabled; otherwise return as-is."""
    if not use_color:
        return text
    prefix = COLOR.get(level, "")
    if bold and _BOLD not in prefix:
        prefix = _BOLD + prefix
    return f"{prefix}{text}{_RESET}" if prefix else text


def render_text(report: Report, ctx: Context, use_color: bool = False,
                discovery_failed: bool = False) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append((_BOLD + "AWS Control Tower — Pre-Upgrade Precheck" + _RESET)
                 if use_color else "AWS Control Tower — Pre-Upgrade Precheck")
    # Only call it the management account once that is established. On a member account the
    # caller's own id was being printed under a "Management account" label, which is wrong
    # information rather than a missing check.
    _acct_label = ("Caller account" if ctx.caller_is_management is False
                   else "Management account")
    lines.append(f"  {_acct_label:<18} : {ctx.mgmt_account or 'not determined'}")
    lines.append(f"  Home region        : {ctx.region}")
    # Discovery can fail before any of this is known. Printing a bare Python None, or an
    # empty list, reads as a rendering bug rather than as "there was nothing to read".
    _ver = ctx.lz.get("version")
    if _ver:
        _latest = ctx.lz.get("latestAvailableVersion")
        lines.append(f"  Landing zone       : v{_ver}"
                     + (f" (latest {_latest})" if _latest else ""))
    else:
        lines.append("  Landing zone       : not determined")
    lines.append("  Governed regions   : "
                 + (", ".join(ctx.governed_regions) if ctx.governed_regions
                    else "not determined"))
    lines.append("=" * 78)
    for level in (BLOCKER, WARNING, UNKNOWN, INFO, PASS):
        group = report.by_level(level)
        if not group:
            continue
        lines.append("\n" + _c(f"{ICON[level]} {level}  ({len(group)})", level, use_color, bold=True))
        lines.append("-" * 78)
        for f in group:
            lines.append("  " + _c(f"{ICON[level]} {_strip_controls(f.summary)}",
                                   level, use_color))
            if f.detail:
                lines.append(f"        {_strip_controls(f.detail, keep_newlines=True)}")
            if f.rows:
                lines.append(f"        {' | '.join(f.cols)}")
                for r in f.rows[:_MAX_DISPLAY_ROWS]:
                    lines.append(f"          - {' | '.join(_safe_cell(x) for x in r)}")
                withheld = len(f.rows) - _MAX_DISPLAY_ROWS
                if withheld > 0:
                    lines.append(f"          ... and {withheld} more row(s) not shown "
                                 "(the full list is in the --json report)")
            if f.remediation:
                lines.append(f"        FIX: {_strip_controls(f.remediation)}")
            doc = f.doc or _CHECK_DOCS.get(f.check, "")
            if doc:
                lines.append(f"        DOC: {doc}")
    lines.append("\n" + "=" * 78)
    n_block = len(report.by_level(BLOCKER))
    n_unk = len(report.by_level(UNKNOWN))
    n_warn = len(report.by_level(WARNING))
    if discovery_failed:
        # None of the checks ran, so there is no verdict to give. Saying "NOT SAFE TO
        # UPGRADE" here would assert something about a landing zone that was never read -
        # and it contradicts the exit code, which is 3 (the precheck could not run) rather
        # than 2 (a blocker was found).
        lines.append(_c("RESULT: PRECHECK DID NOT RUN — the landing zone could not be read, "
                        "so none of the checks were evaluated. This is not a verdict on "
                        "whether the landing zone can be upgraded.", BLOCKER, use_color,
                        bold=True))
    elif n_block:
        lines.append(_c(f"RESULT: NOT SAFE TO UPGRADE — {n_block} blocker(s), "
                        f"{n_warn} warning(s), {n_unk} unverified.", BLOCKER, use_color, bold=True))
    else:
        lines.append(_c(f"RESULT: No blockers. {n_warn} warning(s), {n_unk} unverified — "
                        "review before proceeding.", PASS, use_color, bold=True))
    lines.append("=" * 78)
    return "\n".join(lines)


def render_upgrade_notes(cur: str, latest: str, use_color: bool = False) -> str:
    """Standalone advisory checklist for a version path (no AWS calls). Answers
    'what should I know / watch for upgrading from vX to vY?'."""
    items = upgrade_path_considerations(cur, latest)
    lines = ["=" * 78]
    title = f"AWS Control Tower — Upgrade-Path Considerations: v{cur} -> v{latest}"
    lines.append((_BOLD + title + _RESET) if use_color else title)
    lines.append("=" * 78)
    if not items:
        lines.append(f"No catalogued version-boundary changes between v{cur} and v{latest}.")
        lines.append("(This checklist covers landing zone versions 3.0, 3.1, 3.2, 3.3, and 4.0. "
                     "Confirm cur/latest are landing zone versions, e.g. 2.9:4.0.)")
        lines.append("=" * 78)
        return "\n".join(lines)
    for ver, doc, rows in items:
        lines.append("\n" + _c(f"[ v{ver} ]", INFO, use_color, bold=True))
        lines.append("-" * 78)
        for change, action in rows:
            lines.append("  - " + (_c(change, INFO, use_color)))
            lines.append(f"      {action}")
        lines.append(f"  DOC: {doc}")
    lines.append("\n" + "=" * 78)
    lines.append(f"{len(items)} version boundary(ies) crossed. Advisory checklist — verify against "
                 "the linked release notes before upgrading.")
    lines.append("=" * 78)
    return "\n".join(lines)


def exit_code(report: Report, strict: bool = False, allow_unknown: bool = False) -> int:
    """Process exit code, for pipeline gating.

    BLOCKER always fails.

    UNKNOWN also fails by default. An UNKNOWN means a check could not be evaluated, and for a
    gate in front of a landing-zone update - an operation AWS publishes a pre-update checklist
    for - "I could not check this" must not read as "safe to proceed". Pass allow_unknown=True
    to opt out deliberately.

    WARNING does not fail by default. A WARNING is "reviewed, and not a blocker" - for example a
    drifted StackSet instance in a member account, which this tool's own finding text states does
    NOT block a landing-zone update. Pass strict=True to fail on warnings too.
    """
    if report.has_blockers:
        return 2
    if report.has_unknowns and not allow_unknown:
        return 2
    if strict and report.has_warnings:
        return 2
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Control Tower pre-upgrade precheck (read-only)")
    ap.add_argument("--region", help="Home region (defaults to session region)")
    ap.add_argument("--profile", help="AWS profile for the management account")
    ap.add_argument("--member-role", default="AWSControlTowerExecution",
                    help="Role to assume in shared accounts for the Config check")
    ap.add_argument("--audit-account", help="Override Audit account id")
    ap.add_argument("--log-archive-account", help="Override Log Archive account id")
    ap.add_argument("--json", help="Write full JSON report to this path")
    ap.add_argument("--detect-drift", action="store_true",
                    help="Actively run CloudFormation StackSet drift detection on "
                         "AWSControlTower* StackSets (slower; launches drift operations)")
    ap.add_argument("--drift-timeout", type=int, default=900,
                    help="Total seconds budgeted for StackSet drift detection, shared across "
                         "all StackSets (default 900). StackSets not reached within the budget "
                         "are reported as not started, not as timeouts")
    ap.add_argument("--check-member-roles", action="store_true",
                    help="Assume into every enrolled account to verify the execution role "
                         "(AWSControlTowerExecution) is present/assumable (slower)")
    ap.add_argument("--check-kms-policy", action="store_true",
                    help="Heuristically verify the landing-zone CMK key policy grants CT's "
                         "Config/CloudTrail service principals")
    ap.add_argument("--check-orphaned-resources", action="store_true",
                    help="When the LZ looks broken, scan shared accounts for leftover CT resources "
                         "that would collide ('already exists') when Repair/Reset recreates them")
    ap.add_argument("--strict", action="store_true",
                    help="Also treat WARNING as blocking. UNKNOWN already blocks by default "
                         "(see --allow-unknown)")
    ap.add_argument("--allow-unknown", action="store_true",
                    help="Exit 0 even when one or more checks could not be evaluated (UNKNOWN). "
                         "Off by default: an unverified check is not evidence of a safe upgrade")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="Colorize the text report: auto (TTY only, default), always, or never "
                         "(also honors the NO_COLOR environment variable)")
    ap.add_argument("--upgrade-notes", metavar="CURRENT:LATEST",
                    help="Print the doc-cited upgrade-path considerations checklist for a version "
                         "path (e.g. 2.9:4.0) and exit. Requires no AWS access.")
    args = ap.parse_args()

    use_color = _supports_color(args.color)

    if args.upgrade_notes:
        parts = args.upgrade_notes.split(":", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            print("Use --upgrade-notes CURRENT:LATEST, e.g. 2.9:4.0", file=sys.stderr)
            return 3
        print(render_upgrade_notes(parts[0].strip(), parts[1].strip(), use_color))
        return 0

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    region = args.region or session.region_name
    if not region:
        print("No region: pass --region or configure a default.", file=sys.stderr)
        return 3

    report = Report()
    ctx = Context(session, region, args.member_role)
    if not ctx.discover(report):
        print(render_text(report, ctx, use_color, discovery_failed=True))
        return 3
    if args.audit_account:
        ctx.audit_account = args.audit_account
    if args.log_archive_account:
        ctx.log_archive_account = args.log_archive_account
    ctx.detect_drift = args.detect_drift
    ctx.drift_timeout = args.drift_timeout
    ctx.check_member_roles = args.check_member_roles
    ctx.check_kms_policy = args.check_kms_policy
    ctx.check_orphaned_resources = args.check_orphaned_resources

    # Progress goes to stderr, never stdout: stdout carries the report, which is piped and
    # redirected. Without it a run looks hung — it makes hundreds of API calls and can take
    # a few minutes on a large organization.
    _total = len(CHECKS)
    print(f"Running {_total} pre-upgrade checks against the landing zone in {region}. "
          f"This usually takes one to three minutes.", file=sys.stderr)
    for _i, check in enumerate(CHECKS, 1):
        _label = check.__name__.replace("check_", "").replace("_", " ")
        _progress(f"[{_i:2d}/{_total}] {_label}")
        try:
            check(ctx, report)
        except Exception as e:  # a check must never crash the gate
            report.add(Finding(check.__name__, UNKNOWN,
                               f"Check '{check.__name__}' errored", repr(e)))
    _progress(f"{_total} checks complete.")
    if sys.stderr.isatty():
        print("", file=sys.stderr)

    print(render_text(report, ctx, use_color))
    if args.json:
        def _as_dict(f: Finding) -> dict:
            d = asdict(f)
            d["doc"] = f.doc or _CHECK_DOCS.get(f.check, "")
            return d
        # The report carries the organization's account IDs, OU identifiers, ARNs, resource
        # names and verbatim API error strings, so create it 0600 (not world-readable at the
        # default umask) and refuse to follow a symlink rather than clobber its target.
        _flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        _fd = os.open(args.json, _flags, 0o600)
        # os.open applies that mode ONLY when it creates the file. An existing report.json
        # keeps whatever permissions it already had, so a second run would leave a
        # world-readable file. Set it explicitly. fchmod acts on the open descriptor, so
        # the path cannot be swapped between the open and the permission change.
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(_fd, 0o600)
            except OSError as e:
                # Writable but not chmod-able means someone else owns it - say so rather
                # than silently produce a file without the protection F-05 asks for.
                print(f"WARNING: could not restrict permissions on {args.json}: {e}")
        with os.fdopen(_fd, "w") as fh:
            json.dump({"findings": [_as_dict(f) for f in report.findings]}, fh, indent=2)
        print(f"\nJSON report written to {args.json}")

    return exit_code(report, strict=args.strict, allow_unknown=args.allow_unknown)



if __name__ == "__main__":
    sys.exit(main())
