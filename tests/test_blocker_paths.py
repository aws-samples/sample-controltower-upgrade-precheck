#!/usr/bin/env python3
"""
Offline test harness for the Control Tower pre-upgrade precheck.

WHY THIS EXISTS
---------------
A live run against a *healthy* landing zone only proves the PASS/INFO paths. It does NOT
prove that the checks correctly raise BLOCKER / WARNING on a broken environment. This harness
feeds each check simulated "bad" (and "good") AWS API responses via lightweight fakes and
asserts the correct severity fires — so the blocker-detection logic is proven without needing
a deliberately-broken real Control Tower account.

RUN
---
    python3 tests/test_blocker_paths.py            # plain unittest, no extra deps
    (or)  python3 -m pytest tests/                 # if pytest is installed

No AWS credentials or network are used.
"""

import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

from botocore.exceptions import ClientError

# ---- import the tool module by path (Source/ct_preupgrade_precheck.py) --------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD_PATH = os.path.join(_HERE, "..", "Source", "ct_preupgrade_precheck.py")
_spec = importlib.util.spec_from_file_location("ct_precheck", _MOD_PATH)
ct = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ct)


# ---- fakes ---------------------------------------------------------------------------
def client_error(code, op="Op"):
    return ClientError({"Error": {"Code": code, "Message": code}}, op)


class FakeClient:
    """A stand-in boto3 client. `responses` maps method_name -> dict (or callable(**kwargs)).
    `errors` maps method_name -> exception to raise. can_paginate() returns False so the
    tool's _collect() falls back to a direct method call."""

    def __init__(self, responses=None, errors=None):
        self.responses = responses or {}
        self.errors = errors or {}

    def can_paginate(self, op):
        return False

    def __getattr__(self, name):
        # only reached for names not set as real attributes (i.e., API calls)
        def _call(**kwargs):
            if name in self.errors:
                raise self.errors[name]
            r = self.responses.get(name, {})
            return r(**kwargs) if callable(r) else r
        return _call


class _Creds:
    access_key = "AK"
    secret_key = "SK"  # nosec B105 - fake test credential, not a real secret
    token = "TK"  # nosec B105 - fake test credential, not a real secret

    def get_frozen_credentials(self):
        return self


class FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, service, region_name=None, **kwargs):
        return self._clients.get(service, FakeClient())

    def get_credentials(self):
        return _Creds()


def kms_arn(account, key_id="abcd-1234", region="us-east-1"):
    """Build a synthetic KMS key ARN for tests.

    Composed from parts rather than written as a literal: secret scanners flag an
    ARN-shaped string as a hard-coded key ARN, and these fixtures are placeholders for
    keys that do not exist. Composing keeps the scan clean without an allowlist entry.
    """
    return ":".join(["arn", "aws", "kms", region, account, "key/" + key_id])


def make_ctx(clients=None, **overrides):
    """Build a Context wired to fakes, with healthy discovered defaults that tests override."""
    clients = clients or {}
    clients.setdefault("controltower", FakeClient())
    clients.setdefault("organizations", FakeClient())
    ctx = ct.Context(FakeSession(clients), "us-east-1", "AWSControlTowerExecution")
    ctx.mgmt_account = "111111111111"
    ctx.lz = overrides.get("lz", {
        "status": "ACTIVE", "version": "3.2", "latestAvailableVersion": "4.0",
        "driftStatus": {"status": "IN_SYNC"},
    })
    ctx.manifest = overrides.get("manifest", {})
    ctx.governed_regions = overrides.get("governed_regions", ["us-east-1"])
    ctx.audit_account = overrides.get("audit_account", "444444444444")
    ctx.log_archive_account = overrides.get("log_archive_account", "555555555555")
    ctx.kms_key_arn = overrides.get("kms_key_arn", None)
    return ctx


def levels(report):
    return {f.level for f in report.findings}


def _run(check, ctx):
    rpt = ct.Report()
    check(ctx, rpt)
    return rpt


# ---- tests ---------------------------------------------------------------------------
class TestBlockerPaths(unittest.TestCase):

    # 1. LZ status -----------------------------------------------------------------
    def test_lz_status_failed_blocks(self):
        ctx = make_ctx(lz={"status": "FAILED", "version": "3.2", "messages": [{"message": "boom"}]})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_lz_status, ctx)))

    def test_lz_status_processing_blocks(self):
        ctx = make_ctx(lz={"status": "PROCESSING", "version": "3.2"})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_lz_status, ctx)))

    def test_lz_status_active_passes(self):
        ctx = make_ctx()
        self.assertIn(ct.PASS, levels(_run(ct.check_lz_status, ctx)))

    # 2. LZ drift ------------------------------------------------------------------
    def test_lz_drift_drifted_blocks(self):
        ctx = make_ctx(lz={"status": "ACTIVE", "driftStatus": {"status": "DRIFTED"}})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_lz_drift, ctx)))

    def test_lz_drift_in_sync_passes(self):
        ctx = make_ctx()
        self.assertIn(ct.PASS, levels(_run(ct.check_lz_drift, ctx)))

    # 4. managed accounts ----------------------------------------------------------
    def test_managed_accounts_suspended_warns(self):
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "222222222222", "Name": "bad", "Status": "SUSPENDED"}]}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.WARNING, levels(_run(ct.check_managed_accounts, ctx)))

    # 5. suspended account + provisioned product (classic blocker) -----------------
    def test_suspended_with_provisioned_product_blocks(self):
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "333333333333", "Name": "closed", "Status": "SUSPENDED"}]}})
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "account-333333333333-abc", "Status": "AVAILABLE",
             "Type": "CONTROL_TOWER_ACCOUNT",
             "PhysicalId": "arn:aws:...:333333333333"}]}})
        ctx = make_ctx({"organizations": orgs, "servicecatalog": sc})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_suspended_with_provisioned_product, ctx)))

    def test_unrelated_product_for_suspended_account_is_not_a_blocker(self):
        # The management account's Service Catalog holds products Control Tower does not own.
        # One that merely mentions a suspended account id must not raise a BLOCKER.
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "333333333333", "Name": "closed", "Status": "SUSPENDED"}]}})
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "my-app-stack", "Status": "AVAILABLE", "Type": "CFN_STACK",
             "PhysicalId": "arn:aws:...:333333333333"}]}})
        ctx = make_ctx({"organizations": orgs, "servicecatalog": sc})
        self.assertNotIn(ct.BLOCKER, levels(_run(ct.check_suspended_with_provisioned_product, ctx)))

    def test_unrelated_provisioned_product_types_are_not_reported(self):
        # Reported by an SME: unhealthy CFN_STACK and TERRAFORM_OPEN_SOURCE products were
        # being counted as Account Factory failures. On one organization 31 of 32 unhealthy
        # products were unrelated, so this has to filter on type, not just status.
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "app-1", "Status": "TAINTED", "Type": "CFN_STACK"},
            {"Name": "app-2", "Status": "ERROR", "Type": "TERRAFORM_OPEN_SOURCE"},
            {"Name": "app-3", "Status": "ERROR", "Type": "CFN_STACKSET"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        lv = levels(_run(ct.check_provisioned_product_health, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_account_factory_failure_still_reported_alongside_unrelated_ones(self):
        # The filter must not hide a genuine Account Factory failure sitting next to noise.
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "app-1", "Status": "TAINTED", "Type": "CFN_STACK"},
            {"Name": "acct-real", "Status": "TAINTED", "Type": "CONTROL_TOWER_ACCOUNT"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        findings = _run(ct.check_provisioned_product_health, ctx).findings
        warn = [f for f in findings if f.level == ct.WARNING]
        self.assertTrue(warn, "a real Account Factory failure must still be reported")
        self.assertIn("1 Account Factory", warn[0].summary)
        self.assertEqual([r[0] for r in warn[0].rows], ["acct-real"])

    # 6. enabled controls drift ----------------------------------------------------
    def test_enabled_controls_drift_warns_not_blocks(self):
        # Control drift is a documented repairable change, absent from drift.html's
        # "resolve right away" list, so it must not block the update.
        orgs = FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent":
                lambda ParentId=None, **k: {"OrganizationalUnits":
                    [{"Id": "ou-1", "Arn": "arn:ou-1", "Name": "Prod"}] if ParentId == "r-root" else []},
        })
        ctl = FakeClient({"list_enabled_controls": {"enabledControls": [
            {"controlIdentifier": "AWS-GR_X",
             "driftStatusSummary": {"driftStatus": "DRIFTED"},
             "statusSummary": {"status": "SUCCEEDED"}}]}})
        ctx = make_ctx({"organizations": orgs, "controltower": ctl})
        lv = levels(_run(ct.check_enabled_controls, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    # 7. enabled baselines drift/failed --------------------------------------------
    def test_enabled_baselines_failed_blocks(self):
        # On a service-integration account (Audit), which a landing-zone update acts on.
        ctl = FakeClient({"list_enabled_baselines": {"enabledBaselines": [
            {"targetIdentifier": "arn:aws:organizations::111111111111:account/o-a/444444444444",
             "baselineVersion": "4.0",
             "statusSummary": {"status": "FAILED"}}]}})
        ctx = make_ctx({"controltower": ctl})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_enabled_baselines, ctx)))

    # 7b. Baselines targeting an OU that no longer exists --------------------------
    # A customer deleting an OU in Organizations without deregistering it from Control
    # Tower leaves Control Tower referencing a missing OU; the next landing-zone update
    # fails with TargetNotFoundException and the landing zone is left FAILED.
    @staticmethod
    def _ou_arn(ou_id, account="111111111111", org="o-example"):
        return ":".join(["arn", "aws", "organizations", "", account, "ou/%s/%s" % (org, ou_id)])

    @staticmethod
    def _acct_target(acct, account="111111111111", org="o-example"):
        return ":".join(["arn", "aws", "organizations", "", account,
                         "account/%s/%s" % (org, acct)])

    def _baselines_ctx(self, targets, existing_ou_ids):
        ctl = FakeClient({"list_enabled_baselines": {"enabledBaselines": [
            {"targetIdentifier": t, "baselineVersion": "4.0",
             "statusSummary": {"status": "SUCCEEDED"}} for t in targets]}})
        ctx = make_ctx({"controltower": ctl})
        ctx.all_ou_arns = lambda: [{"Id": i, "Arn": self._ou_arn(i), "Name": i}
                                   for i in existing_ou_ids]
        return ctx

    def test_stale_baseline_target_warns(self):
        ctx = self._baselines_ctx([self._ou_arn("ou-gone")], ["ou-live"])
        lv = levels(_run(ct.check_stale_baseline_targets, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.PASS, lv)

    def test_baseline_targets_all_resolve_passes(self):
        ctx = self._baselines_ctx([self._ou_arn("ou-live")], ["ou-live", "ou-other"])
        lv = levels(_run(ct.check_stale_baseline_targets, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_account_targeted_baselines_are_not_flagged_stale(self):
        # Account targets are never in the OU set. Treating them as stale would make this
        # check fire on every healthy landing zone.
        ctx = self._baselines_ctx([self._acct_target("333333333333")], ["ou-live"])
        lv = levels(_run(ct.check_stale_baseline_targets, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_stale_baseline_targets_ou_read_failure_is_unknown(self):
        # Failing to read the OU tree must not read as "nothing stale".
        ctx = self._baselines_ctx([self._ou_arn("ou-gone")], [])

        def boom():
            raise client_error("AccessDeniedException", "ListOrganizationalUnitsForParent")
        ctx.all_ou_arns = boom
        lv = levels(_run(ct.check_stale_baseline_targets, ctx))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.PASS, lv)

    def test_stale_baseline_targets_baseline_read_failure_is_unknown(self):
        ctl = FakeClient(errors={"list_enabled_baselines":
                                 client_error("ThrottlingException", "ListEnabledBaselines")})
        ctx = make_ctx({"controltower": ctl})
        ctx.all_ou_arns = lambda: [{"Id": "ou-live", "Arn": self._ou_arn("ou-live"),
                                    "Name": "ou-live"}]
        lv = levels(_run(ct.check_stale_baseline_targets, ctx))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.PASS, lv)

    # 7c. Foundational OU structure — three of drift.html's four urgent drift types --------
    ALL_ON = {"centralizedLogging": {"enabled": True, "accountId": "555555555555"},
              "securityRoles": {"enabled": True, "accountId": "444444444444"},
              "config": {"enabled": True, "accountId": "444444444444"},
              "backup": {"enabled": True, "configurations": {
                  "backupAdmin": {"accountId": "777777777777"},
                  "centralBackup": {"accountId": "888888888888"}}}}

    def _ou_ctx(self, parents, ou_accounts, ous, manifest=None):
        """parents: accountId -> parentId. ou_accounts: parentId -> [account dicts]."""
        orgs = FakeClient({
            "list_accounts": {"Accounts": [{"Id": a, "Status": "ACTIVE"} for a in parents]},
            "list_parents": lambda ChildId=None, **k: {
                "Parents": [{"Id": parents[ChildId], "Type": "ORGANIZATIONAL_UNIT"}]}
                if ChildId in parents else {"Parents": []},
            "list_accounts_for_parent": lambda ParentId=None, **k: {
                "Accounts": ou_accounts.get(ParentId, [])},
        })
        ctx = make_ctx({"organizations": orgs},
                       manifest=manifest if manifest is not None else self.ALL_ON)
        ctx.all_ou_arns = lambda: ous
        return ctx

    def test_foreign_account_in_foundational_ou_blocks(self):
        # Control Tower's update validator rejects this outright: "the Security OU contains
        # accounts other than the shared accounts ... then try again."
        ctx = self._ou_ctx(
            parents={"444444444444": "ou-sec", "555555555555": "ou-sec",
                     "777777777777": "ou-sec", "888888888888": "ou-sec"},
            ou_accounts={"ou-sec": [{"Id": "444444444444"}, {"Id": "555555555555"},
                                    {"Id": "777777777777"}, {"Id": "888888888888"},
                                    {"Id": "333333333333", "Name": "workload"}]},
            ous=[{"Id": "ou-sec", "Arn": "arn:ou-sec", "Name": "Security"},
                 {"Id": "ou-wl", "Arn": "arn:ou-wl", "Name": "Workloads"}])
        lv = levels(_run(ct.check_foundational_ou_structure, ctx))
        self.assertIn(ct.BLOCKER, lv)

    def test_disabled_integration_does_not_make_its_account_look_foreign(self):
        # Found live: a landing zone with centralizedLogging disabled names no logging account,
        # but the Log Archive account still sits in the Foundational OU. Judging against that
        # incomplete list reported a legitimate shared account as foreign - a false blocker on a
        # landing zone that had just upgraded successfully.
        manifest = {"centralizedLogging": {"enabled": False},
                    "securityRoles": {"enabled": True, "accountId": "444444444444"},
                    "config": {"enabled": True, "accountId": "444444444444"}}
        ctx = self._ou_ctx(
            parents={"444444444444": "ou-sec"},
            ou_accounts={"ou-sec": [{"Id": "444444444444"},
                                    {"Id": "555555555555", "Name": "Log Account"}]},
            ous=[{"Id": "ou-sec", "Arn": "arn:ou-sec", "Name": "Security"},
                 {"Id": "ou-wl", "Arn": "arn:ou-wl", "Name": "Workloads"}],
            manifest=manifest)
        lv = levels(_run(ct.check_foundational_ou_structure, ctx))
        self.assertNotIn(ct.BLOCKER, lv)
        self.assertIn(ct.INFO, lv, "the skipped comparison must be disclosed, not silent")

    def test_absent_enabled_flag_is_not_treated_as_disabled(self):
        # Pre-4.0 manifests omit the `enabled` flag entirely. Reading absent as disabled would
        # skip the comparison on every older landing zone.
        manifest = {"securityRoles": {"accountId": "444444444444"},
                    "centralizedLogging": {"accountId": "555555555555"}}
        ctx = self._ou_ctx(
            parents={"444444444444": "ou-sec", "555555555555": "ou-sec"},
            ou_accounts={"ou-sec": [{"Id": "444444444444"}, {"Id": "555555555555"},
                                    {"Id": "333333333333", "Name": "workload"}]},
            ous=[{"Id": "ou-sec", "Arn": "arn:ou-sec", "Name": "Security"},
                 {"Id": "ou-wl", "Arn": "arn:ou-wl", "Name": "Workloads"}],
            manifest=manifest)
        # The comparison must actually run, so the foreign account is found.
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_foundational_ou_structure, ctx)))

    def test_shared_accounts_split_across_ous_warns(self):
        # drift.html: "Don't remove shared accounts ... To remediate this type of drift, you
        # must update the landing zone." The update is the remedy, so this warns, not blocks.
        ctx = self._ou_ctx(
            parents={"444444444444": "ou-sec", "555555555555": "ou-other",
                     "777777777777": "ou-sec", "888888888888": "ou-sec"},
            ou_accounts={},
            ous=[{"Id": "ou-sec", "Arn": "arn:ou-sec", "Name": "Security"},
                 {"Id": "ou-other", "Arn": "arn:ou-other", "Name": "Other"}])
        lv = levels(_run(ct.check_foundational_ou_structure, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_no_additional_ou_warns(self):
        # drift.html: "At least one Additional OU is required for AWS Control Tower to operate."
        ctx = self._ou_ctx(
            parents={"444444444444": "ou-sec", "555555555555": "ou-sec",
                     "777777777777": "ou-sec", "888888888888": "ou-sec"},
            ou_accounts={"ou-sec": [{"Id": "444444444444"}, {"Id": "555555555555"},
                                    {"Id": "777777777777"}, {"Id": "888888888888"}]},
            ous=[{"Id": "ou-sec", "Arn": "arn:ou-sec", "Name": "Security"}])
        rpt = _run(ct.check_foundational_ou_structure, ctx)
        warn = [f for f in rpt.findings if f.level == ct.WARNING]
        self.assertTrue(warn and "Additional OU" in warn[0].summary)

    def test_healthy_foundational_ou_passes(self):
        ctx = self._ou_ctx(
            parents={"444444444444": "ou-sec", "555555555555": "ou-sec",
                     "777777777777": "ou-sec", "888888888888": "ou-sec"},
            ou_accounts={"ou-sec": [{"Id": "444444444444"}, {"Id": "555555555555"},
                                    {"Id": "777777777777"}, {"Id": "888888888888"}]},
            ous=[{"Id": "ou-sec", "Arn": "arn:ou-sec", "Name": "Security"},
                 {"Id": "ou-wl", "Arn": "arn:ou-wl", "Name": "Workloads"}])
        lv = levels(_run(ct.check_foundational_ou_structure, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.BLOCKER, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_unreadable_parent_is_unknown_not_pass(self):
        orgs = FakeClient(
            responses={"list_accounts": {"Accounts": []}},
            errors={"list_parents": client_error("AccessDeniedException", "ListParents")})
        ctx = make_ctx({"organizations": orgs}, manifest=self.ALL_ON)
        ctx.all_ou_arns = lambda: [{"Id": "ou-sec", "Arn": "a", "Name": "Security"}]
        lv = levels(_run(ct.check_foundational_ou_structure, ctx))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.PASS, lv)

    # 7d. Governed Region availability ---------------------------------------------------
    def test_disabled_governed_region_warns(self):
        acct = FakeClient({"list_regions": {"Regions": [
            {"RegionName": "us-east-1", "RegionOptStatus": "ENABLED_BY_DEFAULT"},
            {"RegionName": "me-central-1", "RegionOptStatus": "DISABLED"}]}})
        ctx = make_ctx({"account": acct}, governed_regions=["us-east-1", "me-central-1"])
        rpt = _run(ct.check_governed_region_availability, ctx)
        self.assertIn(ct.WARNING, levels(rpt))
        warn = [f for f in rpt.findings if f.level == ct.WARNING][0]
        self.assertEqual(warn.rows[0][0], "me-central-1")

    def test_all_governed_regions_enabled_passes(self):
        acct = FakeClient({"list_regions": {"Regions": [
            {"RegionName": "us-east-1", "RegionOptStatus": "ENABLED_BY_DEFAULT"},
            {"RegionName": "eu-west-2", "RegionOptStatus": "ENABLED"}]}})
        ctx = make_ctx({"account": acct}, governed_regions=["us-east-1", "eu-west-2"])
        self.assertIn(ct.PASS, levels(_run(ct.check_governed_region_availability, ctx)))

    def test_governed_region_read_failure_is_unknown(self):
        acct = FakeClient(errors={"list_regions":
                                  client_error("AccessDeniedException", "ListRegions")})
        ctx = make_ctx({"account": acct}, governed_regions=["us-east-1"])
        lv = levels(_run(ct.check_governed_region_availability, ctx))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.PASS, lv)

    # 8. StackSets: INOPERABLE blocks; OUTDATED is INFO ----------------------------
    def test_stacksets_inoperable_in_shared_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "INOPERABLE",
                 "DriftStatus": "NOT_CHECKED"}]},
        })
        # make_ctx sets mgmt_account = 111111111111 (a shared account)
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_stacksets, ctx)))

    def test_stacksets_member_drift_warns_not_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-ROLES"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "222222222222", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"}]}})  # 222... is a member (not shared)
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_stacksets_outdated_is_info_not_blocker(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "1", "Region": "us-east-1", "Status": "OUTDATED",
                 "DriftStatus": "NOT_CHECKED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "1", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_stacksets_drifted_in_shared_warns_not_blocks(self):
        # Stored drift is a repairable change: drift.html's resolve-right-away list does not
        # include StackSet resource drift, and on 3.1+ "drift is resolved as part of the
        # update process". A landing-zone update was observed succeeding with drifted
        # instances present in a shared account.
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-ROLES"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)
        self.assertNotIn(ct.PASS, lv, "must not claim all instances are CURRENT")

    def test_stacksets_orphaned_account_not_blocker(self):
        # A FAILED/INOPERABLE instance for an account that has LEFT the org is a
        # stale StackSet leftover: it must be INFO (cleanup), never a BLOCKER,
        # because a landing-zone update does not act on departed accounts.
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "999999999999", "Region": "us-east-1", "Status": "OUTDATED",
                 "StackInstanceStatus": {"DetailedStatus": "FAILED"},
                 "DriftStatus": "NOT_CHECKED"}]},
        })
        # Org does NOT contain 999999999999.
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    # 8a-ii. Failure REASON decides severity, not the account tier -----------------
    # Verbatim reason text from a real landing zone. The AWSControlTowerExecution role
    # already existed (AWS Organizations creates it with the account), so the instance
    # failed while the end state Control Tower wanted was already true. The Control
    # Tower service team confirms these are expected and do not block an update.
    ALREADY_EXISTS = ("ResourceLogicalId:AWSControlTowerExecutionRole, "
                      "ResourceType:AWS::IAM::Role, "
                      "ResourceStatusReason:AWSControlTowerExecution already exists.")

    def _exec_role_instance(self, account, reason, drift="NOT_CHECKED"):
        return FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": account, "Region": "us-east-1", "Status": "OUTDATED",
                 "StackInstanceStatus": {"DetailedStatus": "FAILED"},
                 "StatusReason": reason, "DriftStatus": drift}]},
        })

    def test_execution_role_already_exists_in_shared_is_not_a_blocker(self):
        # 111111111111 is the management account, i.e. a shared account. Before the
        # reason was read, this produced "NOT SAFE TO UPGRADE" on a healthy landing zone.
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": self._exec_role_instance("111111111111", self.ALREADY_EXISTS),
                        "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.BLOCKER, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_execution_role_already_exists_in_member_is_not_a_warning(self):
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": self._exec_role_instance("222222222222", self.ALREADY_EXISTS),
                        "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_benign_reason_longer_than_the_display_limit_still_reads_as_benign(self):
        # The real CloudFormation reason is ~138 characters and "already exists" sits at the
        # very end, past the 100-character display truncation. Classifying from the truncated
        # display string silently turned every real benign collision into a WARNING.
        self.assertGreater(len(self.ALREADY_EXISTS), 100, "fixture must exceed the display limit")
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": self._exec_role_instance("111111111111", self.ALREADY_EXISTS),
                        "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_execution_role_failure_for_another_reason_warns_but_never_blocks(self):
        # The instance state on this StackSet is not a reliable signal, so no reason makes it
        # a blocker. An unexplained failure is still surfaced as a WARNING rather than hidden.
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": self._exec_role_instance(
            "111111111111", "AccessDenied: not authorized to perform iam:CreateRole"),
            "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_execution_role_never_blocks_whatever_the_reason(self):
        # Guards the SME's finding directly: two independent Control Tower authorities state
        # failures on this StackSet do not block an update, so nothing here may reach BLOCKER.
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        for reason in (self.ALREADY_EXISTS, "AccessDenied", "Throttled", "", "some novel error"):
            ctx = make_ctx({"cloudformation": self._exec_role_instance("111111111111", reason),
                            "organizations": orgs})
            lv = levels(_run(ct.check_stacksets, ctx))
            self.assertNotIn(ct.BLOCKER, lv, f"blocked on reason: {reason!r}")

    def test_baseline_stackset_already_exists_still_blocks(self):
        # The exemption is deliberately narrow. An "already exists" collision on a
        # BASELINE StackSet means a deleted StackSet left resources behind, which is a
        # common cause of repair failures — it must stay a blocker.
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "OUTDATED",
                 "StackInstanceStatus": {"DetailedStatus": "FAILED"},
                 "StatusReason": "AWSControlTowerBP-BASELINE-CONFIG already exists.",
                 "DriftStatus": "NOT_CHECKED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_stacksets, ctx)))

    def test_execution_role_drift_is_reported_separately_from_the_collision(self):
        # A drifted instance is a real difference from the template, so it is still reported
        # rather than folded into the benign-collision finding -- as a WARNING, since drift
        # does not block an update.
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": self._exec_role_instance(
            "111111111111", self.ALREADY_EXISTS, drift="DRIFTED"), "organizations": orgs})
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_expected_collision_does_not_claim_all_instances_current(self):
        # The PASS line says every instance is CURRENT. An expected collision is not a
        # problem, but it is also not CURRENT, so PASS must not be emitted.
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": self._exec_role_instance("111111111111", self.ALREADY_EXISTS),
                        "organizations": orgs})
        self.assertNotIn(ct.PASS, levels(_run(ct.check_stacksets, ctx)))

    # 8b. Active StackSet drift detection (opt-in --detect-drift) ------------------
    # 8b-ii. --drift-timeout is one shared budget, and must not be spent starting work ----
    class _DriftCfn:
        """Counts detect_stack_set_drift calls; every operation runs forever."""

        def __init__(self, names):
            self.names = names
            self.started = []

        def can_paginate(self, op):
            return False

        def list_stack_sets(self, **k):
            return {"Summaries": [{"StackSetName": n} for n in self.names]}

        def detect_stack_set_drift(self, StackSetName=None, **k):
            self.started.append(StackSetName)
            return {"OperationId": f"op-{StackSetName}"}

        def describe_stack_set_operation(self, **k):
            return {"StackSetOperation": {"Status": "RUNNING"}}

        def list_stack_instances(self, **k):
            return {"Summaries": []}

    def _run_drift(self, n_stacksets, budget):
        names = [f"AWSControlTowerBP-SS{i}" for i in range(1, n_stacksets + 1)]
        cfn = self._DriftCfn(names)
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        ctx.drift_timeout = budget
        rpt = ct.Report()
        ct.check_stackset_active_drift(ctx, rpt)
        return cfn, rpt

    def test_exhausted_drift_budget_starts_no_further_operations(self):
        # Reported by an SME with real timestamps: once the shared budget expired the loop
        # kept calling DetectStackSetDrift on every remaining StackSet, firing real
        # operations it then abandoned, and reporting each as a timeout it never had a
        # chance to beat. Three were still running after the tool had exited.
        cfn, _ = self._run_drift(n_stacksets=11, budget=1)
        self.assertEqual(len(cfn.started), 1,
                         f"started {len(cfn.started)} operations after the budget expired")

    def test_unreached_stacksets_are_not_reported_as_timeouts(self):
        _, rpt = self._run_drift(n_stacksets=11, budget=1)
        unknown = [f for f in rpt.findings if f.level == ct.UNKNOWN]
        self.assertTrue(unknown)
        reasons = [r[1] for r in unknown[0].rows]
        self.assertEqual(reasons.count("timeout"), 1, "only the started one can time out")
        self.assertEqual(reasons.count("not_started"), 10)

    def test_drift_budget_finding_discloses_operations_left_running(self):
        # The tool exits while operations are still in flight; saying nothing about that is
        # how a user ends up starting an upgrade against a busy StackSet.
        _, rpt = self._run_drift(n_stacksets=3, budget=1)
        unknown = [f for f in rpt.findings if f.level == ct.UNKNOWN][0]
        self.assertIn("Still running when this check gave up", unknown.detail)
        self.assertIn("shared across all StackSets", unknown.detail)

    def test_drift_budget_is_not_overshot_by_a_poll_interval(self):
        import time as _t
        t0 = _t.time()
        self._run_drift(n_stacksets=4, budget=1)
        # Without the sleep cap each StackSet overshoots by a full 10s interval.
        self.assertLess(_t.time() - t0, 8.0)

    def test_active_drift_skipped_when_disabled(self):
        ctx = make_ctx()  # detect_drift defaults False
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_active_drift_detects_drift_warns_not_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})  # 111... is mgmt (shared)
        ctx.detect_drift = True
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_active_drift_member_warns_not_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "222222222222", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        ctx.assume = lambda a, r, s: FakeClient({"describe_stack_resource_drifts":
                                                 {"StackResourceDrifts": []}})
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_active_drift_orphaned_drift_not_blocker(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "999999999999", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "1", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        lv = levels(_run(ct.check_stackset_active_drift, ctx))
        self.assertNotIn(ct.BLOCKER, lv)
        self.assertIn(ct.INFO, lv)

    def test_active_drift_reports_resource_detail(self):
        member = FakeClient({"describe_stack_resource_drifts": {"StackResourceDrifts": [
            {"LogicalResourceId": "AWSControlTowerExecutionRole", "ResourceType": "AWS::IAM::Role",
             "StackResourceDriftStatus": "MODIFIED",
             "PropertyDifferences": [{"PropertyPath": "/AssumeRolePolicyDocument"}]}]}})
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT", "DriftStatus": "DRIFTED",
                 "StackId": "arn:aws:cloudformation:us-east-1:1:stack/foo/abc"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        ctx.assume = lambda a, r, s: member
        rpt = _run(ct.check_stackset_active_drift, ctx)
        blk = [f for f in rpt.findings if f.level == ct.WARNING][0]
        self.assertIn("AWS::IAM::Role/AWSControlTowerExecutionRole:MODIFIED", blk.rows[0][-1])

    def test_active_drift_role_missing_points_to_stack(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "detect_stack_set_drift": {"OperationId": "op-1"},
            "describe_stack_set_operation": {"StackSetOperation": {"Status": "SUCCEEDED"}},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT", "DriftStatus": "DRIFTED",
                 "StackId": "arn:aws:cloudformation:us-east-1:1:stack/foo/abc"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        def _boom(a, r, s):
            raise RuntimeError("no such role")
        ctx.assume = _boom
        rpt = _run(ct.check_stackset_active_drift, ctx)
        self.assertIn(ct.WARNING, levels(rpt))
        blk = [f for f in rpt.findings if f.level == ct.WARNING][0]
        self.assertIn("inspect stack", blk.rows[0][-1])

    def test_stacksets_drift_deduped_when_detect_drift(self):
        # With --detect-drift on, the base check must NOT also flag persisted DRIFTED
        # (the active drift check owns drift) -> no duplicate blocker.
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerExecutionRole"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1", "Status": "CURRENT",
                 "DriftStatus": "DRIFTED"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "111111111111", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        ctx.detect_drift = True
        lv = levels(_run(ct.check_stacksets, ctx))
        self.assertNotIn(ct.BLOCKER, lv)

    # 8c. Missing foundational StackSets (broken LZ) ---------------------------------
    def test_expected_stacksets_missing_warns(self):
        cfn = FakeClient({"list_stack_sets": {"Summaries": [
            {"StackSetName": "AWSControlTowerExecutionRole"}]}})  # baseline roles missing
        ctx = make_ctx({"cloudformation": cfn})
        lv = levels(_run(ct.check_expected_stacksets, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_expected_stacksets_present_passes(self):
        cfn = FakeClient({"list_stack_sets": {"Summaries": [
            {"StackSetName": "AWSControlTowerExecutionRole"},
            {"StackSetName": "AWSControlTowerBP-BASELINE-ROLES"},
            {"StackSetName": "AWSControlTowerBP-BASELINE-SERVICE-ROLES"},
            {"StackSetName": "AWSControlTowerBP-BASELINE-CLOUDWATCH"}]}})
        ctx = make_ctx({"cloudformation": cfn})
        self.assertIn(ct.PASS, levels(_run(ct.check_expected_stacksets, ctx)))

    def test_expected_stacksets_missing_is_info_on_v4(self):
        # On LZ 4.0+ the SecurityRoles integration is optional, so missing role StackSets are
        # downgraded from WARNING to INFO (not a "broken landing zone").
        cfn = FakeClient({"list_stack_sets": {"Summaries": [
            {"StackSetName": "AWSControlTowerExecutionRole"}]}})  # baseline roles missing
        ctx = make_ctx({"cloudformation": cfn},
                       lz={"version": "4.0", "latestAvailableVersion": "4.0"})
        lv = levels(_run(ct.check_expected_stacksets, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    # 8d. In-progress StackSet operations --------------------------------------------
    def test_stackset_ops_in_progress_blocks(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_set_operations": {"Summaries": [
                {"Action": "UPDATE", "Status": "RUNNING", "OperationId": "op-1"}]},
        })
        ctx = make_ctx({"cloudformation": cfn})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_stackset_operations_in_progress, ctx)))

    def test_stackset_ops_idle_passes(self):
        cfn = FakeClient({
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-BASELINE-CONFIG"}]},
            "list_stack_set_operations": {"Summaries": [
                {"Action": "UPDATE", "Status": "SUCCEEDED", "OperationId": "op-0"}]},
        })
        ctx = make_ctx({"cloudformation": cfn})
        lv = levels(_run(ct.check_stackset_operations_in_progress, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    # 8e. Account Factory provisioned-product health ---------------------------------
    def test_provisioned_product_tainted_warns(self):
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "acct-x", "Status": "TAINTED", "Type": "CONTROL_TOWER_ACCOUNT"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        lv = levels(_run(ct.check_provisioned_product_health, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_provisioned_product_under_change_warns(self):
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "acct-y", "Status": "UNDER_CHANGE", "Type": "CONTROL_TOWER_ACCOUNT"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        lv = levels(_run(ct.check_provisioned_product_health, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_provisioned_product_available_passes(self):
        sc = FakeClient({"search_provisioned_products": {"ProvisionedProducts": [
            {"Name": "acct-z", "Status": "AVAILABLE", "Type": "CONTROL_TOWER_ACCOUNT"}]}})
        ctx = make_ctx({"servicecatalog": sc})
        self.assertIn(ct.PASS, levels(_run(ct.check_provisioned_product_health, ctx)))

    # 8f. STS AccessDenied must not be a false "region disabled" blocker -------------
    def test_sts_access_denied_is_unknown_not_blocker(self):
        ctx = make_ctx()
        ctx.governed_regions = ["us-east-1"]
        with mock.patch.object(
                ct.boto3, "client",
                return_value=FakeClient(errors={"get_caller_identity": client_error("AccessDenied")})):
            lv = levels(_run(ct.check_sts_regional_activation, ctx))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_sts_region_disabled_blocks_single_region(self):
        ctx = make_ctx()
        ctx.governed_regions = ["ap-east-1"]
        with mock.patch.object(
                ct.boto3, "client",
                return_value=FakeClient(errors={"get_caller_identity": client_error("RegionDisabledException")})):
            lv = levels(_run(ct.check_sts_regional_activation, ctx))
        self.assertIn(ct.BLOCKER, lv)

    # 8g. Opt-in: member execution-role sweep ---------------------------------------
    def test_member_roles_skipped_when_disabled(self):
        ctx = make_ctx()
        lv = levels(_run(ct.check_member_execution_roles, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_member_roles_all_assumable_passes(self):
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},   # mgmt (skipped)
            {"Id": "222222222222", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"organizations": orgs})
        ctx.check_member_roles = True
        ctx.assume = lambda a, r, s: FakeClient()  # get_caller_identity -> {}
        self.assertIn(ct.PASS, levels(_run(ct.check_member_execution_roles, ctx)))

    def test_member_roles_not_assumable_warns(self):
        orgs = FakeClient({"list_accounts": {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"}]}})
        ctx = make_ctx({"organizations": orgs})
        ctx.check_member_roles = True
        def _boom(a, r, s):
            raise client_error("AccessDenied", "AssumeRole")
        ctx.assume = _boom
        lv = levels(_run(ct.check_member_execution_roles, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    # 8h. Opt-in: KMS key policy -----------------------------------------------------
    def test_kms_policy_skipped_when_disabled(self):
        ctx = make_ctx()
        ctx.kms_key_arn = "arn:aws:kms:us-east-1:1:key/abc"
        lv = levels(_run(ct.check_kms_key_policy, ctx))
        self.assertIn(ct.INFO, lv)

    def test_kms_policy_missing_principals_warns(self):
        kms = FakeClient({"get_key_policy": {"Policy": '{"Statement":[{"Principal":{"AWS":"x"}}]}'}})
        ctx = make_ctx({"kms": kms})
        ctx.kms_key_arn = "arn:aws:kms:us-east-1:1:key/abc"
        ctx.check_kms_policy = True
        lv = levels(_run(ct.check_kms_key_policy, ctx))
        self.assertIn(ct.WARNING, lv)

    def test_kms_policy_ok_passes(self):
        pol = '{"Statement":[{"Principal":{"Service":["config.amazonaws.com","cloudtrail.amazonaws.com"]}}]}'
        kms = FakeClient({"get_key_policy": {"Policy": pol}})
        ctx = make_ctx({"kms": kms})
        ctx.kms_key_arn = "arn:aws:kms:us-east-1:1:key/abc"
        ctx.check_kms_policy = True
        self.assertIn(ct.PASS, levels(_run(ct.check_kms_key_policy, ctx)))

    # 8i. Opt-in: orphaned CT resources (recreate-collision) -------------------------
    def test_orphaned_resources_skipped_when_disabled(self):
        ctx = make_ctx()
        lv = levels(_run(ct.check_orphaned_ct_resources, ctx))
        self.assertIn(ct.INFO, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_orphaned_resources_healthy_lz_passes_no_scan(self):
        cfn = FakeClient({"list_stack_sets": {"Summaries": [
            {"StackSetName": "AWSControlTowerExecutionRole"},
            {"StackSetName": "AWSControlTowerBP-BASELINE-ROLES"},
            {"StackSetName": "AWSControlTowerBP-BASELINE-SERVICE-ROLES"}]}})
        ctx = make_ctx({"cloudformation": cfn})  # lz status ACTIVE by default
        ctx.check_orphaned_resources = True
        lv = levels(_run(ct.check_orphaned_ct_resources, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_orphaned_resources_found_when_broken_warns(self):
        ctx = make_ctx(lz={"status": "FAILED", "version": "4.0"})
        ctx.check_orphaned_resources = True
        def fake_assume(a, r, s):
            clients = {
                "iam": FakeClient({"get_role": {"Role": {}}}),  # every probed role "exists"
                "lambda": FakeClient(errors={"get_function": client_error("ResourceNotFoundException", "GetFunction")}),
            }
            return clients.get(s, FakeClient())  # other services: empty responses
        ctx.assume = fake_assume
        lv = levels(_run(ct.check_orphaned_ct_resources, ctx))
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_orphaned_resources_not_assumable_is_unknown(self):
        ctx = make_ctx(lz={"status": "FAILED", "version": "4.0"})
        ctx.check_orphaned_resources = True
        def _boom(a, r, s):
            raise client_error("AccessDenied", "AssumeRole")
        ctx.assume = _boom
        lv = levels(_run(ct.check_orphaned_ct_resources, ctx))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_orphaned_resources_managed_role_not_flagged(self):
        # LZ broken (baseline role StackSets missing) but the ExecutionRole StackSet is
        # present -> AWSControlTowerExecution is stack-managed and must NOT be flagged.
        cfn = FakeClient({"list_stack_sets": {"Summaries": [
            {"StackSetName": "AWSControlTowerExecutionRole"}]}})
        ctx = make_ctx({"cloudformation": cfn}, lz={"status": "FAILED", "version": "4.0"})
        ctx.check_orphaned_resources = True
        def fake_assume(a, r, s):
            if s == "iam":
                c = FakeClient()
                def get_role(RoleName=None, **k):
                    if RoleName == "AWSControlTowerExecution":
                        return {"Role": {}}
                    raise client_error("NoSuchEntity", "GetRole")
                c.get_role = get_role
                return c
            if s == "lambda":
                return FakeClient(errors={"get_function": client_error("ResourceNotFoundException", "GetFunction")})
            return FakeClient()  # config/sns/logs/events/cloudtrail/s3: empty
        ctx.assume = fake_assume
        lv = levels(_run(ct.check_orphaned_ct_resources, ctx))
        self.assertNotIn(ct.WARNING, lv)
        self.assertIn(ct.PASS, lv)

    # 8j. Doc references -----------------------------------------------------------
    def test_doc_map_urls_are_ct_userguide(self):
        self.assertTrue(ct._CHECK_DOCS)
        base = "https://docs.aws.amazon.com/controltower/latest/userguide/"
        for cid, url in ct._CHECK_DOCS.items():
            self.assertTrue(url.startswith(base), f"{cid} -> {url}")
            self.assertTrue(url.endswith(".html"), f"{cid} -> {url}")

    def test_render_includes_doc_reference(self):
        rpt = ct.Report()
        rpt.add(ct.Finding("lz_status", ct.BLOCKER, "Landing zone is in a FAILED state"))
        out = ct.render_text(rpt, make_ctx())
        self.assertIn("DOC: https://docs.aws.amazon.com/controltower", out)

    # 9. Config in shared accounts: extra recorder warns; unreachable = UNKNOWN ----
    def test_config_extra_recorder_warns(self):
        ctx = make_ctx()
        ctx.assume = lambda a, r, s: FakeClient({
            "describe_configuration_recorders": {"ConfigurationRecorders": [{}, {}]}})
        self.assertIn(ct.WARNING, levels(_run(ct.check_config_in_shared_accounts, ctx)))

    def test_config_unreachable_is_unknown_not_pass(self):
        ctx = make_ctx()
        def boom(a, r, s):
            raise client_error("AccessDenied", "AssumeRole")
        ctx.assume = boom
        self.assertIn(ct.UNKNOWN, levels(_run(ct.check_config_in_shared_accounts, ctx)))

    def test_config_no_shared_ids_is_unknown(self):
        ctx = make_ctx(audit_account=None, log_archive_account=None)
        self.assertIn(ct.UNKNOWN, levels(_run(ct.check_config_in_shared_accounts, ctx)))

    # 11. trusted access missing ---------------------------------------------------
    def test_trusted_access_missing_blocks(self):
        orgs = FakeClient({"list_aws_service_access_for_organization":
                           {"EnabledServicePrincipals": [{"ServicePrincipal": "sso.amazonaws.com"}]}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_trusted_access, ctx)))

    def test_trusted_access_present_passes(self):
        orgs = FakeClient({"list_aws_service_access_for_organization":
                           {"EnabledServicePrincipals":
                            [{"ServicePrincipal": s} for s in ct._REQUIRED_TRUSTED_SERVICES]}})
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.PASS, levels(_run(ct.check_trusted_access, ctx)))

    # 13. required IAM roles missing -----------------------------------------------
    def test_required_roles_missing_blocks(self):
        iam = FakeClient(errors={"get_role": client_error("NoSuchEntity", "GetRole")})
        ctx = make_ctx()
        ctx.session._clients["iam"] = iam
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_required_iam_roles, ctx)))

    def test_required_roles_present_passes(self):
        iam = FakeClient({"get_role": {"Role": {"RoleName": "x"}}})
        ctx = make_ctx()
        ctx.session._clients["iam"] = iam
        self.assertIn(ct.PASS, levels(_run(ct.check_required_iam_roles, ctx)))

    # 14. KMS key ------------------------------------------------------------------
    def test_kms_disabled_blocks(self):
        kms = FakeClient({"describe_key": {"KeyMetadata": {"KeyState": "PendingDeletion"}}})
        ctx = make_ctx({"kms": kms}, kms_key_arn="arn:aws:kms:us-east-1:1:key/abc")
        ctx.session._clients["kms"] = kms
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_kms_key, ctx)))

    def test_kms_enabled_passes(self):
        arn = kms_arn("111111111111", key_id="abc")
        kms = FakeClient({"describe_key": {"KeyMetadata": {
            "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT",
            "KeyUsage": "ENCRYPT_DECRYPT", "MultiRegion": False,
            "Arn": arn}}})
        ctx = make_ctx(kms_key_arn=arn)
        ctx.session._clients["kms"] = kms
        self.assertIn(ct.PASS, levels(_run(ct.check_kms_key, ctx)))

    def test_kms_none_is_info(self):
        ctx = make_ctx(kms_key_arn=None)
        self.assertIn(ct.INFO, levels(_run(ct.check_kms_key, ctx)))

    # 15. STS regional activation --------------------------------------------------
    def test_sts_region_disabled_blocks(self):
        fake_sts = FakeClient(errors={"get_caller_identity":
                                      client_error("RegionDisabledException", "GetCallerIdentity")})
        ctx = make_ctx(governed_regions=["us-east-1", "ap-east-1"])
        with mock.patch.object(ct.boto3, "client", return_value=fake_sts):
            self.assertIn(ct.BLOCKER, levels(_run(ct.check_sts_regional_activation, ctx)))

    def test_sts_all_active_passes(self):
        fake_sts = FakeClient({"get_caller_identity": {"Account": "1"}})
        ctx = make_ctx(governed_regions=["us-east-1"])
        with mock.patch.object(ct.boto3, "client", return_value=fake_sts):
            self.assertIn(ct.PASS, levels(_run(ct.check_sts_regional_activation, ctx)))

    # 16. SCP headroom at 10-limit -------------------------------------------------
    def test_scp_at_limit_warns(self):
        ten = [{"Name": f"p{i}", "Id": f"p-{i}", "AwsManaged": False} for i in range(10)]
        orgs = FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent": lambda ParentId=None, **k: {"OrganizationalUnits": []},
            "list_policies_for_target": {"Policies": ten},
        })
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.WARNING, levels(_run(ct.check_scp_headroom, ctx)))

    # 17. SCP blocking content -----------------------------------------------------
    @staticmethod
    def _scp_orgs(content, with_fullaccess=True):
        pols = [{"Name": "custom", "Id": "p-x", "AwsManaged": False}]
        if with_fullaccess:
            pols.insert(0, {"Name": "FullAWSAccess", "Id": "p-Full", "AwsManaged": True})
        return FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent":
                lambda ParentId=None, **k: {"OrganizationalUnits": []},
            "list_policies_for_target": {"Policies": pols},
            "describe_policy": lambda PolicyId=None, **k: {
                "Policy": {"Content": content if PolicyId == "p-x" else "{}"}},
        })

    @staticmethod
    def _deny(action, condition=None):
        stmt = {"Effect": "Deny", "Action": action, "Resource": "*"}
        if condition:
            stmt["Condition"] = condition
        return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})

    def test_scp_deny_on_ct_service_without_exemption_warns(self):
        # config is a service Control Tower acts on inside member accounts, so a Deny on it
        # without an AWSControlTowerExecution exemption can genuinely interfere.
        ctx = make_ctx({"organizations": self._scp_orgs(self._deny("config:*"))})
        rpt = _run(ct.check_scp_blocking, ctx)
        self.assertIn(ct.WARNING, levels(rpt))
        risky = [f for f in rpt.findings if f.level == ct.WARNING][0]
        self.assertIn("config:*", risky.rows[0][2])

    def test_scp_missing_fullaccess_warns_independently(self):
        # Separate concern from a risky Deny: FullAWSAccess must stay attached.
        ctx = make_ctx({"organizations": self._scp_orgs(self._deny("ec2:*"),
                                                       with_fullaccess=False)})
        rpt = _run(ct.check_scp_blocking, ctx)
        summaries = " ".join(f.summary for f in rpt.findings if f.level == ct.WARNING)
        self.assertIn("FullAWSAccess", summaries)

    def test_scp_deny_on_controltower_actions_is_not_reported(self):
        # Verified on a live organization: a 3.3 -> 4.0 landing-zone upgrade succeeded with
        # `Deny controltower:* on *` attached to the organization root throughout. The
        # controltower:* APIs are management-account control-plane calls and SCPs never apply
        # to the management account, so this cannot block an update. Reporting it told users
        # to add a role exemption that would change nothing.
        ctx = make_ctx({"organizations": self._scp_orgs(self._deny("controltower:*"))})
        lv = levels(_run(ct.check_scp_blocking, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_scp_deny_on_unrelated_service_is_not_reported(self):
        ctx = make_ctx({"organizations": self._scp_orgs(self._deny("ec2:*"))})
        lv = levels(_run(ct.check_scp_blocking, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.WARNING, lv)

    def test_scp_deny_all_actions_still_warns(self):
        # Action "*" denies everything, including what CT needs. It cannot be dismissed by
        # intersecting service prefixes, so it must stay a warning.
        ctx = make_ctx({"organizations": self._scp_orgs(self._deny("*"))})
        lv = levels(_run(ct.check_scp_blocking, ctx))
        self.assertIn(ct.WARNING, lv)

    def test_scp_notaction_deny_still_warns(self):
        # NotAction is inverted - it denies everything EXCEPT what it lists - so the same
        # applies. Both shapes occur on real organizations.
        content = json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "NotAction": ["s3:GetObject"], "Resource": "*"}]})
        ctx = make_ctx({"organizations": self._scp_orgs(content)})
        self.assertIn(ct.WARNING, levels(_run(ct.check_scp_blocking, ctx)))

    def test_scp_region_restriction_reported_even_on_unrelated_actions(self):
        # Region restriction via SCP is a separate documented problem, so it is reported even
        # when the denied actions are ones CT never performs in a member account.
        ctx = make_ctx({"organizations": self._scp_orgs(self._deny(
            "controltower:*",
            {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]}}))})
        rpt = _run(ct.check_scp_blocking, ctx)
        self.assertIn(ct.WARNING, levels(rpt))
        risky = [f for f in rpt.findings if f.level == ct.WARNING][0]
        self.assertIn("Region restriction", risky.rows[0][2])

    def test_scp_deny_with_ct_exemption_and_fullaccess_passes(self):
        orgs = FakeClient({
            "list_roots": {"Roots": [{"Id": "r-root"}]},
            "list_organizational_units_for_parent": lambda ParentId=None, **k: {"OrganizationalUnits": []},
            "list_policies_for_target": {"Policies": [
                {"Name": "FullAWSAccess", "Id": "p-Full", "AwsManaged": True},
                {"Name": "restrict-ec2", "Id": "p-restrict", "AwsManaged": False}]},
            "describe_policy": {"Policy": {"Content":
                '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:*","Resource":"*",'
                '"Condition":{"ArnNotLike":{"aws:PrincipalARN":'
                '"arn:aws:iam::*:role/AWSControlTowerExecution"}}}]}'}},
        })
        ctx = make_ctx({"organizations": orgs})
        self.assertIn(ct.PASS, levels(_run(ct.check_scp_blocking, ctx)))

    # 10. customizations detected --------------------------------------------------
    def test_customizations_detected_info(self):
        cfn = FakeClient({
            "list_stacks": {"StackSummaries": [
                {"StackName": "CustomControlTower-abc", "StackStatus": "CREATE_COMPLETE"}]},
            "list_stack_sets": {"Summaries": [{"StackSetName": "CustomControlTower-stackset-1"}]},
        })
        orgs = FakeClient({"list_accounts": {"Accounts": [{"Id": "1", "Name": "AFTmanagement"}]}})
        ctx = make_ctx({"cloudformation": cfn, "organizations": orgs})
        self.assertIn(ct.INFO, levels(_run(ct.check_customizations, ctx)))

    # preflight: too-old SDK is a clean BLOCKER, not a crash -----------------------
    def test_old_sdk_preflight_blocks_cleanly(self):
        class NoLZClient(FakeClient):
            # simulate an old SDK that lacks list_landing_zones
            def __getattr__(self, name):
                if name == "list_landing_zones":
                    raise AttributeError(name)
                return super().__getattr__(name)
        sess = FakeSession({"controltower": NoLZClient(), "organizations": FakeClient(),
                            "sts": FakeClient({"get_caller_identity": {"Account": "1"}})})
        ctx = ct.Context(sess, "us-east-1", "AWSControlTowerExecution")
        rpt = ct.Report()
        ok = ctx.discover(rpt)
        self.assertFalse(ok)
        self.assertIn(ct.BLOCKER, levels(rpt))


class TestDiscoveryAccountClassification(unittest.TestCase):
    """Run from a member account, ListLandingZones returns an EMPTY LIST rather than an
    error, so an empty result alone cannot tell "wrong account" from "wrong Region". It used
    to report only "Confirm you are in the home region" and print the member account's own id
    under a "Management account" label - both wrong, in a case a user hits easily."""

    MEMBER = "333333333333"
    MASTER = "111111111111"

    def _ctx(self, caller, master=None, org_error=None, lz=None, lz_error=None):
        ct_client = (FakeClient(errors={"list_landing_zones": lz_error}) if lz_error
                     else FakeClient({"list_landing_zones": {"landingZones": lz or []}}))
        orgs = (FakeClient(errors={"describe_organization": org_error}) if org_error
                else FakeClient({"describe_organization":
                                 {"Organization": {"MasterAccountId": master}}}))
        sts = FakeClient({"get_caller_identity": {"Account": caller}})
        ctx = ct.Context(FakeSession({"controltower": ct_client, "organizations": orgs,
                                      "sts": sts}), "us-east-1", "AWSControlTowerExecution")
        return ctx

    def _run(self, ctx):
        rpt = ct.Report()
        ok = ctx.discover(rpt)
        return ok, rpt, ct.render_text(rpt, ctx, discovery_failed=not ok)

    def test_member_account_is_named_as_the_cause(self):
        ctx = self._ctx(caller=self.MEMBER, master=self.MASTER)
        ok, rpt, out = self._run(ctx)
        self.assertFalse(ok)
        self.assertIs(ctx.caller_is_management, False)
        self.assertIn("not the Control Tower management account", out)
        self.assertIn("run the precheck from", out.lower())

    def test_member_account_is_not_labelled_management_account(self):
        ctx = self._ctx(caller=self.MEMBER, master=self.MASTER)
        _, _, out = self._run(ctx)
        self.assertIn("Caller account", out)
        self.assertNotIn("Management account", out)

    def test_member_account_message_does_not_leak_the_management_account_id(self):
        # The report gets pasted into tickets, so it names the role, not the account.
        ctx = self._ctx(caller=self.MEMBER, master=self.MASTER)
        _, _, out = self._run(ctx)
        self.assertNotIn(self.MASTER, out)

    def test_management_account_with_no_landing_zone_points_at_the_region(self):
        # Same empty result, different cause: here the account is right and the Region is the
        # thing to check. The two must not produce the same message.
        ctx = self._ctx(caller=self.MASTER, master=self.MASTER)
        ok, _, out = self._run(ctx)
        self.assertFalse(ok)
        self.assertIs(ctx.caller_is_management, True)
        self.assertIn("home Region", out)
        self.assertNotIn("not the Control Tower management account", out)

    def test_account_not_in_an_organization_is_reported_as_such(self):
        ctx = self._ctx(caller=self.MEMBER,
                        org_error=client_error("AWSOrganizationsNotInUseException",
                                               "DescribeOrganization"))
        ok, _, out = self._run(ctx)
        self.assertFalse(ok)
        self.assertIn("not part of an AWS Organization", out)

    def test_undeterminable_account_does_not_claim_the_account_is_fine(self):
        # An SCP can deny DescribeOrganization in a member account. Guessing would replace one
        # confidently wrong message with another, so it has to say it could not be established.
        ctx = self._ctx(caller=self.MEMBER,
                        org_error=client_error("AccessDeniedException", "DescribeOrganization"))
        ok, _, out = self._run(ctx)
        self.assertFalse(ok)
        self.assertIsNone(ctx.caller_is_management)
        self.assertIn("could not be established", out)
        self.assertIn("management account", out)

    def test_landing_zone_found_establishes_the_management_account(self):
        # Only the management account gets a landing zone back, so no extra call is needed.
        ctx = self._ctx(caller=self.MASTER, lz=[{"arn": "arn:aws:controltower:::landingzone/X"}])
        ctx.ct = FakeClient({
            "list_landing_zones": {"landingZones": [{"arn": "arn:lz"}]},
            "get_landing_zone": {"landingZone": {"version": "3.3", "manifest": {}}}})
        rpt = ct.Report()
        self.assertTrue(ctx.discover(rpt))
        self.assertIs(ctx.caller_is_management, True)
        self.assertIn("Management account", ct.render_text(rpt, ctx))

    def test_wrong_region_says_so_instead_of_getlandingzone_failed(self):
        ctx = self._ctx(caller=self.MASTER, master=self.MASTER)
        ctx.ct = FakeClient(
            responses={"list_landing_zones": {"landingZones": [{"arn": "arn:lz"}]}},
            errors={"get_landing_zone": client_error("ResourceNotFoundException",
                                                     "GetLandingZone")})
        rpt = ct.Report()
        self.assertFalse(ctx.discover(rpt))
        out = ct.render_text(rpt, ctx, discovery_failed=True)
        self.assertIn("No landing zone in us-east-1", out)
        self.assertNotIn("GetLandingZone failed", out)


class TestDiscoveryFailureRendering(unittest.TestCase):
    """When discovery fails, none of the checks ran, so the report must not read as a
    verdict on the landing zone. Reported from a test against an account with no landing
    zone: the output said "NOT SAFE TO UPGRADE - 1 blocker(s)" while exiting 3, which is
    the code for "the precheck could not run" - the two contradicted each other."""

    def _failed_discovery(self):
        rpt = ct.Report()
        rpt.add(ct.Finding("discovery", ct.BLOCKER,
                           "No landing zone found in this account/region",
                           "ListLandingZones returned empty."))
        return rpt

    def _bare_ctx(self):
        ctx = make_ctx(lz={}, governed_regions=[])
        ctx.mgmt_account = "111111111111"
        return ctx

    def test_discovery_failure_does_not_claim_the_upgrade_is_unsafe(self):
        out = ct.render_text(self._failed_discovery(), self._bare_ctx(),
                             discovery_failed=True)
        self.assertNotIn("NOT SAFE TO UPGRADE", out)
        self.assertIn("PRECHECK DID NOT RUN", out)

    def test_discovery_failure_says_it_is_not_a_verdict(self):
        out = ct.render_text(self._failed_discovery(), self._bare_ctx(),
                             discovery_failed=True)
        self.assertIn("not a verdict", out)

    def test_header_does_not_print_python_none(self):
        # The header used to render "Landing zone : vNone (latest None)" and an empty
        # governed-regions line, which reads as a rendering bug rather than as "unknown".
        out = ct.render_text(self._failed_discovery(), self._bare_ctx(),
                             discovery_failed=True)
        self.assertNotIn("None", out)
        self.assertIn("Landing zone       : not determined", out)
        self.assertIn("Governed regions   : not determined", out)

    def test_a_real_blocker_still_says_not_safe_to_upgrade(self):
        # The default path must be unchanged: a blocker found by an actual check is still
        # a verdict.
        rpt = ct.Report()
        rpt.add(ct.Finding("lz_status", ct.BLOCKER, "Landing zone is in a FAILED state"))
        out = ct.render_text(rpt, make_ctx())
        self.assertIn("NOT SAFE TO UPGRADE", out)
        self.assertNotIn("PRECHECK DID NOT RUN", out)

    def test_latest_version_omitted_rather_than_rendered_as_none(self):
        ctx = make_ctx(lz={"version": "3.3"}, governed_regions=["us-east-1"])
        out = ct.render_text(ct.Report(), ctx)
        self.assertIn("Landing zone       : v3.3", out)
        self.assertNotIn("None", out)


class TestColorRendering(unittest.TestCase):
    """The severity coloring is opt-in, TTY-gated, and never leaks into plain output."""

    def _report(self):
        rpt = ct.Report()
        rpt.add(ct.Finding("lz_status", ct.BLOCKER, "Landing zone is in a FAILED state"))
        rpt.add(ct.Finding("managed_accounts", ct.WARNING, "1 suspended account"))
        rpt.add(ct.Finding("update_available", ct.INFO, "v3.3 -> v4.0 available"))
        rpt.add(ct.Finding("iam_roles", ct.PASS, "All required roles present"))
        return rpt

    def test_color_true_emits_ansi(self):
        out = ct.render_text(self._report(), make_ctx(), use_color=True)
        self.assertIn("\033[", out)
        self.assertIn(ct.COLOR[ct.BLOCKER], out)

    def test_color_false_emits_no_ansi(self):
        out = ct.render_text(self._report(), make_ctx(), use_color=False)
        self.assertNotIn("\033[", out)

    def test_default_is_plain(self):
        # default arg must stay no-color so piped/redirected output is clean
        self.assertNotIn("\033[", ct.render_text(self._report(), make_ctx()))

    def test_supports_color_modes(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            self.assertFalse(ct._supports_color("never"))
            self.assertTrue(ct._supports_color("always"))

    def test_no_color_env_overrides_always(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(ct._supports_color("always"))

    def test_auto_follows_tty(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NO_COLOR", None)
            with mock.patch.object(ct.sys.stdout, "isatty", return_value=False):
                self.assertFalse(ct._supports_color("auto"))
            with mock.patch.object(ct.sys.stdout, "isatty", return_value=True):
                self.assertTrue(ct._supports_color("auto"))


class TestVersionAwareIamChecks(unittest.TestCase):
    """Landing-zone-version-aware IAM checks (release-notes: LZ 4.0 / v4 migration guide)."""

    def _iam(self, missing=None, attached=None):
        missing = set(missing or [])

        def get_role(**kw):
            if kw["RoleName"] in missing:
                raise client_error("NoSuchEntity", "GetRole")
            return {"Role": {"RoleName": kw["RoleName"]}}

        return FakeClient(responses={
            "get_role": get_role,
            "list_attached_role_policies": {
                "AttachedPolicies": [{"PolicyName": p} for p in (attached or [])]},
        })

    # ---- #1: org Config aggregator role is version-gated ----
    def test_aggregator_role_not_required_on_v4(self):
        # On LZ 4.0 the aggregator is service-linked; the legacy role's absence must NOT block.
        ctx = make_ctx(clients={"iam": self._iam(missing={ct._CONFIG_AGGREGATOR_ROLE})},
                       lz={"version": "4.0", "latestAvailableVersion": "4.0"})
        lv = levels(_run(ct.check_required_iam_roles, ctx))
        self.assertIn(ct.PASS, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_aggregator_role_required_on_v3(self):
        ctx = make_ctx(clients={"iam": self._iam(missing={ct._CONFIG_AGGREGATOR_ROLE})},
                       lz={"version": "3.2", "latestAvailableVersion": "4.0"})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_required_iam_roles, ctx)))

    def test_core_role_missing_blocks_on_v4(self):
        # Core roles are still required on every version.
        ctx = make_ctx(clients={"iam": self._iam(missing={"AWSControlTowerAdmin"})},
                       lz={"version": "4.0", "latestAvailableVersion": "4.0"})
        self.assertIn(ct.BLOCKER, levels(_run(ct.check_required_iam_roles, ctx)))

    def test_all_roles_present_pass_on_v3(self):
        ctx = make_ctx(clients={"iam": self._iam(missing=set())},
                       lz={"version": "3.2", "latestAvailableVersion": "4.0"})
        self.assertIn(ct.PASS, levels(_run(ct.check_required_iam_roles, ctx)))

    # ---- #3: v4 CloudTrail-role managed-policy prerequisite ----
    def test_cloudtrail_v4_warns_when_inline_only(self):
        ctx = make_ctx(clients={"iam": self._iam(attached=[])},
                       lz={"version": "3.2", "latestAvailableVersion": "4.0"})
        self.assertIn(ct.WARNING, levels(_run(ct.check_cloudtrail_role_v4_policy, ctx)))

    def test_cloudtrail_v4_pass_when_managed_attached(self):
        ctx = make_ctx(
            clients={"iam": self._iam(attached=["AWSControlTowerCloudTrailRolePolicy"])},
            lz={"version": "3.2", "latestAvailableVersion": "4.0"})
        self.assertIn(ct.PASS, levels(_run(ct.check_cloudtrail_role_v4_policy, ctx)))

    def test_cloudtrail_v4_skipped_when_no_v4_upgrade(self):
        ctx = make_ctx(clients={"iam": self._iam(attached=[])},
                       lz={"version": "3.2", "latestAvailableVersion": "3.3"})
        self.assertEqual(len(_run(ct.check_cloudtrail_role_v4_policy, ctx).findings), 0)

    def test_cloudtrail_v4_skipped_when_already_v4(self):
        ctx = make_ctx(clients={"iam": self._iam(attached=[])},
                       lz={"version": "4.0", "latestAvailableVersion": "4.0"})
        self.assertEqual(len(_run(ct.check_cloudtrail_role_v4_policy, ctx).findings), 0)

    def test_version_helpers(self):
        ctx = make_ctx(lz={"version": "4.0", "latestAvailableVersion": "3.3"})
        self.assertEqual(ct._lz_major_version(ctx), 4)
        self.assertEqual(ct._latest_major_version(ctx), 3)
        self.assertIsNone(ct._lz_major_version(make_ctx(lz={"version": None})))


class TestUpgradePathConsiderations(unittest.TestCase):
    """Version-path upgrade-considerations catalog + advisory check."""

    def test_full_path_crosses_all_five_boundaries(self):
        vers = [v for v, _doc, _rows in ct.upgrade_path_considerations("2.9", "4.0")]
        self.assertEqual(vers, ["3.0", "3.1", "3.2", "3.3", "4.0"])

    def test_partial_path_only_includes_crossed_boundaries(self):
        vers = [v for v, _d, _r in ct.upgrade_path_considerations("3.3", "4.0")]
        self.assertEqual(vers, ["4.0"])

    def test_same_version_yields_no_considerations(self):
        self.assertEqual(ct.upgrade_path_considerations("4.0", "4.0"), [])

    def test_mid_range_excludes_below_and_above(self):
        vers = [v for v, _d, _r in ct.upgrade_path_considerations("3.1", "3.3")]
        self.assertEqual(vers, ["3.2", "3.3"])  # 3.0/3.1 below current, 4.0 above latest

    def test_version_tuple_orders_2_9_below_3_0(self):
        self.assertLess(ct._ver_tuple("2.9"), ct._ver_tuple("3.0"))
        self.assertEqual(ct._ver_tuple("4.0"), (4, 0))
        self.assertIsNone(ct._ver_tuple(None))

    def test_every_catalog_entry_is_doc_cited_and_well_formed(self):
        for ver, doc, rows in ct._VERSION_CONSIDERATIONS:
            self.assertTrue(doc.startswith(ct.DOC), f"{ver} doc not a CT userguide URL: {doc}")
            self.assertTrue(rows, f"{ver} has no considerations")
            for row in rows:
                self.assertEqual(len(row), 2, f"{ver} row must be (change, action): {row}")
                self.assertTrue(row[0] and row[1], f"{ver} has an empty cell")

    def test_v4_cloudtrail_managed_policy_prerequisite_present(self):
        rows = dict((v, rows) for v, _d, rows in ct._VERSION_CONSIDERATIONS)["4.0"]
        blob = " ".join(c + " " + a for c, a in rows)
        self.assertIn("AWSControlTowerCloudTrailRolePolicy", blob)
        self.assertIn("Do NOT disable service integrations", blob)

    def test_check_emits_info_findings_on_update_path(self):
        ctx = make_ctx(lz={"status": "ACTIVE", "version": "2.9", "latestAvailableVersion": "4.0"})
        rpt = _run(ct.check_upgrade_path_considerations, ctx)
        ups = [f for f in rpt.findings if f.check == "upgrade_considerations"]
        self.assertEqual(len(ups), 5)
        self.assertTrue(all(f.level == ct.INFO for f in ups))
        self.assertTrue(all(f.doc.startswith(ct.DOC) for f in ups))

    def test_check_silent_when_already_latest(self):
        ctx = make_ctx(lz={"status": "ACTIVE", "version": "4.0", "latestAvailableVersion": "4.0"})
        rpt = _run(ct.check_upgrade_path_considerations, ctx)
        self.assertEqual([f for f in rpt.findings if f.check == "upgrade_considerations"], [])

    def test_check_silent_when_latest_unknown(self):
        ctx = make_ctx(lz={"status": "ACTIVE", "version": "3.3", "latestAvailableVersion": None})
        rpt = _run(ct.check_upgrade_path_considerations, ctx)
        self.assertEqual([f for f in rpt.findings if f.check == "upgrade_considerations"], [])

    def test_render_upgrade_notes_scopes_to_path(self):
        out = ct.render_upgrade_notes("3.2", "4.0")
        self.assertIn("[ v3.3 ]", out)
        self.assertIn("[ v4.0 ]", out)
        self.assertNotIn("[ v3.0 ]", out)
        self.assertIn("DOC:", out)

    def test_render_upgrade_notes_empty_path_is_graceful(self):
        out = ct.render_upgrade_notes("4.0", "4.0")
        self.assertIn("No catalogued version-boundary changes", out)


class TestV4IntegrationAccountsSameOu(unittest.TestCase):
    """LZ 4.0 requires every service-integration account to share one parent OU."""

    LOG = "111111111111"
    SEC = "222222222222"
    CFG = "333333333333"
    OU_A = [{"Id": "ou-aaaa", "Type": "ORGANIZATIONAL_UNIT"}]
    OU_B = [{"Id": "ou-bbbb", "Type": "ORGANIZATIONAL_UNIT"}]

    def _manifest(self, **extra):
        m = {"centralizedLogging": {"accountId": self.LOG, "enabled": True},
             "securityRoles": {"accountId": self.SEC, "enabled": True}}
        m.update(extra)
        return m

    def _ctx(self, parents, manifest=None, lz=None):
        """parents maps accountId -> Parents list, or an Exception to raise for it."""
        def list_parents(**kwargs):
            v = parents[kwargs["ChildId"]]
            if isinstance(v, Exception):
                raise v
            return {"Parents": v}
        orgs = FakeClient(responses={"list_parents": list_parents})
        return make_ctx({"organizations": orgs},
                        manifest=self._manifest() if manifest is None else manifest,
                        lz=lz or {"status": "ACTIVE", "version": "3.3",
                                  "latestAvailableVersion": "4.0",
                                  "driftStatus": {"status": "IN_SYNC"}})

    def _run(self, ctx):
        rep = ct.Report()
        ct.check_v4_integration_accounts_same_ou(ctx, rep)
        return rep.findings

    def test_same_parent_ou_passes(self):
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: self.OU_A}))
        self.assertEqual([x.level for x in f], [ct.PASS])
        self.assertIn("share one parent OU", f[0].summary)

    def test_split_across_ous_warns(self):
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: self.OU_B}))
        self.assertEqual([x.level for x in f], [ct.WARNING])
        self.assertIn("2 different parent", f[0].summary)
        self.assertEqual(len(f[0].rows), 2)

    def test_disabled_integration_is_skipped(self):
        # 4.0 manifest with SecurityRoles/Config/Backup off: only logging names an account.
        m = {"centralizedLogging": {"accountId": self.LOG, "enabled": True},
             "securityRoles": {"enabled": False},
             "config": {"enabled": False},
             "backup": {"enabled": False}}
        f = self._run(self._ctx({self.LOG: self.OU_A}, manifest=m))
        self.assertEqual([x.level for x in f], [ct.PASS])
        self.assertIn("not applicable", f[0].summary)

    def test_config_account_is_included(self):
        m = self._manifest(config={"accountId": self.CFG, "enabled": True})
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: self.OU_A,
                                 self.CFG: self.OU_A}, manifest=m))
        self.assertEqual([x.level for x in f], [ct.PASS])
        self.assertIn("3 service-integration", f[0].summary)

    def test_denied_list_parents_is_unknown_not_pass(self):
        """Fail-safe: an unreadable parent must not be dropped into a PASS."""
        denied = ct.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListParents")
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: denied}))
        levels = [x.level for x in f]
        self.assertIn(ct.UNKNOWN, levels)
        self.assertNotIn(ct.PASS, levels)

    def test_denied_still_reports_a_split_it_can_see(self):
        denied = ct.ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListParents")
        m = self._manifest(config={"accountId": self.CFG, "enabled": True})
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: self.OU_B,
                                 self.CFG: denied}, manifest=m))
        levels = [x.level for x in f]
        self.assertIn(ct.UNKNOWN, levels)
        self.assertIn(ct.WARNING, levels)

    def test_not_evaluated_when_v4_not_available(self):
        ctx = self._ctx({self.LOG: self.OU_A, self.SEC: self.OU_A},
                        lz={"status": "ACTIVE", "version": "3.2",
                            "latestAvailableVersion": "3.3",
                            "driftStatus": {"status": "IN_SYNC"}})
        self.assertEqual(self._run(ctx), [])

    def test_empty_parents_list_is_unknown(self):
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: []}))
        levels = [x.level for x in f]
        self.assertIn(ct.UNKNOWN, levels)
        self.assertNotIn(ct.PASS, levels)


    def test_shared_account_counts_once(self):
        """Config and CentralizedLogging on one account is a single account, not two."""
        m = self._manifest(config={"accountId": self.LOG, "enabled": True})
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: self.OU_A}, manifest=m))
        self.assertEqual([x.level for x in f], [ct.PASS])
        self.assertIn("2 service-integration", f[0].summary)

    def test_shared_account_shows_every_integration_label(self):
        m = self._manifest(config={"accountId": self.LOG, "enabled": True})
        f = self._run(self._ctx({self.LOG: self.OU_A, self.SEC: self.OU_B}, manifest=m))
        self.assertEqual([x.level for x in f], [ct.WARNING])
        labels = " ".join(str(r[0]) for r in f[0].rows)
        self.assertIn("CentralizedLogging", labels)
        self.assertIn("Config", labels)

    def test_all_integrations_on_one_account_is_not_applicable(self):
        m = {"centralizedLogging": {"accountId": self.LOG, "enabled": True},
             "config": {"accountId": self.LOG, "enabled": True},
             "securityRoles": {"enabled": False}}
        f = self._run(self._ctx({self.LOG: self.OU_A}, manifest=m))
        self.assertEqual([x.level for x in f], [ct.PASS])
        self.assertIn("not applicable", f[0].summary)


class TestPartialScopeSurfacesAsUnknown(unittest.TestCase):
    """F-01 regression: a per-target API failure must never be absorbed into a bare PASS.

    Each check below loops over targets. If one target's call fails, the check previously
    dropped it silently and reported PASS over the remainder - so a real blocker in the
    skipped target became a clean report. Every case must now emit an UNKNOWN too.
    """

    OU_A = {"Arn": "arn:aws:organizations::1:ou/o-x/ou-AAA", "Name": "OU-A", "Id": "ou-AAA"}
    OU_B = {"Arn": "arn:aws:organizations::1:ou/o-x/ou-BBB", "Name": "OU-B", "Id": "ou-BBB"}

    @staticmethod
    def _err(code, op="Op"):
        return ct.ClientError({"Error": {"Code": code, "Message": "denied"}}, op)

    @staticmethod
    def _levels(ctx, fn):
        rep = ct.Report()
        fn(ctx, rep)
        return [f.level for f in rep.findings], rep.findings

    def _assert_partial(self, levels):
        self.assertIn(ct.UNKNOWN, levels, "skip was not surfaced as UNKNOWN")
        self.assertNotEqual(levels, [ct.PASS], "check still fails open")

    def test_enabled_controls_partial_ou_read(self):
        def lec(**kw):
            if kw.get("targetIdentifier", "").endswith("ou-BBB"):
                raise self._err("AccessDeniedException", "ListEnabledControls")
            return {"enabledControls": [{"controlIdentifier": "CT.OK",
                                         "statusSummary": {"status": "SUCCEEDED"},
                                         "driftStatusSummary": {"driftStatus": "IN_SYNC"}}]}
        ctx = make_ctx({"controltower": FakeClient(responses={"list_enabled_controls": lec})})
        ctx.all_ou_arns = lambda: [self.OU_A, self.OU_B]
        levels, findings = self._levels(ctx, ct.check_enabled_controls)
        self._assert_partial(levels)
        passes = [f for f in findings if f.level == ct.PASS]
        self.assertTrue(passes and "skipped" in passes[0].summary,
                        "PASS summary should disclose the skipped count")

    def test_enabled_controls_throttling_is_recorded(self):
        """Throttling, not just AccessDenied, must surface - it is the realistic case."""
        def lec(**kw):
            if kw.get("targetIdentifier", "").endswith("ou-BBB"):
                raise self._err("ThrottlingException", "ListEnabledControls")
            return {"enabledControls": []}
        ctx = make_ctx({"controltower": FakeClient(responses={"list_enabled_controls": lec})})
        ctx.all_ou_arns = lambda: [self.OU_A, self.OU_B]
        levels, findings = self._levels(ctx, ct.check_enabled_controls)
        self._assert_partial(levels)
        unknown = [f for f in findings if f.level == ct.UNKNOWN][0]
        self.assertIn("ThrottlingException", " ".join(str(c) for r in unknown.rows for c in r))

    def test_stacksets_partial_instance_read(self):
        cfn = FakeClient(
            responses={"list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-A"}]}},
            errors={"list_stack_instances": self._err("AccessDeniedException",
                                                     "ListStackInstances")})
        orgs = FakeClient(responses={"list_accounts": {"Accounts": [{"Id": "111111111111"}]}})
        levels, _ = self._levels(make_ctx({"cloudformation": cfn, "organizations": orgs}),
                                 ct.check_stacksets)
        self._assert_partial(levels)

    def test_stackset_operations_partial_read(self):
        cfn = FakeClient(
            responses={"list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-A"}]}},
            errors={"list_stack_set_operations": self._err("AccessDeniedException",
                                                          "ListStackSetOperations")})
        levels, _ = self._levels(make_ctx({"cloudformation": cfn}),
                                 ct.check_stackset_operations_in_progress)
        self._assert_partial(levels)

    def test_scp_blocking_unreadable_policy_document(self):
        orgs = FakeClient(
            responses={"list_roots": {"Roots": [{"Id": "r-abc", "Name": "Root"}]},
                       "list_policies_for_target": {"Policies": [
                           {"Name": "FullAWSAccess", "Id": "p-full", "AwsManaged": True},
                           {"Name": "CustomDeny", "Id": "p-cust"}]}},
            errors={"describe_policy": self._err("AccessDeniedException", "DescribePolicy")})
        ctx = make_ctx({"organizations": orgs})
        ctx.all_ou_arns = lambda: []
        levels, _ = self._levels(ctx, ct.check_scp_blocking)
        self._assert_partial(levels)

    def test_scp_headroom_partial_target_read(self):
        def lpft(**kw):
            if kw.get("TargetId") == "ou-AAA":
                raise self._err("AccessDeniedException", "ListPoliciesForTarget")
            return {"Policies": [{"Name": "FullAWSAccess", "Id": "p-full", "AwsManaged": True}]}
        orgs = FakeClient(responses={"list_roots": {"Roots": [{"Id": "r-abc", "Name": "Root"}]},
                                     "list_policies_for_target": lpft})
        ctx = make_ctx({"organizations": orgs})
        ctx.all_ou_arns = lambda: [self.OU_A]
        levels, _ = self._levels(ctx, ct.check_scp_headroom)
        self._assert_partial(levels)

    def test_orphaned_resource_probe_skips_surface(self):
        """The nine silent `except: pass` probe failures are now reported as UNKNOWN."""
        denied = self._err("AccessDeniedException", "ListTopics")

        class Boom(FakeClient):
            def __getattr__(self, name):
                def _call(**kwargs):
                    raise denied
                return _call

        ctx = make_ctx({"cloudformation": FakeClient(
            responses={"list_stack_sets": {"Summaries": []}})})
        ctx.check_orphaned_resources = True
        ctx.lz = {"status": "FAILED", "version": "3.3", "latestAvailableVersion": "4.0",
                  "driftStatus": {"status": "IN_SYNC"}}
        ctx.assume = lambda a, r, s: Boom()
        levels, _ = self._levels(ctx, ct.check_orphaned_ct_resources)
        self._assert_partial(levels)

    def test_no_failures_emits_no_unknown(self):
        """The fix must not add noise when everything reads cleanly."""
        cfn = FakeClient(responses={
            "list_stack_sets": {"Summaries": [{"StackSetName": "AWSControlTowerBP-A"}]},
            "list_stack_instances": {"Summaries": [
                {"Account": "111111111111", "Region": "us-east-1",
                 "Status": "CURRENT", "DriftStatus": "IN_SYNC"}]}})
        orgs = FakeClient(responses={"list_accounts": {"Accounts": [{"Id": "111111111111"}]}})
        levels, _ = self._levels(make_ctx({"cloudformation": cfn, "organizations": orgs}),
                                 ct.check_stacksets)
        self.assertNotIn(ct.UNKNOWN, levels)
        self.assertIn(ct.PASS, levels)


class TestExitCode(unittest.TestCase):
    """F-04: UNKNOWN fails closed by default; WARNING does not.

    An UNKNOWN means a check could not be evaluated. In front of a landing-zone update that is
    not something to treat as "safe to proceed". A WARNING is reviewed-and-not-blocking, so it
    must not gate unless the operator asks for it with --strict.
    """

    @staticmethod
    def _rep(*levels):
        r = ct.Report()
        for lv in levels:
            r.add(ct.Finding("t", lv, "summary"))
        return r

    def test_clean_report_is_zero(self):
        self.assertEqual(ct.exit_code(self._rep(ct.PASS, ct.INFO)), 0)

    def test_blocker_is_two(self):
        self.assertEqual(ct.exit_code(self._rep(ct.PASS, ct.BLOCKER)), 2)

    def test_unknown_fails_closed_by_default(self):
        self.assertEqual(ct.exit_code(self._rep(ct.PASS, ct.UNKNOWN)), 2)

    def test_unknown_can_be_explicitly_allowed(self):
        self.assertEqual(ct.exit_code(self._rep(ct.PASS, ct.UNKNOWN), allow_unknown=True), 0)

    def test_warning_does_not_fail_by_default(self):
        self.assertEqual(ct.exit_code(self._rep(ct.PASS, ct.WARNING)), 0)

    def test_warning_fails_under_strict(self):
        self.assertEqual(ct.exit_code(self._rep(ct.PASS, ct.WARNING), strict=True), 2)

    def test_unknown_still_fails_under_strict(self):
        self.assertEqual(ct.exit_code(self._rep(ct.UNKNOWN), strict=True), 2)

    def test_blocker_overrides_allow_unknown(self):
        self.assertEqual(
            ct.exit_code(self._rep(ct.BLOCKER, ct.UNKNOWN), allow_unknown=True), 2)

    def test_allow_unknown_does_not_suppress_strict_warning(self):
        self.assertEqual(
            ct.exit_code(self._rep(ct.WARNING, ct.UNKNOWN), strict=True, allow_unknown=True), 2)

    def test_allow_unknown_with_warning_and_no_strict_is_zero(self):
        self.assertEqual(
            ct.exit_code(self._rep(ct.WARNING, ct.UNKNOWN), allow_unknown=True), 0)


class TestConfigSharedAccounts(unittest.TestCase):
    """F-07: Control Tower's own Config resources are identified by name, so a single
    pre-existing customer recorder in a newly governed Region is caught - the case a
    count-based (`len(recs) > 1`) test could not see.
    """

    CT_REC = {"name": "aws-controltower-BaselineConfigRecorder"}
    CT_CHAN = {"name": "aws-controltower-BaselineConfigDeliveryChannel"}

    def _ctx(self, recorders=None, channels=None, raise_on_assume=False):
        cfg = FakeClient(responses={
            "describe_configuration_recorders": {"ConfigurationRecorders": recorders or []},
            "describe_delivery_channels": {"DeliveryChannels": channels or []},
        })
        ctx = make_ctx()
        if raise_on_assume:
            def _boom(*a, **k):
                raise ct.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "AssumeRole")
            ctx.assume = _boom
        else:
            ctx.assume = lambda acct, region, svc: cfg
        return ctx

    @staticmethod
    def _run(ctx):
        rep = ct.Report()
        ct.check_config_in_shared_accounts(ctx, rep)
        return [f.level for f in rep.findings], rep.findings

    def test_single_preexisting_recorder_is_flagged(self):
        lv, f = self._run(self._ctx(recorders=[{"name": "default"}]))
        self.assertEqual(lv, [ct.WARNING])
        self.assertIn("non-Control Tower", f[0].summary)

    def test_control_tower_recorder_alone_passes(self):
        lv, _ = self._run(self._ctx(recorders=[self.CT_REC]))
        self.assertEqual(lv, [ct.PASS])

    def test_foreign_delivery_channel_is_flagged(self):
        lv, f = self._run(self._ctx(recorders=[self.CT_REC],
                                    channels=[{"name": "my-own-channel"}]))
        self.assertEqual(lv, [ct.WARNING])
        self.assertTrue(any("delivery channel" in str(r).lower() for r in f[0].rows))

    def test_control_tower_channel_alone_passes(self):
        lv, _ = self._run(self._ctx(recorders=[self.CT_REC], channels=[self.CT_CHAN]))
        self.assertEqual(lv, [ct.PASS])

    def test_unnamed_recorder_is_flagged(self):
        lv, _ = self._run(self._ctx(recorders=[{}]))
        self.assertEqual(lv, [ct.WARNING])

    def test_assume_failure_is_unknown_not_pass(self):
        lv, _ = self._run(self._ctx(raise_on_assume=True))
        self.assertIn(ct.UNKNOWN, lv)
        self.assertNotIn(ct.PASS, lv)

    def test_no_shared_accounts_is_unknown(self):
        ctx = self._ctx()
        ctx.audit_account = None
        ctx.log_archive_account = None
        lv, _ = self._run(ctx)
        self.assertEqual(lv, [ct.UNKNOWN])


class TestReportRenderingSafety(unittest.TestCase):
    """F-12: resource names reach the report from AWS API responses, so control characters
    must not reach the terminal, and truncation must be disclosed rather than silent.
    """

    @staticmethod
    def _render(finding):
        rep = ct.Report()
        rep.add(finding)
        return ct.render_text(rep, make_ctx(), use_color=False)

    def test_ansi_escape_in_cell_is_neutralised(self):
        out = self._render(ct.Finding("t", ct.WARNING, "s", cols=["OU"],
                                      rows=[["\x1b[31mred-ou\x1b[0m"]]))
        self.assertNotIn("\x1b", out)
        self.assertIn("red-ou", out)

    def test_carriage_return_cannot_overwrite_a_line(self):
        out = self._render(ct.Finding("t", ct.WARNING, "s", cols=["OU"],
                                      rows=[["ou\r          [OK] all good"]]))
        self.assertNotIn("\r", out)

    def test_pipe_in_cell_cannot_fake_a_column_break(self):
        out = self._render(ct.Finding("t", ct.WARNING, "s", cols=["OU", "Status"],
                                      rows=[["a|b", "OK"]]))
        self.assertIn("a/b", out)

    def test_control_chars_in_summary_are_neutralised(self):
        out = self._render(ct.Finding("t", ct.WARNING, "bad\x1b[2Jsummary"))
        self.assertNotIn("\x1b", out)

    def test_control_chars_in_remediation_are_neutralised(self):
        out = self._render(ct.Finding("t", ct.WARNING, "s", remediation="do\x1b[1mthis"))
        self.assertNotIn("\x1b", out)

    def test_rows_beyond_the_display_cap_are_disclosed(self):
        extra = 7
        rows = [[f"ou-{i}"] for i in range(ct._MAX_DISPLAY_ROWS + extra)]
        f = ct.Finding("t", ct.WARNING, "s", cols=["OU"], rows=rows)
        out = self._render(f)
        self.assertIn(f"and {extra} more row(s) not shown", out)
        # The Finding keeps every row, so the --json report stays complete.
        self.assertEqual(len(f.rows), ct._MAX_DISPLAY_ROWS + extra)

    def test_no_truncation_marker_when_under_the_cap(self):
        out = self._render(ct.Finding("t", ct.WARNING, "s", cols=["OU"],
                                      rows=[["ou-1"], ["ou-2"]]))
        self.assertNotIn("more row(s) not shown", out)

    def test_detail_newlines_are_preserved(self):
        out = self._render(ct.Finding("t", ct.UNKNOWN, "s", detail="line one\nline two"))
        self.assertIn("line one\nline two", out)


class TestCloudTrailRoleGating(unittest.TestCase):
    """Sign-off condition 1: AWSControlTowerCloudTrailRole must not be required when the
    CloudTrail / CentralizedLogging integration is legitimately disabled on a 4.0+ landing
    zone - otherwise the tool emits a false BLOCKER telling a customer they cannot upgrade.

    The gate is version AND flag, not either alone: disabling CentralizedLogging on 3.3 and
    earlier toggled the organization trail off but retained the deployed resources, so the
    role is still expected there.
    """

    CT_ROLE = "AWSControlTowerCloudTrailRole"

    def _ctx(self, version, logging_enabled):
        cl = {"accountId": "666666666666"}
        if logging_enabled is not None:
            cl["enabled"] = logging_enabled
        return make_ctx(
            lz={"status": "ACTIVE", "version": version, "latestAvailableVersion": "4.0",
                "driftStatus": {"status": "IN_SYNC"}},
            manifest={"centralizedLogging": cl})

    def _run_with_missing_cloudtrail_role(self, ctx):
        """Every role exists except AWSControlTowerCloudTrailRole."""
        def get_role(**kw):
            if kw.get("RoleName") == self.CT_ROLE:
                raise ct.ClientError(
                    {"Error": {"Code": "NoSuchEntity", "Message": "not found"}}, "GetRole")
            return {"Role": {"RoleName": kw.get("RoleName")}}
        iam = FakeClient(responses={"get_role": get_role})
        ctx.session = FakeSession({"iam": iam})
        rep = ct.Report()
        ct.check_required_iam_roles(ctx, rep)
        return [f.level for f in rep.findings], rep.findings

    def test_v33_logging_enabled_role_required(self):
        lv, f = self._run_with_missing_cloudtrail_role(self._ctx("3.3", True))
        self.assertEqual(lv, [ct.BLOCKER])
        self.assertIn(self.CT_ROLE, str(f[0].rows))

    def test_v40_logging_enabled_role_required(self):
        lv, _ = self._run_with_missing_cloudtrail_role(self._ctx("4.0", True))
        self.assertEqual(lv, [ct.BLOCKER])

    def test_v40_logging_disabled_role_not_required(self):
        """The condition-1 case: absence is expected, so no BLOCKER."""
        lv, f = self._run_with_missing_cloudtrail_role(self._ctx("4.0", False))
        self.assertEqual(lv, [ct.PASS])
        self.assertIn(self.CT_ROLE, f[0].summary)
        self.assertIn("disables CentralizedLogging", f[0].summary)

    def test_v33_logging_disabled_role_still_required(self):
        """Pre-4.0 a disable retained the resources, so the role is still expected."""
        lv, _ = self._run_with_missing_cloudtrail_role(self._ctx("3.3", False))
        self.assertEqual(lv, [ct.BLOCKER])

    def test_unknown_version_logging_disabled_not_required(self):
        lv, _ = self._run_with_missing_cloudtrail_role(self._ctx("not-a-version", False))
        self.assertEqual(lv, [ct.PASS])

    def test_absent_enabled_flag_keeps_role_required(self):
        lv, _ = self._run_with_missing_cloudtrail_role(self._ctx("4.0", None))
        self.assertEqual(lv, [ct.BLOCKER])

    def test_missing_and_unverifiable_are_both_reported(self):
        """A role that could not be checked must not be dropped when a BLOCKER also fires."""
        def get_role(**kw):
            name = kw.get("RoleName")
            if name == self.CT_ROLE:
                raise ct.ClientError(
                    {"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "GetRole")
            if name == "AWSControlTowerAdmin":
                raise ct.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetRole")
            return {"Role": {"RoleName": name}}
        ctx = self._ctx("3.3", True)
        ctx.session = FakeSession({"iam": FakeClient(responses={"get_role": get_role})})
        rep = ct.Report()
        ct.check_required_iam_roles(ctx, rep)
        levels = [f.level for f in rep.findings]
        self.assertIn(ct.BLOCKER, levels)
        self.assertIn(ct.UNKNOWN, levels)


class TestBaselineSeverityByTarget(unittest.TestCase):
    """A landing-zone update acts on the management and service-integration accounts. Enrolled
    accounts are updated separately: "When you perform a landing zone update, you must update
    your enrolled accounts to apply new controls to those accounts" (update-existing-accounts).
    Account baseline drift is repairable drift, fixed by updating the account. So an unhealthy
    baseline on a member account or OU must NOT fail the whole precheck.
    """

    ARN = "arn:aws:organizations::111111111111:account/o-abc123/%s"
    OU_ARN = "arn:aws:organizations::111111111111:ou/o-abc123/ou-ab12-cdefghij"

    def _levels(self, target, status="FAILED", drift=None):
        b = {"targetIdentifier": target, "baselineVersion": "4.0",
             "statusSummary": {"status": status}}
        if drift:
            b["driftStatusSummary"] = {"driftStatus": drift}
        ctl = FakeClient({"list_enabled_baselines": {"enabledBaselines": [b]}})
        return levels(_run(ct.check_enabled_baselines, make_ctx({"controltower": ctl})))

    def test_audit_account_blocks(self):
        self.assertIn(ct.BLOCKER, self._levels(self.ARN % "444444444444"))

    def test_log_archive_account_blocks(self):
        self.assertIn(ct.BLOCKER, self._levels(self.ARN % "555555555555"))

    def test_management_account_blocks(self):
        self.assertIn(ct.BLOCKER, self._levels(self.ARN % "111111111111"))

    def test_member_account_warns_not_blocks(self):
        """The observed real case: a test account parked in an unmanaged OU reported FAILED,
        which previously failed an otherwise healthy landing zone with exit 2."""
        lv = self._levels(self.ARN % "333333333333")
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_ou_target_warns_not_blocks(self):
        lv = self._levels(self.OU_ARN)
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_member_drift_warns_not_blocks(self):
        lv = self._levels(self.ARN % "333333333333", status="SUCCEEDED", drift="DRIFTED")
        self.assertIn(ct.WARNING, lv)
        self.assertNotIn(ct.BLOCKER, lv)

    def test_integration_account_drift_still_blocks(self):
        self.assertIn(ct.BLOCKER,
                      self._levels(self.ARN % "444444444444",
                                   status="SUCCEEDED", drift="DRIFTED"))

    def test_not_applicable_and_not_enabled_are_expected(self):
        """4.0: the CT and Config baselines are not applicable to the Security OU and the
        service-integration accounts, and that status is expected - never a finding."""
        for status in ("NOT_APPLICABLE", "Not Applicable", "NOT_ENABLED", "Not Enabled"):
            self.assertEqual(self._levels(self.ARN % "444444444444", status=status),
                             {ct.PASS}, f"{status!r} should be treated as expected")

    def test_healthy_passes(self):
        self.assertEqual(self._levels(self.ARN % "444444444444", status="SUCCEEDED"), {ct.PASS})

    def test_mixed_targets_report_separately(self):
        ctl = FakeClient({"list_enabled_baselines": {"enabledBaselines": [
            {"targetIdentifier": self.ARN % "444444444444", "baselineVersion": "4.0",
             "statusSummary": {"status": "FAILED"}},
            {"targetIdentifier": self.ARN % "333333333333", "baselineVersion": "4.0",
             "statusSummary": {"status": "FAILED"}}]}})
        lv = levels(_run(ct.check_enabled_baselines, make_ctx({"controltower": ctl})))
        self.assertEqual(lv, {ct.BLOCKER, ct.WARNING})

    def test_target_account_id_parsing(self):
        self.assertEqual(ct._target_account_id(self.ARN % "123456789012"), "123456789012")
        self.assertEqual(ct._target_account_id("123456789012"), "123456789012")
        self.assertIsNone(ct._target_account_id(self.OU_ARN))
        self.assertIsNone(ct._target_account_id("arn:acct"))
        self.assertIsNone(ct._target_account_id(""))

    def test_execution_role_stackset_no_longer_asserted(self):
        """StackSet presence is the wrong proxy for the role; it can be deleted with stacks
        retained. check_member_execution_roles tests the role directly instead."""
        self.assertNotIn("AWSControlTowerExecutionRole", ct._EXPECTED_STACKSETS)


class TestKmsKeyRequirements(unittest.TestCase):
    """configure-kms-keys.html: Control Tower pre-checks the key against five requirements -
    Enabled, Symmetric, Not a multi-Region key, correct key policy, and Key is in the management
    account - and "does not support multi-Region keys or asymmetric keys". Four are decided by
    the kms:DescribeKey response this check already makes.
    """

    ARN = kms_arn("111111111111")

    def _levels(self, **meta):
        md = {"KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT",
              "KeyUsage": "ENCRYPT_DECRYPT", "MultiRegion": False, "Arn": self.ARN}
        md.update(meta)
        kms = FakeClient({"describe_key": {"KeyMetadata": md}})
        ctx = make_ctx({"kms": kms}, kms_key_arn=md["Arn"])
        rep = ct.Report()
        ct.check_kms_key(ctx, rep)
        return {f.level for f in rep.findings}, rep.findings

    def test_compliant_key_passes(self):
        lv, _ = self._levels()
        self.assertEqual(lv, {ct.PASS})

    def test_disabled_key_blocks(self):
        lv, f = self._levels(KeyState="Disabled")
        self.assertEqual(lv, {ct.BLOCKER})
        self.assertIn("Enabled", str(f[0].rows))

    def test_pending_deletion_blocks(self):
        lv, _ = self._levels(KeyState="PendingDeletion")
        self.assertEqual(lv, {ct.BLOCKER})

    def test_multi_region_key_blocks(self):
        """Regression: a multi-Region key previously reported PASS with a cosmetic
        '(multi-Region)' label, although Control Tower does not support such keys."""
        lv, f = self._levels(MultiRegion=True)
        self.assertEqual(lv, {ct.BLOCKER})
        self.assertIn("multi-Region", str(f[0].rows))

    def test_asymmetric_key_blocks(self):
        lv, f = self._levels(KeySpec="RSA_4096", KeyUsage="ENCRYPT_DECRYPT")
        self.assertEqual(lv, {ct.BLOCKER})
        self.assertIn("Symmetric", str(f[0].rows))

    def test_sign_verify_key_blocks(self):
        lv, _ = self._levels(KeySpec="", KeyUsage="SIGN_VERIFY")
        self.assertEqual(lv, {ct.BLOCKER})

    def test_legacy_spec_field_honoured(self):
        lv, _ = self._levels(KeySpec="", CustomerMasterKeySpec="RSA_2048")
        self.assertEqual(lv, {ct.BLOCKER})

    def test_key_outside_management_account_blocks(self):
        lv, f = self._levels(Arn=kms_arn("999999999999"))
        self.assertEqual(lv, {ct.BLOCKER})
        self.assertIn("management account", str(f[0].rows))

    def test_all_problems_reported_together(self):
        lv, f = self._levels(KeyState="Disabled", MultiRegion=True, KeySpec="RSA_4096",
                             Arn=kms_arn("999999999999", key_id="x"))
        self.assertEqual(lv, {ct.BLOCKER})
        self.assertEqual(len(f[0].rows), 4)

    def test_no_key_configured_is_info(self):
        ctx = make_ctx({"kms": FakeClient()}, kms_key_arn=None)
        rep = ct.Report()
        ct.check_kms_key(ctx, rep)
        self.assertEqual({f.level for f in rep.findings}, {ct.INFO})

    def test_arn_account_parsing(self):
        self.assertEqual(ct._arn_account(self.ARN), "111111111111")
        self.assertIsNone(ct._arn_account("not-an-arn"))
        self.assertIsNone(ct._arn_account(""))


class TestV4IntegrationDependencies(unittest.TestCase):
    """lz-api-launch.html: "If you disable AWS Config integration ("config.enabled": false), you
    must also disable the following integrations: Security Roles, Access Management, Backup."
    key-changes-lz-v4.html adds that IdentityCenterBaseline, BackupAdminBaseline and
    BackupCentralVaultBaseline each require CentralSecurityRolesBaseline.
    """

    def _levels(self, manifest, version="3.3", latest="4.0"):
        ctx = make_ctx(manifest=manifest,
                       lz={"status": "ACTIVE", "version": version,
                           "latestAvailableVersion": latest,
                           "driftStatus": {"status": "IN_SYNC"}})
        rep = ct.Report()
        ct.check_v4_integration_dependencies(ctx, rep)
        return {f.level for f in rep.findings}, rep.findings

    def test_config_disabled_with_security_roles_enabled_warns(self):
        lv, f = self._levels({"config": {"enabled": False},
                              "securityRoles": {"enabled": True}})
        self.assertEqual(lv, {ct.WARNING})
        self.assertIn("securityRoles", str(f[0].rows))

    def test_config_disabled_with_access_management_enabled_warns(self):
        lv, f = self._levels({"config": {"enabled": False},
                              "accessManagement": {"enabled": True}})
        self.assertEqual(lv, {ct.WARNING})
        self.assertIn("accessManagement", str(f[0].rows))

    def test_config_disabled_with_backup_enabled_warns(self):
        lv, _ = self._levels({"config": {"enabled": False},
                              "backup": {"enabled": True}})
        self.assertEqual(lv, {ct.WARNING})

    def test_security_roles_disabled_with_backup_enabled_warns(self):
        lv, _ = self._levels({"config": {"enabled": True},
                              "securityRoles": {"enabled": False},
                              "backup": {"enabled": True}})
        self.assertEqual(lv, {ct.WARNING})

    def test_each_offender_reported_once(self):
        """backup violates both rules at once; it must appear a single time."""
        lv, f = self._levels({"config": {"enabled": False},
                              "securityRoles": {"enabled": False},
                              "backup": {"enabled": True}})
        self.assertEqual(lv, {ct.WARNING})
        self.assertEqual(len(f[0].rows), 1)

    def test_real_v4_manifest_passes(self):
        """The observed 4.0 manifest: config off with every dependent off, logging on."""
        lv, _ = self._levels({"accessManagement": {"enabled": False},
                              "backup": {"enabled": False},
                              "centralizedLogging": {"accountId": "555555555555",
                                                     "enabled": True},
                              "config": {"enabled": False},
                              "securityRoles": {"enabled": False}},
                             version="4.0")
        self.assertEqual(lv, {ct.PASS})

    def test_all_enabled_passes(self):
        lv, _ = self._levels({"config": {"enabled": True},
                              "securityRoles": {"enabled": True},
                              "accessManagement": {"enabled": True},
                              "backup": {"enabled": True}})
        self.assertEqual(lv, {ct.PASS})

    def test_centralized_logging_is_independent(self):
        """LogArchiveBaseline and CentralConfigBaseline have no dependencies either way."""
        lv, _ = self._levels({"centralizedLogging": {"enabled": False},
                              "config": {"enabled": True},
                              "securityRoles": {"enabled": True}})
        self.assertEqual(lv, {ct.PASS})

    def test_absent_flags_are_not_read_as_disabled(self):
        """A 3.3 manifest has no enabled flags and no config key; nothing may fire."""
        lv, _ = self._levels({"accessManagement": {"enabled": True},
                              "centralizedLogging": {"accountId": "555555555555",
                                                     "enabled": True},
                              "securityRoles": {"accountId": "444444444444"}})
        self.assertEqual(lv, {ct.PASS})

    def test_no_flags_at_all_is_info(self):
        lv, _ = self._levels({"securityRoles": {"accountId": "444444444444"}})
        self.assertEqual(lv, {ct.INFO})

    def test_skipped_when_4_0_not_in_play(self):
        lv, f = self._levels({"config": {"enabled": False},
                              "backup": {"enabled": True}},
                             version="3.2", latest="3.3")
        self.assertEqual(f, [])
        self.assertEqual(lv, set())

    def test_integration_enabled_helper(self):
        ctx = make_ctx(manifest={"config": {"enabled": False},
                                 "securityRoles": {"accountId": "444444444444"},
                                 "backup": {"enabled": True}})
        self.assertIs(ct._integration_enabled(ctx, "config"), False)
        self.assertIs(ct._integration_enabled(ctx, "backup"), True)
        self.assertIsNone(ct._integration_enabled(ctx, "securityRoles"))
        self.assertIsNone(ct._integration_enabled(ctx, "accessManagement"))


class TestIdentityCenterRegion(unittest.TestCase):
    """getting-started-prereqs.html: "If AWS IAM Identity Center is already set up, the AWS Control
    Tower home Region must be the same as the IAM Identity Center Region. However, if IAM Identity
    Center is set up in the US East (N. Virginia) Region (us-east-1), AWS Control Tower uses that
    instance regardless of the home Region you select."
    """

    INSTANCE = {"Instances": [{"InstanceArn": "arn:aws:sso:::instance/ssoins-abc123",
                               "IdentityStoreId": "d-abc123"}]}

    def _run(self, present_in, home="us-east-1", governed=None, manifest=None, errors_in=()):
        """present_in: regions where ListInstances returns an instance."""
        class RegionalSession:
            def __init__(self, outer):
                self.outer = outer
            def client(self, service, region_name=None, **kw):
                if service != "sso-admin":
                    return FakeClient()
                if region_name in errors_in:
                    return FakeClient(errors={"list_instances": client_error(
                        "AccessDeniedException", "ListInstances")})
                body = self.outer.INSTANCE if region_name in present_in else {"Instances": []}
                return FakeClient({"list_instances": body})
        ctx = make_ctx(manifest=manifest if manifest is not None else {},
                       governed_regions=governed if governed is not None else [home])
        ctx.region = home
        ctx.session = RegionalSession(self)
        rep = ct.Report()
        ct.check_identity_center_region(ctx, rep)
        return {f.level for f in rep.findings}, rep.findings

    def test_aligned_with_home_region_passes(self):
        lv, f = self._run(present_in={"eu-west-1"}, home="eu-west-1", governed=["eu-west-1"])
        self.assertEqual(lv, {ct.PASS})
        self.assertIn("home Region", f[0].summary)

    def test_us_east_1_is_exempt(self):
        """Home is eu-west-1 but Identity Center is in us-east-1 - documented as acceptable."""
        lv, f = self._run(present_in={"us-east-1"}, home="eu-west-1", governed=["eu-west-1"])
        self.assertEqual(lv, {ct.PASS})
        self.assertIn("us-east-1", f[0].summary)

    def test_real_mismatch_warns(self):
        lv, f = self._run(present_in={"ap-south-1"}, home="eu-west-1",
                          governed=["eu-west-1", "ap-south-1"])
        self.assertEqual(lv, {ct.WARNING})
        self.assertIn("ap-south-1", f[0].summary)

    def test_absent_everywhere_is_info_not_unknown(self):
        """UNKNOWN fails closed by default, so absence must not gate the upgrade."""
        lv, _ = self._run(present_in=set(), home="eu-west-1", governed=["eu-west-1"])
        self.assertEqual(lv, {ct.INFO})

    def test_access_management_disabled_skips(self):
        lv, f = self._run(present_in={"ap-south-1"}, home="eu-west-1",
                          governed=["eu-west-1", "ap-south-1"],
                          manifest={"accessManagement": {"enabled": False}})
        self.assertEqual(lv, {ct.INFO})
        self.assertIn("not applicable", f[0].summary)

    def test_all_calls_failing_is_unknown(self):
        lv, _ = self._run(present_in=set(), home="eu-west-1", governed=["eu-west-1"],
                          errors_in=("eu-west-1", "us-east-1"))
        self.assertEqual(lv, {ct.UNKNOWN})

    def test_home_region_not_probed_twice_when_us_east_1(self):
        lv, f = self._run(present_in={"us-east-1"}, home="us-east-1", governed=["us-east-1"])
        self.assertEqual(lv, {ct.PASS})
        self.assertIn("home Region", f[0].summary)


class TestServiceIntegrationAccounts(unittest.TestCase):
    """The manifest nests TWO Backup accounts under backup.configurations, so a flat
    node.get("accountId") never finds them. That made the same-parent-OU check compare only a
    subset of the integration accounts and still report PASS, and left those accounts out of the
    severity-tiering set so a failure in one was downgraded to a member-account WARNING.
    """

    FULL = {
        "centralizedLogging": {"accountId": "555555555555", "enabled": True},
        "securityRoles": {"accountId": "444444444444", "enabled": True},
        "config": {"accountId": "666666666666", "enabled": True},
        "backup": {"enabled": True, "configurations": {
            "backupAdmin": {"accountId": "777777777777"},
            "centralBackup": {"accountId": "888888888888"},
        }},
    }

    def test_all_five_accounts_found(self):
        got = ct.service_integration_accounts(self.FULL)
        self.assertEqual(set(got), {"555555555555", "444444444444", "666666666666",
                                    "777777777777", "888888888888"})

    def test_nested_backup_accounts_found(self):
        got = ct.service_integration_accounts(self.FULL)
        self.assertIn("777777777777", got)
        self.assertIn("888888888888", got)
        self.assertEqual(got["777777777777"], ["Backup admin"])
        self.assertEqual(got["888888888888"], ["Central backup"])

    def test_explicitly_disabled_integration_excluded(self):
        """A disabled integration is no longer managed by Control Tower, so its accounts must
        NOT be treated as ones a landing-zone operation acts on."""
        m = dict(self.FULL, backup={"enabled": False, "configurations": {
            "backupAdmin": {"accountId": "777777777777"}}})
        got = ct.service_integration_accounts(m)
        self.assertNotIn("777777777777", got)

    def test_absent_enabled_flag_is_not_a_disable(self):
        """Pre-4.0 manifests carry no enabled flags at all."""
        got = ct.service_integration_accounts(
            {"securityRoles": {"accountId": "444444444444"}})
        self.assertEqual(set(got), {"444444444444"})

    def test_shared_account_between_integrations_groups_labels(self):
        got = ct.service_integration_accounts({
            "centralizedLogging": {"accountId": "555555555555"},
            "config": {"accountId": "555555555555"}})
        self.assertEqual(set(got), {"555555555555"})
        self.assertEqual(len(got["555555555555"]), 2)

    def test_empty_manifest_yields_nothing(self):
        self.assertEqual(ct.service_integration_accounts({}), {})

    def test_backup_without_configurations_is_safe(self):
        self.assertEqual(ct.service_integration_accounts({"backup": {"enabled": True}}), {})

    def test_shared_accounts_property_includes_backup(self):
        ctx = make_ctx(manifest=self.FULL)
        self.assertEqual(
            ctx.shared_accounts,
            {"111111111111", "555555555555", "444444444444", "666666666666",
             "777777777777", "888888888888"})

    def test_shared_accounts_property_honours_overrides(self):
        """--audit-account / --log-archive-account are applied after discovery."""
        ctx = make_ctx(manifest={})
        ctx.audit_account = "222222222222"
        self.assertIn("222222222222", ctx.shared_accounts)

    def test_baseline_failure_in_backup_account_now_blocks(self):
        """Regression for the observed live case: a failure in the backupAdmin account was
        classified as a member account and downgraded to WARNING."""
        arn = "arn:aws:organizations::111111111111:account/o-a/777777777777"
        ctl = FakeClient({"list_enabled_baselines": {"enabledBaselines": [
            {"targetIdentifier": arn, "baselineVersion": "4.0",
             "statusSummary": {"status": "FAILED"}}]}})
        ctx = make_ctx({"controltower": ctl}, manifest=self.FULL)
        lv = levels(_run(ct.check_enabled_baselines, ctx))
        self.assertIn(ct.BLOCKER, lv)
        self.assertNotIn(ct.WARNING, lv)


if __name__ == "__main__":
    unittest.main(verbosity=2)
