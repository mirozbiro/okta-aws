#!/usr/bin/env python3
"""
okta-aws: CLI tool to authenticate to AWS via Okta SAML with MFA support.

Authenticates to an Okta portal (including MFA), navigates to the AWS SAML
app, presents available accounts and roles, assumes the selected role via STS,
and writes temporary credentials to ~/.aws/credentials.
"""

import argparse
import base64
import configparser
import getpass
import os
import sys
import time
import xml.etree.ElementTree as ET

import boto3
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.okta-aws")
AWS_CREDENTIALS_PATH = os.path.expanduser("~/.aws/credentials")
AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")
DEFAULT_PROFILE = "okta"
DEFAULT_SESSION_DURATION = 3600  # 1 hour

SAML_ROLE_ATTRIBUTE = "https://aws.amazon.com/SAML/Attributes/Role"
SAML_SESSION_ATTRIBUTE = "https://aws.amazon.com/SAML/Attributes/SessionDuration"

PUSH_POLL_INTERVAL = 3   # seconds between push-approval polls
PUSH_POLL_TIMEOUT = 180  # seconds before giving up on a push

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def load_config(config_path):
    """Load configuration from an INI file."""
    config = configparser.ConfigParser()
    if os.path.exists(config_path):
        config.read(config_path)
    return config


# ---------------------------------------------------------------------------
# Okta authentication
# ---------------------------------------------------------------------------


def okta_authn(okta_url, username, password):
    """Perform primary Okta username/password authentication.

    Returns the parsed JSON response from the /api/v1/authn endpoint.
    Raises requests.HTTPError on HTTP errors.
    """
    url = f"{okta_url}/api/v1/authn"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    response = requests.post(
        url,
        json={"username": username, "password": password},
        headers=headers,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def okta_mfa_verify(okta_url, factor, state_token, passcode=None):
    """Send an MFA verification request to Okta.

    For push factors call without *passcode* to trigger the challenge, then
    poll this endpoint again (without passcode) to check approval status.
    """
    url = f"{okta_url}/api/v1/authn/factors/{factor['id']}/verify"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = {"stateToken": state_token}
    if passcode:
        payload["passCode"] = passcode
    response = requests.post(url, json=payload, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


def _choose_factor(factors):
    """Return a single factor from *factors*, prompting the user if necessary."""
    if len(factors) == 1:
        return factors[0]

    labels = {
        "token:software:totp": "TOTP Authenticator",
        "push": "Okta Verify Push",
        "sms": "SMS",
        "call": "Voice Call",
        "token:hotp": "HOTP Token",
        "email": "Email",
    }

    print("\nAvailable MFA factors:")
    for i, factor in enumerate(factors):
        factor_type = factor.get("factorType", "unknown")
        provider = factor.get("provider", "")
        label = labels.get(factor_type, factor_type)
        if provider:
            label = f"{label} ({provider})"
        print(f"  [{i + 1}] {label}")

    while True:
        try:
            choice = int(input("\nSelect MFA factor: ").strip()) - 1
            if 0 <= choice < len(factors):
                return factors[choice]
        except ValueError:
            pass
        print("Invalid selection, please try again.")


def handle_mfa(okta_url, authn_result):
    """Handle the MFA challenge and return the authn result after success."""
    state_token = authn_result["stateToken"]
    factors = authn_result["_embedded"]["factors"]
    factor = _choose_factor(factors)
    factor_type = factor.get("factorType", "")

    if factor_type == "push":
        return _handle_push(okta_url, factor, state_token)

    if factor_type in ("token:software:totp", "token:hotp"):
        passcode = input("Enter TOTP code: ").strip()
        return okta_mfa_verify(okta_url, factor, state_token, passcode)

    if factor_type == "sms":
        print("Sending SMS code...")
        okta_mfa_verify(okta_url, factor, state_token)
        passcode = input("Enter SMS code: ").strip()
        return okta_mfa_verify(okta_url, factor, state_token, passcode)

    if factor_type == "email":
        print("Sending email code...")
        okta_mfa_verify(okta_url, factor, state_token)
        passcode = input("Enter email code: ").strip()
        return okta_mfa_verify(okta_url, factor, state_token, passcode)

    # Generic fallback for any other factor type
    passcode = input(f"Enter code for {factor_type}: ").strip()
    return okta_mfa_verify(okta_url, factor, state_token, passcode)


def _handle_push(okta_url, factor, state_token):
    """Poll Okta Verify push until approved, rejected, or timeout."""
    print("Sending push notification to Okta Verify… please approve it.", flush=True)
    result = okta_mfa_verify(okta_url, factor, state_token)
    deadline = time.time() + PUSH_POLL_TIMEOUT

    while result.get("status") == "MFA_CHALLENGE":
        factor_result = result.get("factorResult", "")
        if factor_result == "WAITING":
            if time.time() > deadline:
                print("\nPush notification timed out.")
                sys.exit(1)
            print(".", end="", flush=True)
            time.sleep(PUSH_POLL_INTERVAL)
            result = okta_mfa_verify(okta_url, factor, state_token)
        elif factor_result == "REJECTED":
            print("\nPush notification was rejected.")
            sys.exit(1)
        elif factor_result == "TIMEOUT":
            print("\nPush notification timed out.")
            sys.exit(1)
        else:
            break  # unknown status — fall through and let caller check

    print()
    return result


# ---------------------------------------------------------------------------
# SAML assertion retrieval
# ---------------------------------------------------------------------------


def get_saml_assertion(okta_url, app_url, session_token, debug=False):
    """Retrieve the base64-encoded SAML assertion from the Okta AWS app.

    Two strategies are tried:
    1. Exchange the session token for a cookie via /login/sessionCookieRedirect,
       then follow redirects to the app.
    2. Append the session token directly to the app URL as a query parameter.

    Returns (saml_assertion, action_url, http_session).
      - saml_assertion: raw base64 SAML assertion string
      - action_url: the form POST target URL (AWS SSO ACS or signin.aws.amazon.com/saml)
      - http_session: the requests.Session with any established cookies
    Raises ValueError when no SAMLResponse form field is found.
    """
    session = requests.Session()

    # Strategy 1: session cookie exchange
    cookie_url = f"{okta_url}/login/sessionCookieRedirect"
    if debug:
        print(f"[DEBUG] Strategy 1: GET {cookie_url}")
        print(f"[DEBUG]   params: checkAccountSetupComplete=true, token=<redacted>, redirectUrl={app_url}")
    resp = session.get(
        cookie_url,
        params={"checkAccountSetupComplete": "true", "token": session_token, "redirectUrl": app_url},
        allow_redirects=True,
        timeout=30,
    )
    if debug:
        print(f"[DEBUG] Final URL after redirects: {resp.url}")
        print(f"[DEBUG] HTTP status: {resp.status_code}")
        print(f"[DEBUG] Redirect chain: {[r.url for r in resp.history]}")
        print(f"[DEBUG] Response HTML (first 3000 chars):\n{resp.text[:3000]}")
    resp.raise_for_status()
    saml_assertion, action_url = _extract_saml_form(resp.text)

    if debug:
        print(f"[DEBUG] SAMLResponse found (strategy 1): {bool(saml_assertion)}")
        print(f"[DEBUG] Form action URL (strategy 1): {action_url}")

    if not saml_assertion:
        # Strategy 2: session token as query parameter
        strategy2_url = f"{app_url}?sessionToken={session_token}"
        if debug:
            print(f"[DEBUG] Strategy 2: GET {app_url}?sessionToken=<redacted>")
        resp = session.get(
            strategy2_url,
            allow_redirects=True,
            timeout=30,
        )
        if debug:
            print(f"[DEBUG] Final URL after redirects: {resp.url}")
            print(f"[DEBUG] HTTP status: {resp.status_code}")
            print(f"[DEBUG] Redirect chain: {[r.url for r in resp.history]}")
            print(f"[DEBUG] Response HTML (first 3000 chars):\n{resp.text[:3000]}")
        resp.raise_for_status()
        saml_assertion, action_url = _extract_saml_form(resp.text)
        if debug:
            print(f"[DEBUG] SAMLResponse found (strategy 2): {bool(saml_assertion)}")
            print(f"[DEBUG] Form action URL (strategy 2): {action_url}")

    if not saml_assertion:
        raise ValueError(
            "Could not find SAMLResponse in Okta response. "
            "Verify that 'app_url' is the embed link for the AWS SAML app."
        )

    return saml_assertion, action_url, session


def _extract_saml_form(html):
    """Return (saml_assertion, action_url) from an HTML form, or (None, None)."""
    soup = BeautifulSoup(html, "lxml")
    tag = soup.find("input", {"name": "SAMLResponse"})
    if not tag:
        return None, None
    form = tag.find_parent("form")
    action_url = form["action"] if form and form.get("action") else None
    return tag["value"], action_url


def _extract_saml_response(html):
    """Return the SAMLResponse value from an HTML form, or None."""
    value, _ = _extract_saml_form(html)
    return value


# ---------------------------------------------------------------------------
# SAML parsing
# ---------------------------------------------------------------------------


def parse_saml_roles(saml_assertion):
    """Decode and parse the SAML assertion.

    Returns:
        roles (list[dict]): each dict has keys role_arn, principal_arn,
            account_id, role_name.
        session_duration (int): requested session duration in seconds.
    """
    saml_xml = base64.b64decode(saml_assertion).decode("utf-8")
    root = ET.fromstring(saml_xml)

    roles = []
    session_duration = DEFAULT_SESSION_DURATION
    ns_value = "{urn:oasis:names:tc:SAML:2.0:assertion}"

    for attr in root.iter(f"{ns_value}Attribute"):
        attr_name = attr.get("Name", "")

        if attr_name == SAML_ROLE_ATTRIBUTE:
            for value_el in attr.iter(f"{ns_value}AttributeValue"):
                text = (value_el.text or "").strip()
                if not text:
                    continue
                role_info = _parse_role_value(text)
                if role_info:
                    roles.append(role_info)

        elif attr_name == SAML_SESSION_ATTRIBUTE:
            for value_el in attr.iter(f"{ns_value}AttributeValue"):
                try:
                    session_duration = int((value_el.text or "").strip())
                except ValueError:
                    pass

    return roles, session_duration


def _parse_role_value(text):
    """Parse a single Role attribute value into a dict.

    The value is a comma-separated pair of ARNs:
    ``arn:aws:iam::ACCT:saml-provider/P,arn:aws:iam::ACCT:role/R``
    or in reverse order.  Returns None if the value cannot be parsed.
    """
    parts = [p.strip() for p in text.split(",")]
    if len(parts) != 2:
        return None

    role_arn = next((p for p in parts if ":role/" in p), None)
    principal_arn = next((p for p in parts if ":saml-provider/" in p), None)

    if not role_arn or not principal_arn:
        return None

    return {
        "role_arn": role_arn,
        "principal_arn": principal_arn,
        "account_id": role_arn.split(":")[4],
        "role_name": role_arn.split("/")[-1],
    }


# ---------------------------------------------------------------------------
# AWS IAM Identity Center (SSO) flow
# ---------------------------------------------------------------------------

SSO_DEFAULT_REGION = "us-east-1"


def submit_saml_to_sso(action_url, saml_assertion, http_session):
    """POST the SAML assertion to the AWS SSO ACS endpoint.

    Returns the x-amz-sso_authn token extracted from the response cookies,
    plus the SSO region inferred from the action_url host.
    Raises ValueError when the token cannot be found.
    """
    resp = http_session.post(
        action_url,
        data={"SAMLResponse": saml_assertion},
        allow_redirects=True,
        timeout=30,
    )
    resp.raise_for_status()

    # The portal sets x-amz-sso_authn as a cookie on the SSO domain
    token = http_session.cookies.get("x-amz-sso_authn")
    if not token:
        # Sometimes it arrives as a header or query param in the redirect
        for r in resp.history:
            token = r.cookies.get("x-amz-sso_authn")
            if token:
                break

    if not token:
        raise ValueError(
            "Could not retrieve x-amz-sso_authn token after SAML POST. "
            "Verify that the Okta app is configured for AWS IAM Identity Center (SSO)."
        )

    # Derive region from hostname: portal.sso.<region>.amazonaws.com or similar
    import re
    m = re.search(r"portal\.sso\.([a-z0-9-]+)\.amazonaws\.com", action_url)
    sso_region = m.group(1) if m else SSO_DEFAULT_REGION

    return token, sso_region


def list_sso_accounts_and_roles(sso_token, sso_region):
    """Return a flat list of dicts with keys: account_id, account_name, role_name.

    Uses boto3 SSO client with the short-lived portal token — no credentials needed.
    """
    client = boto3.client("sso", region_name=sso_region)
    accounts = []
    paginator = client.get_paginator("list_accounts")
    for page in paginator.paginate(accessToken=sso_token):
        accounts.extend(page["accountList"])

    entries = []
    for acct in accounts:
        role_paginator = client.get_paginator("list_account_roles")
        for page in role_paginator.paginate(
            accessToken=sso_token, accountId=acct["accountId"]
        ):
            for role in page["roleList"]:
                entries.append(
                    {
                        "account_id": acct["accountId"],
                        "account_name": acct.get("accountName", acct["accountId"]),
                        "role_name": role["roleName"],
                    }
                )
    return entries


def select_sso_account_and_role(entries, preselect_account=None, preselect_role=None):
    """Interactive (or automatic) account and role selection for SSO entries.

    Each entry has keys: account_id, account_name, role_name.
    Returns a single selected entry dict.
    """
    if preselect_account or preselect_role:
        candidates = [
            e for e in entries
            if (not preselect_account or e["account_id"] == preselect_account
                or e["account_name"] == preselect_account)
            and (not preselect_role or e["role_name"] == preselect_role)
        ]
        if not candidates:
            print(
                f"No SSO role found matching "
                f"account={preselect_account or 'any'}, "
                f"role={preselect_role or 'any'}"
            )
            print("Available entries:")
            for e in entries:
                print(f"  {e['account_id']} ({e['account_name']}): {e['role_name']}")
            sys.exit(1)
        if len(candidates) == 1:
            return candidates[0]
        entries = candidates

    # Group by account
    groups = {}
    for e in entries:
        groups.setdefault(e["account_id"], []).append(e)
    account_ids = list(groups.keys())

    if len(account_ids) == 1:
        chosen_account = account_ids[0]
    else:
        print("\nAvailable AWS accounts (SSO):")
        for i, acct_id in enumerate(account_ids):
            acct_name = groups[acct_id][0]["account_name"]
            count = len(groups[acct_id])
            print(f"  [{i + 1}] {acct_id}  {acct_name}  ({count} role{'s' if count != 1 else ''})")
        while True:
            try:
                idx = int(input("\nSelect account: ").strip()) - 1
                if 0 <= idx < len(account_ids):
                    chosen_account = account_ids[idx]
                    break
            except ValueError:
                pass
            print("Invalid selection, please try again.")

    account_entries = groups[chosen_account]
    if len(account_entries) == 1:
        return account_entries[0]

    print(f"\nAvailable roles for {account_entries[0]['account_name']} ({chosen_account}):")
    for i, e in enumerate(account_entries):
        print(f"  [{i + 1}] {e['role_name']}")

    while True:
        try:
            idx = int(input("\nSelect role: ").strip()) - 1
            if 0 <= idx < len(account_entries):
                return account_entries[idx]
        except ValueError:
            pass
        print("Invalid selection, please try again.")


def get_sso_role_credentials(sso_token, sso_region, account_id, role_name):
    """Call sso:GetRoleCredentials and return a Credentials-style dict."""
    client = boto3.client("sso", region_name=sso_region)
    resp = client.get_role_credentials(
        roleName=role_name,
        accountId=account_id,
        accessToken=sso_token,
    )
    rc = resp["roleCredentials"]
    import datetime
    return {
        "AccessKeyId": rc["accessKeyId"],
        "SecretAccessKey": rc["secretAccessKey"],
        "SessionToken": rc["sessionToken"],
        "Expiration": datetime.datetime.utcfromtimestamp(rc["expiration"] / 1000),
    }


# ---------------------------------------------------------------------------
# Account / role selection  (legacy SAML/STS path — kept for fallback)
# ---------------------------------------------------------------------------


def _group_roles_by_account(roles):
    """Return {account_id: [role, …], …} dict preserving insertion order."""
    groups = {}
    for role in roles:
        groups.setdefault(role["account_id"], []).append(role)
    return groups


def select_account_and_role(roles, preselect_account=None, preselect_role=None):
    """Interactive (or automatic) account and role selection.

    If *preselect_account* and/or *preselect_role* are provided the matching
    role is returned without prompting.  Exits with an error when no match is
    found.
    """
    if preselect_account or preselect_role:
        candidates = [
            r for r in roles
            if (not preselect_account or r["account_id"] == preselect_account)
            and (not preselect_role or r["role_name"] == preselect_role)
        ]
        if not candidates:
            print(
                f"No role found matching "
                f"account={preselect_account or 'any'}, "
                f"role={preselect_role or 'any'}"
            )
            print("Available roles:")
            for r in roles:
                print(f"  Account {r['account_id']}: {r['role_name']}")
            sys.exit(1)
        if len(candidates) == 1:
            return candidates[0]
        roles = candidates  # fall through to interactive selection

    groups = _group_roles_by_account(roles)
    account_ids = sorted(groups.keys())

    # Choose account
    if len(account_ids) == 1:
        chosen_account = account_ids[0]
    else:
        print("\nAvailable AWS accounts:")
        for i, acct in enumerate(account_ids):
            count = len(groups[acct])
            print(f"  [{i + 1}] {acct}  ({count} role{'s' if count != 1 else ''})")
        while True:
            try:
                idx = int(input("\nSelect account: ").strip()) - 1
                if 0 <= idx < len(account_ids):
                    chosen_account = account_ids[idx]
                    break
            except ValueError:
                pass
            print("Invalid selection, please try again.")

    # Choose role within that account
    account_roles = groups[chosen_account]
    if len(account_roles) == 1:
        return account_roles[0]

    print(f"\nAvailable roles for account {chosen_account}:")
    for i, role in enumerate(account_roles):
        print(f"  [{i + 1}] {role['role_name']}")
        print(f"       {role['role_arn']}")

    while True:
        try:
            idx = int(input("\nSelect role: ").strip()) - 1
            if 0 <= idx < len(account_roles):
                return account_roles[idx]
        except ValueError:
            pass
        print("Invalid selection, please try again.")


# ---------------------------------------------------------------------------
# AWS credentials
# ---------------------------------------------------------------------------


def assume_role_with_saml(role, saml_assertion, session_duration, region):
    """Call STS AssumeRoleWithSAML and return the Credentials dict."""
    sts = boto3.client("sts", region_name=region)
    response = sts.assume_role_with_saml(
        RoleArn=role["role_arn"],
        PrincipalArn=role["principal_arn"],
        SAMLAssertion=saml_assertion,
        DurationSeconds=min(session_duration, 43200),  # STS max is 12 h
    )
    return response["Credentials"]


def write_aws_credentials(credentials, profile, region):
    """Write temporary credentials to ~/.aws/credentials (and region to ~/.aws/config).

    The credentials file is created with mode 0o600 if it does not exist.
    """
    os.makedirs(os.path.dirname(AWS_CREDENTIALS_PATH), exist_ok=True)

    creds_config = configparser.ConfigParser()
    if os.path.exists(AWS_CREDENTIALS_PATH):
        creds_config.read(AWS_CREDENTIALS_PATH)

    if not creds_config.has_section(profile):
        creds_config.add_section(profile)

    creds_config.set(profile, "aws_access_key_id", credentials["AccessKeyId"])
    creds_config.set(profile, "aws_secret_access_key", credentials["SecretAccessKey"])
    creds_config.set(profile, "aws_session_token", credentials["SessionToken"])
    creds_config.set(profile, "region", region)

    with open(AWS_CREDENTIALS_PATH, "w") as fh:
        creds_config.write(fh)
    os.chmod(AWS_CREDENTIALS_PATH, 0o600)

    # Update ~/.aws/config so 'region' and 'output' are set for the profile
    aws_cfg = configparser.ConfigParser()
    if os.path.exists(AWS_CONFIG_PATH):
        aws_cfg.read(AWS_CONFIG_PATH)

    cfg_section = "default" if profile == "default" else f"profile {profile}"
    if not aws_cfg.has_section(cfg_section):
        aws_cfg.add_section(cfg_section)
    aws_cfg.set(cfg_section, "region", region)
    aws_cfg.set(cfg_section, "output", "json")

    with open(AWS_CONFIG_PATH, "w") as fh:
        aws_cfg.write(fh)
    os.chmod(AWS_CONFIG_PATH, 0o600)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Authenticate to AWS via Okta SAML with MFA support.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  okta-aws                              Use values from ~/.okta-aws
  okta-aws --profile dev                Store credentials in 'dev' profile
  okta-aws --account 123456789012       Pre-select an AWS account
  okta-aws --account 123456789012 \\
           --role MyRole                Pre-select account and role (no prompts)
""",
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help="Path to config file (default: ~/.okta-aws)")
    parser.add_argument("--profile",
                        help=f"AWS credentials profile name (default: {DEFAULT_PROFILE})")
    parser.add_argument("--username", help="Okta username (overrides config)")
    parser.add_argument("--okta-url",
                        help="Okta organization URL, e.g. https://corp.okta.com")
    parser.add_argument("--app-url",
                        help="Okta AWS app embed link URL")
    parser.add_argument("--region", help="AWS region written to ~/.aws/credentials (default: us-east-1)")
    parser.add_argument("--sso-region",
                        help="AWS SSO / IAM Identity Center region (default: us-east-1)")
    parser.add_argument("--duration", type=int,
                        help="Session duration in seconds (default: from SAML / 3600)")
    parser.add_argument("--account",
                        help="Pre-select AWS account ID or name (skips account prompt)")
    parser.add_argument("--role",
                        help="Pre-select IAM role name (skips role prompt)")
    parser.add_argument("--debug", action="store_true",
                        help="Print verbose debug information (URLs, HTML, SAML XML)")
    return parser


def main():
    args = _build_parser().parse_args()

    cfg = load_config(args.config)
    sec = "default"

    def cf(key, arg_val, fallback=None):
        """Return arg_val if set, else config value, else fallback."""
        if arg_val is not None:
            return arg_val
        if cfg.has_section(sec) and cfg.has_option(sec, key):
            return cfg.get(sec, key)
        return fallback

    okta_url = cf("okta_url", args.okta_url)
    app_url = cf("app_url", args.app_url)
    username = cf("username", args.username)
    profile = cf("profile", args.profile, DEFAULT_PROFILE)
    region = cf("region", args.region, "us-east-1")
    sso_region = cf("sso_region", args.sso_region, None)  # will be inferred from ACS url if not set
    duration_cfg = cf("duration", str(args.duration) if args.duration else None,
                      str(DEFAULT_SESSION_DURATION))
    duration = int(duration_cfg)

    # Prompt for any missing required values
    if not okta_url:
        okta_url = input("Okta URL (e.g. https://corp.okta.com): ").strip()
    if not app_url:
        app_url = input("Okta AWS app URL (embed link): ").strip()
    if not username:
        username = input("Username: ").strip()

    if not okta_url.startswith("http"):
        okta_url = f"https://{okta_url}"
    okta_url = okta_url.rstrip("/")

    print(f"\nAuthenticating to {okta_url} as {username}…")
    password = getpass.getpass("Password: ")

    # --- Primary authentication ---
    try:
        authn_result = okta_authn(okta_url, username, password)
    except requests.HTTPError as exc:
        status_code = exc.response.status_code
        if status_code == 401:
            print("Authentication failed: invalid username or password.")
        elif status_code == 429:
            print("Authentication failed: too many requests — please wait and retry.")
        else:
            print(f"Authentication failed: HTTP {status_code}.")
        sys.exit(1)

    status = authn_result.get("status")

    if status == "LOCKED_OUT":
        print("Your account is locked out. Please contact your administrator.")
        sys.exit(1)
    if status == "PASSWORD_EXPIRED":
        print("Your password has expired. Please reset it in Okta and try again.")
        sys.exit(1)
    if status == "MFA_ENROLL":
        print("MFA enrollment is required. Please enroll a factor in Okta first.")
        sys.exit(1)

    if status in ("MFA_REQUIRED", "MFA_CHALLENGE"):
        print("MFA verification required.")
        authn_result = handle_mfa(okta_url, authn_result)
        status = authn_result.get("status")

    if status != "SUCCESS":
        print(f"Authentication failed with unexpected status: {status}")
        sys.exit(1)

    session_token = authn_result.get("sessionToken")
    if not session_token:
        print("Okta did not return a session token. Check your credentials and try again.")
        sys.exit(1)

    print("Okta authentication successful.")

    # --- SAML assertion ---
    print("Retrieving SAML assertion from AWS app…")
    try:
        saml_assertion, action_url, http_session = get_saml_assertion(
            okta_url, app_url, session_token, debug=args.debug
        )
    except Exception as exc:
        print(f"Failed to retrieve SAML assertion: {exc}")
        sys.exit(1)

    if args.debug:
        print(f"[DEBUG] SAML form action URL: {action_url}")
        try:
            import base64 as _b64
            saml_xml = _b64.b64decode(saml_assertion).decode("utf-8")
            print(f"[DEBUG] Decoded SAML XML (first 3000 chars):\n{saml_xml[:3000]}")
        except Exception as e:
            print(f"[DEBUG] Could not decode SAML assertion: {e}")

    # -----------------------------------------------------------------------
    # Detect whether this is an AWS SSO (IAM Identity Center) app or a
    # classic STS/SAML app by inspecting the SAML form action URL.
    # SSO ACS URLs contain "portal.sso" or "identitycenter" / "sso.amazonaws"
    # -----------------------------------------------------------------------
    is_sso = bool(sso_region) or (action_url and (
        "portal.sso" in action_url
        or "identitycenter" in action_url
        or ("sso" in action_url and "amazonaws.com" in action_url)
    ))

    if args.debug:
        print(f"[DEBUG] is_sso detection result: {is_sso}  (action_url={action_url!r})")
        if not is_sso and action_url:
            print("[DEBUG] action_url does not match SSO patterns — falling back to STS path.")
            print("[DEBUG] If your setup uses SSO, run with --sso-region to force SSO mode.")

    if is_sso:
        # ---- AWS IAM Identity Center (SSO) path ----
        print("Detected AWS IAM Identity Center (SSO) portal. Completing SSO login…")
        try:
            sso_token, inferred_sso_region = submit_saml_to_sso(action_url, saml_assertion, http_session)
        except Exception as exc:
            print(f"Failed to complete SSO login: {exc}")
            sys.exit(1)

        # User-specified or config sso_region takes priority over inferred
        effective_sso_region = sso_region or inferred_sso_region
        print(f"SSO region: {effective_sso_region}")

        print("Listing SSO accounts and roles…")
        try:
            entries = list_sso_accounts_and_roles(sso_token, effective_sso_region)
        except Exception as exc:
            print(f"Failed to list SSO accounts/roles: {exc}")
            sys.exit(1)

        if not entries:
            print("No SSO accounts or roles found. Check your IAM Identity Center assignments.")
            sys.exit(1)

        selected = select_sso_account_and_role(entries, args.account, args.role)
        print(f"\nRequesting credentials for: [{selected['account_name']}] {selected['account_id']} / {selected['role_name']}")

        try:
            credentials = get_sso_role_credentials(
                sso_token, effective_sso_region,
                selected["account_id"], selected["role_name"]
            )
        except Exception as exc:
            print(f"Failed to get SSO role credentials: {exc}")
            sys.exit(1)

    else:
        # ---- Classic STS AssumeRoleWithSAML path ----
        try:
            roles, saml_duration = parse_saml_roles(saml_assertion)
        except Exception as exc:
            print(f"Failed to parse SAML assertion: {exc}")
            sys.exit(1)

        if not roles:
            print(
                "No AWS roles found in SAML assertion. "
                "Ensure the Okta app is configured to include Role attributes."
            )
            sys.exit(1)

        if args.duration is None:
            duration = saml_duration

        selected_role = select_account_and_role(roles, args.account, args.role)
        print(f"\nAssuming role: {selected_role['role_arn']}")

        try:
            credentials = assume_role_with_saml(selected_role, saml_assertion, duration, region)
        except Exception as exc:
            print(f"Failed to assume role: {exc}")
            sys.exit(1)

    # --- Write credentials ---
    write_aws_credentials(credentials, profile, region)

    expiry = credentials["Expiration"].strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\nCredentials written to profile '{profile}' ({AWS_CREDENTIALS_PATH})")
    print(f"Expires: {expiry}")
    print()
    if profile == "default":
        print("  aws s3 ls")
    else:
        print(f"  aws --profile {profile} s3 ls")
        print(f"  # or: export AWS_PROFILE={profile}")


if __name__ == "__main__":
    main()
