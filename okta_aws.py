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

# Okta Identity Engine (IDX) headers
IDX_ACCEPT = "application/ion+json; okta-version=1.0.0"
IDX_HEADERS = {
    "Accept": IDX_ACCEPT,
    "Content-Type": IDX_ACCEPT,
}

# ---------------------------------------------------------------------------
# Terminal UI helpers
# ---------------------------------------------------------------------------

def _print_box(title, lines):
    """Print a properly-aligned Unicode box with a title and body lines."""
    max_line = max((len(l) for l in lines), default=0)
    inner = max(len(title) + 2, max_line + 2)
    print(f"\n┌─ {title} {'─' * (inner - len(title) - 1)}┐")
    for line in lines:
        print(f"│  {line}{' ' * (inner - len(line) - 2)}  │")
    print(f"└{'─' * (inner + 2)}┘\n")


def _step(msg):
    """Print an in-progress step line."""
    print(f"  →  {msg}")


def _ok(msg):
    """Print a completion indicator."""
    print(f"  ✔  {msg}")


# ---------------------------------------------------------------------------
# PKCE + IDX helpers
# ---------------------------------------------------------------------------


def _pkce_pair():
    """Return (code_verifier, code_challenge) using S256 method."""
    import hashlib
    import secrets
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _idx_find_remediation(state, *names):
    """Return (href, form_dict) for the first matching remediation name, else (None, None)."""
    for rem in state.get("remediation", {}).get("value", []):
        if rem.get("name") in names:
            return rem.get("href"), rem
    return None, None


def _idx_get_session_token(state):
    """Extract a Okta sessionToken from a terminal IDX state dict, or None."""
    # Embedded IDX with short-lived session token
    for key in ("session", "user"):
        obj = state.get(key)
        if isinstance(obj, dict):
            tok = obj.get("token") or (obj.get("value") or {}).get("token")
            if tok:
                return tok
    return None


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

    print("\n  Available MFA factors:\n")
    for i, factor in enumerate(factors):
        factor_type = factor.get("factorType", "unknown")
        provider = factor.get("provider", "")
        label = labels.get(factor_type, factor_type)
        if provider:
            label = f"{label} ({provider})"
        print(f"  [{i + 1:>2}]  {label}")

    while True:
        try:
            choice = int(input("\n  Select factor: ").strip()) - 1
            if 0 <= choice < len(factors):
                return factors[choice]
        except ValueError:
            pass
        print("  Invalid selection — enter a number from the list.")


def _is_wrong_code(http_error):
    """Return True when the HTTPError is Okta's 'invalid passcode' response."""
    resp = http_error.response
    if resp is None:
        return False
    if resp.status_code not in (400, 403):
        return False
    try:
        code = resp.json().get("errorCode", "")
        # E0000068 = invalid passcode/answer, E0000079 = too many attempts
        return code in ("E0000068", "E0000079") or "passcode" in resp.text.lower()
    except Exception:
        return False


MFA_MAX_ATTEMPTS = 3


def handle_mfa(okta_url, authn_result):
    """Handle the MFA challenge and return the authn result after success.

    Re-prompts up to MFA_MAX_ATTEMPTS times on an incorrect code instead of
    crashing so the user can correct a typo without re-running the script.
    """
    state_token = authn_result["stateToken"]
    factors = authn_result["_embedded"]["factors"]
    factor = _choose_factor(factors)
    factor_type = factor.get("factorType", "")

    if factor_type == "push":
        return _handle_push(okta_url, factor, state_token)

    if factor_type == "sms":
        print("  Sending SMS code…")
        okta_mfa_verify(okta_url, factor, state_token)

    if factor_type == "email":
        print("  Sending email code…")
        okta_mfa_verify(okta_url, factor, state_token)

    prompt = {
        "token:software:totp": "  TOTP code: ",
        "token:hotp":          "  HOTP code: ",
        "sms":                 "  SMS code: ",
        "email":               "  Email code: ",
    }.get(factor_type, f"  Code ({factor_type}): ")

    for attempt in range(1, MFA_MAX_ATTEMPTS + 1):
        passcode = input(prompt).strip()
        try:
            return okta_mfa_verify(okta_url, factor, state_token, passcode)
        except requests.HTTPError as exc:
            if _is_wrong_code(exc):
                remaining = MFA_MAX_ATTEMPTS - attempt
                if remaining > 0:
                    print(f"  Incorrect code — {remaining} attempt{'s' if remaining != 1 else ''} left.")
                else:
                    print("  Incorrect code — no attempts remaining.")
                    sys.exit(1)
            else:
                raise  # unexpected HTTP error — propagate normally


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
# Okta Identity Engine (IDX) authentication
# ---------------------------------------------------------------------------


def okta_idx_authn(okta_url, client_id, username, password, debug=False):
    """Authenticate via the Okta Identity Engine (IDX) pipeline.

    Returns ``(session_token, requests_session)`` where:
    - ``session_token`` is the short-lived Okta session token (str) if the
      terminal IDX state exposes one, otherwise ``None``.
    - ``requests_session`` is a :class:`requests.Session` that carries the
      Okta session cookies set during the IDX flow.  When ``session_token``
      is ``None`` the caller must use this session to fetch the SAML app URL
      directly (the session is already authenticated).

    Raises :class:`requests.HTTPError` or :class:`RuntimeError` on failure.
    """
    import hashlib  # noqa: F401 (used inside _pkce_pair)
    import secrets

    session = requests.Session()
    state_val = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
    code_verifier, code_challenge = _pkce_pair()
    redirect_uri = "http://localhost:8080/login/callback"

    # --- Step 1: obtain interactionHandle via /oauth2/v1/interact ---
    if debug:
        print(f"[IDX] POST {okta_url}/oauth2/v1/interact")
    interact_resp = session.post(
        f"{okta_url}/oauth2/v1/interact",
        data={
            "client_id": client_id,
            "scope": "openid profile email",
            "redirect_uri": redirect_uri,
            "state": state_val,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        timeout=30,
    )
    if debug:
        print(f"[IDX] interact status: {interact_resp.status_code} body: {interact_resp.text[:300]}")
    interact_resp.raise_for_status()
    interaction_handle = interact_resp.json().get("interaction_handle")
    if not interaction_handle:
        raise RuntimeError(
            f"No interaction_handle returned from /oauth2/v1/interact. "
            f"Verify --client-id is correct.\nResponse: {interact_resp.text[:300]}"
        )

    # --- Step 2: introspect to bootstrap the state machine ---
    if debug:
        print(f"[IDX] POST /idp/idx/introspect")
    idx_resp = session.post(
        f"{okta_url}/idp/idx/introspect",
        json={"interactionHandle": interaction_handle},
        headers=IDX_HEADERS,
        timeout=30,
    )
    if debug:
        print(f"[IDX] introspect status: {idx_resp.status_code}")
    idx_resp.raise_for_status()
    idx_state = idx_resp.json()

    # --- Step 3: identify (username) ---
    identify_href, identify_form = _idx_find_remediation(idx_state, "identify")
    if not identify_href:
        raise RuntimeError(
            f"IDX: 'identify' remediation not found after introspect. "
            f"Available: {[r.get('name') for r in idx_state.get('remediation', {}).get('value', [])]}"
        )

    # Some orgs allow password inline with identify; others require a separate step.
    inline_pw = any(v.get("name") == "credentials"
                    for v in (identify_form or {}).get("value", []))
    identify_payload: dict = {"identifier": username, "rememberMe": False}
    if inline_pw:
        identify_payload["credentials"] = {"passcode": password}

    if debug:
        print(f"[IDX] POST identify → {identify_href}  (inline_password={inline_pw})")
    idx_resp = session.post(identify_href, json=identify_payload, headers=IDX_HEADERS, timeout=30)
    if debug:
        print(f"[IDX] identify status: {idx_resp.status_code}")
    idx_resp.raise_for_status()
    idx_state = idx_resp.json()

    # --- Step 4: select password authenticator (if required) ---
    sel_href, sel_form = _idx_find_remediation(idx_state, "select-authenticator-authenticate")
    if sel_href and not inline_pw:
        pw_option = None
        for fv in (sel_form or {}).get("value", []):
            for opt in fv.get("options", []):
                if opt.get("label", "").lower() == "password":
                    pw_option = opt.get("value", {})
                    break
            if pw_option:
                break
        if not pw_option:
            # take first option if password not explicitly found
            for fv in (sel_form or {}).get("value", []):
                opts = fv.get("options", [])
                if opts:
                    pw_option = opts[0].get("value", {})
                    break
        if debug:
            print(f"[IDX] Selecting authenticator: {pw_option}")
        idx_resp = session.post(
            sel_href, json={"authenticator": pw_option}, headers=IDX_HEADERS, timeout=30
        )
        if debug:
            print(f"[IDX] select-authenticator status: {idx_resp.status_code}")
        idx_resp.raise_for_status()
        idx_state = idx_resp.json()

    # --- Step 5: answer password challenge ---
    # IDX uses two sub-steps:
    #   a) challenge  → POST to idp/idx/challenge  (initiate / pick method)
    #   b) challenge/answer → POST to idp/idx/challenge/answer  (submit passcode)
    # Some orgs skip (a) and return challenge/answer directly.
    chal_href, _ = _idx_find_remediation(
        idx_state, "challenge", "challenge/answer", "authenticator-verification-data"
    )
    if chal_href and not inline_pw:
        if debug:
            print(f"[IDX] POST challenge (password) → {chal_href}")
        # First POST may just initiate the challenge (no credentials yet)
        name_found = next(
            (r.get("name") for r in idx_state.get("remediation", {}).get("value", [])
             if r.get("name") in ("challenge", "challenge/answer", "authenticator-verification-data")),
            None,
        )
        if name_found == "challenge":
            # Initiate challenge, then submit answer
            idx_resp = session.post(chal_href, json={}, headers=IDX_HEADERS, timeout=30)
            if debug:
                print(f"[IDX] challenge initiate status: {idx_resp.status_code}")
            idx_resp.raise_for_status()
            idx_state = idx_resp.json()
            # Now look for challenge/answer
            ans_href, _ = _idx_find_remediation(
                idx_state, "challenge/answer", "authenticator-verification-data"
            )
            chal_href = ans_href or chal_href  # fall back to same href if not changed
        if debug:
            print(f"[IDX] POST challenge/answer (password) → {chal_href}")
        idx_resp = session.post(
            chal_href,
            json={"credentials": {"passcode": password}},
            headers=IDX_HEADERS,
            timeout=30,
        )
        if debug:
            print(f"[IDX] challenge/answer status: {idx_resp.status_code}")
        idx_resp.raise_for_status()
        idx_state = idx_resp.json()

    # --- Step 6: MFA (if any step requires it) ---
    idx_state = _handle_idx_mfa(idx_state, session, debug)

    # --- Step 7: read terminal state ---
    session_token = _idx_get_session_token(idx_state)
    if debug:
        print(f"[IDX] Terminal sessionToken obtained: {bool(session_token)}")
        print(f"[IDX] Session cookies after IDX: {[c.name for c in session.cookies]}")

    return session_token, session


def _idx_is_push(chal_form):
    """Return True if the IDX challenge form is for Okta Verify push (not a code entry)."""
    # IDX push authenticators have no 'credentials' value field, or have
    # methodType=push in their currentAuthenticator context.
    for fv in (chal_form or {}).get("value", []):
        if fv.get("name") == "credentials":
            return False  # a credentials field means the user must type a code
    # Also check authenticator context if present
    auth = (chal_form or {}).get("relatesTo", {}) or {}
    if isinstance(auth, dict):
        method = auth.get("value", {}).get("methodTypes", [])
        if isinstance(method, list) and method:
            return method[0] == "push"
    return True  # no credentials field → treat as push / number-challenge


def _idx_print_messages(state):
    """Print any user-facing messages embedded in an IDX state response."""
    for msg_obj in state.get("messages", {}).get("value", []):
        text = msg_obj.get("message", "")
        cls = msg_obj.get("class", "INFO").upper()
        if text:
            prefix = "  ✖  " if cls == "ERROR" else "  ℹ  "
            print(f"{prefix}{text}")


def _handle_idx_mfa(idx_state, session, debug=False):
    """Consume MFA remediations in the IDX state machine.  Returns updated state."""
    enroll_href, _ = _idx_find_remediation(idx_state, "select-authenticator-enroll")
    if enroll_href:
        print("MFA enrollment is required. Please enroll a factor in Okta first.")
        sys.exit(1)

    for _ in range(16):  # guard against infinite loops
        # Available remediation names at each MFA step:
        #   select-authenticator-authenticate  → choose which MFA
        #   challenge                          → initiate challenge (e.g. send push / SMS)
        #   challenge/answer                   → submit the code
        #   challenge-poll                     → poll push approval
        sel_href, sel_form = _idx_find_remediation(idx_state, "select-authenticator-authenticate")
        chal_href, chal_form = _idx_find_remediation(idx_state, "challenge", "challenge/answer")
        poll_href, _ = _idx_find_remediation(idx_state, "challenge-poll")

        if debug:
            avail = [r.get("name") for r in idx_state.get("remediation", {}).get("value", [])]
            print(f"[IDX] MFA loop remediations: {avail}")

        if poll_href:
            # We're inside a push poll — keep polling until approved
            if time.time() > getattr(_handle_idx_mfa, "_deadline", time.time() + PUSH_POLL_TIMEOUT):
                print("\nPush notification timed out.")
                sys.exit(1)
            print(".", end="", flush=True)
            time.sleep(PUSH_POLL_INTERVAL)
            idx_resp = session.post(poll_href, json={}, headers=IDX_HEADERS, timeout=30)
            idx_resp.raise_for_status()
            idx_state = idx_resp.json()
            continue

        if not sel_href and not chal_href:
            break  # no more MFA steps — flow is complete

        if chal_href:
            chal_name = next(
                (r.get("name") for r in idx_state.get("remediation", {}).get("value", [])
                 if r.get("name") in ("challenge", "challenge/answer")),
                "challenge",
            )

            if chal_name == "challenge":
                # POST to /idp/idx/challenge — initiates the challenge
                # (sends push notification, SMS, etc.)
                if debug:
                    print(f"[IDX] POST challenge (initiate) → {chal_href}")
                idx_resp = session.post(chal_href, json={}, headers=IDX_HEADERS, timeout=30)
                if debug:
                    print(f"[IDX] challenge initiate status: {idx_resp.status_code}")
                idx_resp.raise_for_status()
                idx_state = idx_resp.json()
                # Set push deadline marker so the poll branch above can use it
                _handle_idx_mfa._deadline = time.time() + PUSH_POLL_TIMEOUT  # type: ignore[attr-defined]
                # Check next state for push poll vs code entry
                poll_href2, _ = _idx_find_remediation(idx_state, "challenge-poll")
                ans_href, ans_form = _idx_find_remediation(idx_state, "challenge/answer")
                if poll_href2:
                    # Push was initiated — next loop iteration will poll
                    print("Sending push notification to Okta Verify… please approve it.", flush=True)
                elif ans_href:
                    # Code-based MFA (TOTP / SMS / email)
                    _idx_print_messages(idx_state)
                    code = input("  MFA code: ").strip()
                    if debug:
                        print(f"[IDX] POST challenge/answer → {ans_href}")
                    idx_resp = session.post(
                        ans_href,
                        json={"credentials": {"passcode": code}},
                        headers=IDX_HEADERS,
                        timeout=30,
                    )
                    if debug:
                        print(f"[IDX] challenge/answer status: {idx_resp.status_code}")
                    idx_resp.raise_for_status()
                    idx_state = idx_resp.json()
                continue

            else:
                # challenge/answer — direct code submission
                if _idx_is_push(chal_form):
                    # Should not normally happen (push goes via challenge → poll)
                    # but handle gracefully by issuing the challenge first
                    if debug:
                        print(f"[IDX] Push detected at challenge/answer — treating as initiate")
                    idx_resp = session.post(chal_href, json={}, headers=IDX_HEADERS, timeout=30)
                    idx_resp.raise_for_status()
                    idx_state = idx_resp.json()
                    print("Sending push notification to Okta Verify… please approve it.", flush=True)
                    _handle_idx_mfa._deadline = time.time() + PUSH_POLL_TIMEOUT  # type: ignore[attr-defined]
                else:
                    _idx_print_messages(idx_state)
                    code = input("  MFA code: ").strip()
                    if debug:
                        print(f"[IDX] POST challenge/answer → {chal_href}")
                    idx_resp = session.post(
                        chal_href,
                        json={"credentials": {"passcode": code}},
                        headers=IDX_HEADERS,
                        timeout=30,
                    )
                    if debug:
                        print(f"[IDX] challenge/answer status: {idx_resp.status_code}")
                    idx_resp.raise_for_status()
                    idx_state = idx_resp.json()

        elif sel_href:
            # Need to select a non-password MFA authenticator
            options = []
            for fv in (sel_form or {}).get("value", []):
                for opt in fv.get("options", []):
                    if opt.get("label", "").lower() not in ("password",):
                        options.append(opt)
            if not options:
                break
            if len(options) == 1:
                chosen = options[0]
            else:
                print("\n  Available MFA authenticators:\n")
                for i, opt in enumerate(options):
                    print(f"  [{i + 1:>2}]  {opt.get('label', 'unknown')}")
                while True:
                    try:
                        pick = int(input("\n  Select MFA: ").strip()) - 1
                        if 0 <= pick < len(options):
                            chosen = options[pick]
                            break
                    except ValueError:
                        pass
                    print("Invalid selection.")
            if debug:
                print(f"[IDX] Selecting MFA authenticator: {chosen.get('label')}")
            idx_resp = session.post(
                sel_href,
                json={"authenticator": chosen.get("value", {})},
                headers=IDX_HEADERS,
                timeout=30,
            )
            if debug:
                print(f"[IDX] select-authenticator status: {idx_resp.status_code}")
            idx_resp.raise_for_status()
            idx_state = idx_resp.json()

    # Print newline if we were dot-printing push poll
    print("\n", end="", flush=True) if getattr(_handle_idx_mfa, "_deadline", None) else None
    _handle_idx_mfa._deadline = None  # type: ignore[attr-defined]
    return idx_state





def get_saml_assertion(okta_url, app_url, session_token=None, authed_session=None, debug=False):
    """Retrieve the base64-encoded SAML assertion from the Okta AWS app.

    Two modes of operation:

    **IDX mode** (``authed_session`` provided): The caller supplies a
    :class:`requests.Session` that is already authenticated via the IDX
    pipeline (it carries Okta session cookies).  The app URL is fetched
    directly with that session — no sessionCookieRedirect needed.

    **Classic mode** (``session_token`` provided): A fresh session is
    created and two strategies are tried:
    1. Exchange the token via ``/login/sessionCookieRedirect``.
    2. Append the token as ``?sessionToken=`` query parameter.

    Returns ``(saml_assertion, action_url, http_session)``.
    Raises :class:`ValueError` when no SAMLResponse form field is found.
    """
    if authed_session is not None:
        # ---- IDX path: session already carries Okta cookies ----
        session = authed_session
        if debug:
            print(f"[DEBUG] IDX mode: GET {app_url} with pre-authenticated session")
        resp = session.get(app_url, allow_redirects=True, timeout=30)
        if debug:
            print(f"[DEBUG] Final URL after redirects: {resp.url}")
            print(f"[DEBUG] HTTP status: {resp.status_code}")
            print(f"[DEBUG] Redirect chain: {[r.url for r in resp.history]}")
            print(f"[DEBUG] Response HTML (first 3000 chars):\n{resp.text[:3000]}")
        resp.raise_for_status()
        saml_assertion, action_url = _extract_saml_form(resp.text)
        if debug:
            print(f"[DEBUG] SAMLResponse found (IDX direct): {bool(saml_assertion)}")
            print(f"[DEBUG] Form action URL: {action_url}")
        if not saml_assertion:
            raise ValueError(
                "IDX mode: could not find SAMLResponse in Okta app response. "
                "Verify --app-url is the embed link for the AWS SSO app and that "
                "the --client-id belongs to an Okta app with access to it."
            )
        return saml_assertion, action_url, session

    # ---- Classic path: exchange session token for cookie ----
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


def _get_cookie_value(jar, name):
    """Safely get a cookie value from a jar, handling duplicate-name cookies."""
    # Iterate directly to avoid CookieConflictError when the same name
    # appears on multiple domains (e.g. platform-ubid on signin.aws vs awsapps.com)
    for cookie in jar:
        if cookie.name == name:
            return cookie.value
    return None


def submit_saml_to_sso(action_url, saml_assertion, http_session, debug=False):
    """POST the SAML assertion to the AWS SSO ACS endpoint.

    Returns the sso_authn token extracted from the response cookies,
    plus the SSO region inferred from the action_url host.
    Raises ValueError when the token cannot be found.
    """
    if debug:
        print(f"[DEBUG] POSTing SAMLResponse to: {action_url}")

    resp = http_session.post(
        action_url,
        data={"SAMLResponse": saml_assertion},
        allow_redirects=True,
        timeout=30,
    )
    resp.raise_for_status()

    if debug:
        print(f"[DEBUG] SSO POST final URL: {resp.url}")
        print(f"[DEBUG] SSO POST status: {resp.status_code}")
        print(f"[DEBUG] SSO POST redirect chain:")
        for r in resp.history:
            print(f"[DEBUG]   {r.status_code} -> {r.url}")
            try:
                print(f"[DEBUG]   cookies set: {dict(r.cookies)}")
            except Exception:
                print(f"[DEBUG]   cookies set: (could not display — duplicate names)")
        try:
            print(f"[DEBUG] Final response cookies: {dict(resp.cookies)}")
        except Exception:
            print(f"[DEBUG] Final response cookies: (could not display — duplicate names)")
        try:
            print(f"[DEBUG] All session cookies: {dict(http_session.cookies)}")
        except Exception:
            pass
        print(f"[DEBUG] Response headers: {dict(resp.headers)}")
        print(f"[DEBUG] Response HTML (first 3000 chars):\n{resp.text[:3000]}")

    # AWS IAM Identity Center has had TWO different cookie names across portal versions:
    #   - Old portal (pre-2023):  x-amz-sso_authn
    #   - New Access Portal:      aws-usi-authn
    # We check all possible names, and search all jars safely.
    TOKEN_COOKIE_NAMES = ("aws-usi-authn", "x-amz-sso_authn")
    token = None
    token_name_found = None

    # 1. Session jar (most common — set during redirect chain)
    for name in TOKEN_COOKIE_NAMES:
        token = _get_cookie_value(http_session.cookies, name)
        if token:
            token_name_found = name
            if debug:
                print(f"[DEBUG] Found '{name}' in session jar")
            break

    # 2. Final response cookies
    if not token:
        for name in TOKEN_COOKIE_NAMES:
            token = _get_cookie_value(resp.cookies, name)
            if token:
                token_name_found = name
                if debug:
                    print(f"[DEBUG] Found '{name}' in final response cookies")
                break

    # 3. Any hop in the redirect chain
    if not token:
        for r in resp.history:
            for name in TOKEN_COOKIE_NAMES:
                token = _get_cookie_value(r.cookies, name)
                if token:
                    token_name_found = name
                    if debug:
                        print(f"[DEBUG] Found '{name}' in redirect hop: {r.url}")
                    break
            if token:
                break

    # 4. Check query params in the final URL
    if not token:
        import re as _re
        for name in TOKEN_COOKIE_NAMES:
            m = _re.search(rf"[?&]{_re.escape(name)}=([^&]+)", resp.url)
            if m:
                token = m.group(1)
                token_name_found = name
                if debug:
                    print(f"[DEBUG] Found '{name}' in final URL query params")
                break

    # 5. Check response body JSON
    if not token:
        import re as _re
        for name in TOKEN_COOKIE_NAMES:
            m = _re.search(rf'"{_re.escape(name)}"\s*:\s*"([^"]+)"', resp.text)
            if m:
                token = m.group(1)
                token_name_found = name
                if debug:
                    print(f"[DEBUG] Found '{name}' in response body JSON")
                break

    if debug:
        print(f"[DEBUG] Auth token found: {bool(token)} (cookie name: {token_name_found!r})")

    if not token:
        raise ValueError(
            "Could not retrieve SSO auth token (aws-usi-authn / x-amz-sso_authn) after SAML POST.\n"
            "Run with --debug to inspect the full redirect chain and cookies.\n"
            "Verify that the Okta app is configured for AWS IAM Identity Center (SSO)."
        )

    # Infer region from the action_url:
    #   New portal:  eu-west-1.signin.aws.amazon.com/platform/saml/acs/...
    #   Old portal:  portal.sso.eu-west-1.amazonaws.com/...
    import re
    m = re.search(r"([a-z]{2}-[a-z]+-\d)\.(?:signin\.aws|portal\.sso)", action_url)
    sso_region = m.group(1) if m else SSO_DEFAULT_REGION

    if debug:
        print(f"[DEBUG] Inferred SSO region from action_url: {sso_region}")

    # Extract the portal origin from the final redirect URL.
    # e.g. https://d-936777ef92.awsapps.com/start/?workflowResultHandle=UUID
    from urllib.parse import urlparse
    parsed = urlparse(resp.url)
    portal_origin = f"{parsed.scheme}://{parsed.netloc}"

    if debug:
        print(f"[DEBUG] Portal origin (awsapps.com): {portal_origin}")

    return portal_origin, sso_region, http_session


def get_sso_access_token_via_device_auth(portal_origin, sso_region, http_session, debug=False):
    """Get an AWS SSO OIDC access token using the device authorization grant flow.

    Steps:
      1. Register an OIDC public client with AWS SSO OIDC.
      2. Start device authorization — gets a verificationUriComplete URL and deviceCode.
      3. Attempt headless auto-approval by GETting the activation URL with the
         already-authenticated http_session (carries aws-usi-authn cookie).
      4. Poll create_token until approved.  If approval is still pending after
         the headless attempt, print the URL so the user can approve manually
         in their browser (same experience as ``aws sso login``).

    Returns the OIDC ``accessToken`` string (a JWT), valid for ~8 hours.
    """
    start_url = f"{portal_origin}/start/"
    sso_oidc = boto3.client("sso-oidc", region_name=sso_region)

    if debug:
        print(f"[DEBUG] Registering SSO OIDC client for {start_url}")

    # Register a public OIDC client (cached ~90 days by AWS, re-registering is fine)
    client_resp = sso_oidc.register_client(
        clientName="okta-aws",
        clientType="public",
    )
    client_id = client_resp["clientId"]
    client_secret = client_resp["clientSecret"]

    if debug:
        print(f"[DEBUG] OIDC client registered (clientId prefix: {client_id[:12]}…)")

    # Start device authorization
    authz_resp = sso_oidc.start_device_authorization(
        clientId=client_id,
        clientSecret=client_secret,
        startUrl=start_url,
    )
    verify_url = authz_resp["verificationUriComplete"]
    device_code = authz_resp["deviceCode"]
    user_code = authz_resp["userCode"]
    interval = authz_resp.get("interval", 5)
    expires_in = authz_resp.get("expiresIn", 600)

    if debug:
        print(f"[DEBUG] Device authorization started:")
        print(f"[DEBUG]   userCode:  {user_code}")
        print(f"[DEBUG]   verifyUrl: {verify_url}")
        print(f"[DEBUG]   interval:  {interval}s  expiresIn: {expires_in}s")

    # --- Poll create_token, prompting the user to approve in their local browser ---
    # The verification URL is an AWS portal SPA (awsapps.com).  Approval requires
    # a browser session already authenticated to that portal — it cannot be
    # completed headlessly from Python.
    #
    # In the VS Code integrated terminal the URL below is rendered as a clickable
    # link that opens in your LOCAL browser (not the server's), even on a remote
    # SSH / VS Code Server session.  If you are already logged into the AWS portal
    # in that browser, a single "Allow" click completes the flow.

    deadline = time.time() + expires_in
    prompted = False

    while time.time() < deadline:
        try:
            token_resp = sso_oidc.create_token(
                clientId=client_id,
                clientSecret=client_secret,
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=device_code,
            )
            if prompted:
                print()  # newline after dot-animation
            if debug:
                print("[DEBUG] SSO OIDC access token obtained successfully.")
            return token_resp["accessToken"]

        except sso_oidc.exceptions.AuthorizationPendingException:
            if not prompted:
                _print_box(
                    "AWS SSO authorization required",
                    [
                        "Open this URL in your browser  (Ctrl+click works in VS Code):",
                        "",
                        verify_url,
                        "",
                        f"User code: {user_code}  (pre-filled in the URL above)",
                        "",
                        "Click  Allow  in the portal, then return here.",
                    ],
                )
                print("Waiting for approval", end="", flush=True)
                prompted = True
            else:
                print(".", end="", flush=True)
            time.sleep(interval)

        except sso_oidc.exceptions.SlowDownException:
            interval = min(interval + 5, 30)
            time.sleep(interval)

        except Exception as exc:
            if debug:
                print(f"\n[DEBUG] create_token error: {type(exc).__name__}: {exc}")
            time.sleep(interval)

    raise RuntimeError(
        f"Device authorization not approved within {expires_in} seconds. "
        "Re-run the script and approve the URL shown above."
    )


def list_sso_accounts_and_roles(access_token, sso_region, debug=False):
    """Return a flat list of dicts with keys: account_id, account_name, role_name.

    Uses the boto3 ``sso`` client with the OIDC ``access_token`` obtained from
    :func:`get_sso_access_token_via_device_auth`.  This is the same mechanism
    used by the AWS CLI ``aws sso login`` flow.
    """
    from botocore.config import Config as BotocoreConfig

    sso = boto3.client(
        "sso",
        region_name=sso_region,
        config=BotocoreConfig(retries={"max_attempts": 12, "mode": "adaptive"}),
    )
    entries = []

    if debug:
        print(f"[DEBUG] boto3 sso.list_accounts (region={sso_region})")

    # Collect accounts first, then query roles per account with a small delay
    # to avoid hitting the SSO API rate limit (TooManyRequestsException).
    accounts = []
    paginator = sso.get_paginator("list_accounts")
    for page in paginator.paginate(accessToken=access_token):
        accounts.extend(page.get("accountList", []))

    for acct in accounts:
        acct_id = acct["accountId"]
        acct_name = acct.get("accountName", acct_id)
        if debug:
            print(f"[DEBUG]   account: {acct_id}  ({acct_name})")
        role_paginator = sso.get_paginator("list_account_roles")
        for role_page in role_paginator.paginate(accountId=acct_id, accessToken=access_token):
            for role in role_page.get("roleList", []):
                entries.append({
                    "account_id": acct_id,
                    "account_name": acct_name,
                    "role_name": role["roleName"],
                })
        # Brief pause between accounts to stay within SSO API rate limits
        time.sleep(0.3)

    return entries


def get_sso_role_credentials(access_token, sso_region, account_id, role_name, debug=False):
    """Get temporary credentials via the boto3 ``sso`` client.

    Uses the OIDC ``access_token`` from :func:`get_sso_access_token_via_device_auth`.
    Returns a dict with keys matching the STS Credentials format:
    ``AccessKeyId``, ``SecretAccessKey``, ``SessionToken``, ``Expiration``.
    """
    import datetime
    sso = boto3.client("sso", region_name=sso_region)

    if debug:
        print(f"[DEBUG] boto3 sso.get_role_credentials: account={account_id} role={role_name}")

    resp = sso.get_role_credentials(
        accountId=account_id,
        roleName=role_name,
        accessToken=access_token,
    )
    rc = resp["roleCredentials"]
    return {
        "AccessKeyId": rc["accessKeyId"],
        "SecretAccessKey": rc["secretAccessKey"],
        "SessionToken": rc["sessionToken"],
        "Expiration": datetime.datetime.utcfromtimestamp(rc["expiration"] / 1000),
    }


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
        max_name = max(len(groups[aid][0]["account_name"]) for aid in account_ids)
        print("\n  Available AWS accounts:\n")
        for i, acct_id in enumerate(account_ids):
            acct_name = groups[acct_id][0]["account_name"]
            count = len(groups[acct_id])
            print(f"  [{i + 1:>2}]  {acct_id}  {acct_name:<{max_name}}  ({count} role{'s' if count != 1 else ''})")
        while True:
            try:
                idx = int(input("\n  Account: ").strip()) - 1
                if 0 <= idx < len(account_ids):
                    chosen_account = account_ids[idx]
                    break
            except ValueError:
                pass
            print("  Invalid selection — enter a number from the list.")

    account_entries = groups[chosen_account]
    if len(account_entries) == 1:
        return account_entries[0]

    print(f"\n  Available roles for {account_entries[0]['account_name']} ({chosen_account}):\n")
    for i, e in enumerate(account_entries):
        print(f"  [{i + 1:>2}]  {e['role_name']}")

    while True:
        try:
            idx = int(input("\n  Role: ").strip()) - 1
            if 0 <= idx < len(account_entries):
                return account_entries[idx]
        except ValueError:
            pass
        print("  Invalid selection — enter a number from the list.")


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
  okta-aws --client-id 0oa...           Use Okta Identity Engine (IDX) auth
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
    parser.add_argument("--client-id",
                        help="Okta OIDC application client ID — enables Identity Engine (IDX) "
                             "authentication instead of the deprecated /api/v1/authn API. "
                             "Set 'client_id' in ~/.okta-aws to avoid passing it every time.")
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
    client_id = cf("client_id", args.client_id)  # optional — enables IDX flow
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

    # -----------------------------------------------------------------------
    # Authentication: IDX (Identity Engine) when --client-id is set, else
    # fall back to the classic /api/v1/authn pipeline.
    # -----------------------------------------------------------------------
    idx_session = None   # requests.Session pre-authenticated via IDX
    session_token = None

    if client_id:
        # ---- Okta Identity Engine (IDX) path ----
        print("Using Okta Identity Engine (IDX) authentication…")
        try:
            session_token, idx_session = okta_idx_authn(
                okta_url, client_id, username, password, debug=args.debug
            )
        except requests.HTTPError as exc:
            sc = exc.response.status_code if exc.response is not None else "?"
            if sc == 400:
                print(
                    f"IDX authentication failed (HTTP 400). "
                    f"Check --client-id is a Native/SPA app in this Okta org.\n"
                    f"Response: {exc.response.text[:300]}"
                )
            elif sc == 401:
                print("IDX authentication failed: invalid credentials.")
            else:
                print(f"IDX authentication failed: HTTP {sc}.")
            sys.exit(1)
        except RuntimeError as exc:
            print(f"IDX authentication failed: {exc}")
            sys.exit(1)
        _ok("Okta authentication successful.")
    else:
        # ---- Classic /api/v1/authn path ----
        if args.debug:
            print("[DEBUG] No --client-id set; using classic /api/v1/authn")
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

        _ok("Okta authentication successful.")

    # --- SAML assertion ---
    _step("Retrieving SAML assertion from AWS app…")
    try:
        saml_assertion, action_url, http_session = get_saml_assertion(
            okta_url, app_url,
            session_token=session_token,
            authed_session=idx_session,
            debug=args.debug,
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
        _step("Completing AWS SSO login…")
        try:
            portal_origin, inferred_sso_region, sso_http_session = submit_saml_to_sso(
                action_url, saml_assertion, http_session, debug=args.debug
            )
        except Exception as exc:
            print(f"\n  ✖  SSO login failed: {exc}")
            sys.exit(1)

        # User-specified or config sso_region takes priority over inferred
        effective_sso_region = sso_region or inferred_sso_region
        _step(f"Requesting device authorization token  [{effective_sso_region}]")
        try:
            sso_access_token = get_sso_access_token_via_device_auth(
                portal_origin, effective_sso_region, sso_http_session, debug=args.debug
            )
        except Exception as exc:
            print(f"\n  ✖  Failed to obtain SSO access token: {exc}")
            sys.exit(1)

        _step("Loading accounts and roles…")
        try:
            entries = list_sso_accounts_and_roles(
                sso_access_token, effective_sso_region, debug=args.debug
            )
        except Exception as exc:
            print(f"\n  ✖  Failed to list SSO accounts/roles: {exc}")
            sys.exit(1)

        if not entries:
            print("\n  ✖  No accounts or roles found. Check your IAM Identity Center assignments.")
            sys.exit(1)

        selected = select_sso_account_and_role(entries, args.account, args.role)
        _step(f"Assuming  {selected['account_name']} ({selected['account_id']}) / {selected['role_name']}")

        try:
            credentials = get_sso_role_credentials(
                sso_access_token, effective_sso_region,
                selected["account_id"], selected["role_name"],
                debug=args.debug,
            )
        except Exception as exc:
            print(f"\n  ✖  Failed to get SSO role credentials: {exc}")
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
        _step(f"Assuming  {selected_role['role_arn']}")

        try:
            credentials = assume_role_with_saml(selected_role, saml_assertion, duration, region)
        except Exception as exc:
            print(f"Failed to assume role: {exc}")
            sys.exit(1)

    # --- Write credentials ---
    write_aws_credentials(credentials, profile, region)

    expiry = credentials["Expiration"].strftime("%Y-%m-%d %H:%M:%S UTC")
    rule = "─" * 68
    print(f"\n{rule}")
    _ok(f"Credentials written  →  profile '{profile}'")
    print(f"     Expires:  {expiry}")
    print(f"     Path:     {AWS_CREDENTIALS_PATH}")
    print()
    if profile == "default":
        print("     aws s3 ls")
    else:
        print(f"     aws --profile {profile} s3 ls")
        print(f"     export AWS_PROFILE={profile}")
    print(f"{rule}\n")


if __name__ == "__main__":
    main()
