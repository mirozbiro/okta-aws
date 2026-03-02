# okta-aws

A CLI-only Python tool that authenticates to an **Okta** portal (including MFA),
navigates to your **AWS SAML app**, presents all available accounts and roles,
assumes the selected role, and writes temporary AWS credentials so you can use
the AWS CLI immediately.

If you have multiple AWS app tiles in Okta (e.g. "AWS Prod", "AWS Dev",
"AWS Staging") the tool automatically discovers them after login and lets you
choose — **no hardcoded app URL required**.

---

## Prerequisites

- Python 3.8 or later
- An Okta account with access to an AWS SAML application
- The AWS CLI (optional but the whole point)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/mirozbiro/okta-aws.git
cd okta-aws

# Install the package and its dependencies (creates the 'assume' command)
pip install -e .
```

> **Tip — run it anywhere as `assume`**
>
> The `pip install -e .` command above registers two global commands:
> `assume` and `okta-aws`.  After installation you can type `assume` in any
> terminal, from any directory, just like `pip` or `git`.
>
> If you prefer not to install it, you can still run it directly:
> ```bash
> pip install -r requirements.txt
> python /path/to/okta-aws/okta_aws.py
> ```

---

## Configuration

Copy the example config file and fill in your values:

```bash
cp config.example ~/.okta-aws
```

Edit `~/.okta-aws`:

```ini
[default]
okta_url = https://yourcompany.okta.com
username = you@yourcompany.com
profile  = okta
region   = us-east-1
```

### `app_url` — optional

`app_url` is **not required**.  When omitted the tool automatically discovers
all AWS app tiles assigned to your Okta user after login and prompts you to
pick one.  If you only have one AWS app it is selected silently.

This is the recommended setup for most users — no URL needed, and it works
even if you have multiple AWS environments.

If you prefer to pin a specific app and skip the selection step every time,
add it to your config:

```ini
app_url = https://yourcompany.okta.com/home/amazon_aws/0oa.../272
```

#### Finding the App Embed Link (only needed if you want to pin an app)

1. In the Okta Admin Console go to **Applications → \<your AWS app\>**.
2. Open the **General** tab.
3. Copy the **App Embed Link** — this is your `app_url`.

### Identity Engine (IDX) authentication — optional

If your Okta org uses **Identity Engine** (the newer Okta platform), add your
OIDC Native/SPA app's client ID to get a more robust authentication flow:

```ini
client_id = 0oa...
```

You can also pass it on the command line with `--client-id`.

---

## Usage

```
assume [OPTIONS]
```

(You can also use `okta-aws` as the command name — they are identical.)

### Options

| Flag | Description |
|------|-------------|
| `--config PATH` | Config file path (default: `~/.okta-aws`) |
| `--profile NAME` | AWS credentials profile to write (default: `okta`) |
| `--username EMAIL` | Okta username (overrides config) |
| `--okta-url URL` | Okta organization URL (overrides config) |
| `--app-url URL` | Okta AWS app embed link — skips app-discovery prompt (overrides config) |
| `--client-id ID` | Okta OIDC client ID — enables Identity Engine (IDX) auth (overrides config) |
| `--region REGION` | AWS region written to credentials (default: `us-east-1`) |
| `--sso-region REGION` | AWS SSO / IAM Identity Center region (default: inferred from app) |
| `--duration SECS` | Session duration in seconds (default: from SAML assertion) |
| `--account ID` | Pre-select AWS account ID — skips account prompt |
| `--role NAME` | Pre-select IAM role name — skips role prompt |
| `--debug` | Print verbose debug information (URLs, HTML, SAML XML) |

### Examples

```bash
# Interactive — use values from ~/.okta-aws (auto-discovers your AWS app)
assume

# Store credentials under the 'dev' profile
assume --profile dev

# Skip all prompts by pre-selecting account and role
assume --account 123456789012 --role MyDeployRole

# Override the Okta username for this run
assume --username admin@corp.com

# Use a specific AWS app URL (skips app-discovery)
assume --app-url https://corp.okta.com/home/amazon_aws/0oa.../272

# Use Okta Identity Engine auth
assume --client-id 0oa...
```

---

## Typical session

```
Authenticating to https://corp.okta.com as alice@corp.com…
Password:
MFA verification required.

Available MFA factors:
  [1] TOTP Authenticator (GOOGLE)
  [2] Okta Verify Push (OKTA)

Select MFA factor: 1
Enter TOTP code: 123456
  ✔  Okta authentication successful.
  →  Discovering AWS app tiles from Okta…

Available AWS apps:

  [ 1]  AWS SSO Prod
  [ 2]  AWS SSO Dev

  Select AWS app: 1
  ✔  AWS app: AWS SSO Prod
  →  Retrieving SAML assertion from AWS app…

Available AWS accounts:
  [1] 111111111111  (2 roles)
  [2] 222222222222  (1 role)

Select account: 1

Available roles for account 111111111111:
  [1] Developer
       arn:aws:iam::111111111111:role/Developer
  [2] ReadOnly
       arn:aws:iam::111111111111:role/ReadOnly

Select role: 1

Assuming role: arn:aws:iam::111111111111:role/Developer

────────────────────────────────────────────────────────────────────────
  ✔  Credentials written  →  profile 'okta'
     Expires:  2026-02-26 10:00:00 UTC
     Path:     /home/alice/.aws/credentials

     aws --profile okta s3 ls
     export AWS_PROFILE=okta
────────────────────────────────────────────────────────────────────────
```

---

## Supported MFA factors

| Factor | Notes |
|--------|-------|
| TOTP Authenticator (Google/Microsoft/Okta) | Enter 6-digit code |
| Okta Verify Push | Approve on your phone; script polls automatically |
| SMS | Code sent by text message |
| Email | Code sent by email |
| Voice call | Code delivered by phone call |

---

## Credentials file

Credentials are written to `~/.aws/credentials` under the chosen profile and
expire at the time shown.  The file is created with `0600` permissions.

```ini
[okta]
aws_access_key_id     = ASIA...
aws_secret_access_key = ...
aws_session_token     = ...
region                = us-east-1
```

Run any AWS CLI command with:

```bash
# With explicit profile
aws --profile okta s3 ls

# Or export so all commands use it
export AWS_PROFILE=okta
aws s3 ls
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `No AWS app tiles found in your Okta org` | Your user has no AWS apps assigned; ask your Okta admin, or set `app_url` manually |
| `Could not find SAMLResponse` | Wrong `app_url`; ensure it is the Embed Link, not the app tile URL |
| `No AWS roles found in SAML assertion` | SAML app not configured to send Role attribute; contact your Okta admin |
| `HTTP 401` | Wrong username or password |
| `HTTP 429` | Okta rate-limited you; wait a minute and retry |
| `Failed to assume role` | Your IAM trust policy may not allow this principal; check with your AWS admin |