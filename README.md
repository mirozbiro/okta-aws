# okta-aws

A CLI-only Python tool that authenticates to an **Okta** portal (including MFA),
navigates to the configured **AWS SAML app**, presents all available accounts and
roles, assumes the selected role, and writes temporary AWS credentials so you can
use the AWS CLI immediately.

---

## Prerequisites

- Python 3.8 or later
- An Okta account with access to the AWS SAML application
- The AWS CLI (optional but the whole point)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/mirozbiro/okta-aws.git
cd okta-aws

# Install Python dependencies
pip install -r requirements.txt

# Make the script executable (Linux / macOS)
chmod +x okta_aws.py
```

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
app_url  = https://yourcompany.okta.com/home/amazon_aws/0oa.../272
username = you@yourcompany.com
profile  = okta
region   = us-east-1
```

### Finding the App Embed Link

1. In the Okta Admin Console go to **Applications → \<your AWS app\>**.
2. Open the **General** tab.
3. Copy the **App Embed Link** — this is your `app_url`.

---

## Usage

```
python okta_aws.py [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--config PATH` | Config file path (default: `~/.okta-aws`) |
| `--profile NAME` | AWS credentials profile to write (default: `okta`) |
| `--username EMAIL` | Okta username (overrides config) |
| `--okta-url URL` | Okta organization URL (overrides config) |
| `--app-url URL` | Okta AWS app embed link (overrides config) |
| `--region REGION` | AWS region (default: `us-east-1`) |
| `--duration SECS` | Session duration in seconds (default: from SAML assertion) |
| `--account ID` | Pre-select AWS account ID — skips account prompt |
| `--role NAME` | Pre-select IAM role name — skips role prompt |

### Examples

```bash
# Interactive — use values from ~/.okta-aws
python okta_aws.py

# Store credentials under the 'dev' profile
python okta_aws.py --profile dev

# Skip all prompts by pre-selecting account and role
python okta_aws.py --account 123456789012 --role MyDeployRole

# Override the Okta username for this run
python okta_aws.py --username admin@corp.com
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
Okta authentication successful.
Retrieving SAML assertion from AWS app…

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

Credentials written to profile 'okta' (/home/alice/.aws/credentials)
Expires: 2026-02-26 10:00:00 UTC

  aws --profile okta s3 ls
  # or: export AWS_PROFILE=okta
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
| `Could not find SAMLResponse` | Wrong `app_url`; ensure it is the Embed Link, not the app tile URL |
| `No AWS roles found in SAML assertion` | SAML app not configured to send Role attribute; contact your Okta admin |
| `HTTP 401` | Wrong username or password |
| `HTTP 429` | Okta rate-limited you; wait a minute and retry |
| `Failed to assume role` | Your IAM trust policy may not allow this principal; check with your AWS admin |