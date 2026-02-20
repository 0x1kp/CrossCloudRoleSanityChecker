# Cross-Cloud Role Sanity Checker

A command-line security preflight tool that validates AWS IAM roles and GCP service accounts before cross-cloud data transfers. It checks for overly permissive permissions, unsafe trust policies, public bucket exposure, missing encryption, and dangerous service account configurations, then produces a structured report of all findings.

The intended use case is running this tool as a gate before operations like AWS DataSync jobs that target GCP, where a misconfigured role on either side could lead to privilege escalation, data exposure, or unauthorized access.

---

## Table of Contents

- [What It Checks](#what-it-checks)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Security Considerations](#security-considerations)
- [Required IAM Permissions](#required-iam-permissions)
- [Limitations](#limitations)
- [Running Tests](#running-tests)
- [CI/CD](#cicd)

---

## What It Checks

The tool runs eight checks total: four against AWS and four against GCP.

### AWS Checks

| Check | Source Function | What It Detects |
|-------|----------------|-----------------|
| IAM role permissions | `check_iam_role_permissions` | Wildcard actions (`*` or `service:*`) in any managed policy attached to the role |
| Trust policy | `check_trust_policy` | Assume-role trust policies that grant access to all AWS principals (`"AWS": "*"`) or all services (`"Service": "*"`) |
| S3 bucket encryption | `check_s3_bucket_encryption` | S3 buckets without server-side encryption enabled |
| S3 public access block | `check_s3_public_access` | Account-level S3 public access block settings that are not fully enforced |

### GCP Checks

| Check | Source Function | What It Detects |
|-------|----------------|-----------------|
| Service account IAM bindings | `check_gcp_service_account_permissions` | Project-level IAM bindings granting the service account a dangerous role (`roles/owner`, `roles/editor`, `roles/iam.securityAdmin`, `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountKeyAdmin`, `roles/iam.serviceAccountTokenCreator`, `roles/resourcemanager.projectIamAdmin`, `roles/resourcemanager.organizationAdmin`) |
| Service account keys | `check_service_account_keys` | User-managed service account keys, which are a security risk because they do not auto-rotate and can be exfiltrated |
| GCS bucket public access | `check_gcs_bucket_public_access` | GCS bucket IAM bindings that include `allUsers` or `allAuthenticatedUsers` |
| GCS bucket encryption | `check_gcs_bucket_encryption` | GCS buckets not configured with a Customer-Managed Encryption Key (CMEK) |

Each check runs independently. If one check fails (for example, due to missing permissions), the remaining checks still execute and the failure is captured as an `ERROR:` line item in the report.

---

## Project Structure

```
CrossCloudRoleSanityChecker/
  .github/
    workflows/
      ci.yml                 # GitHub Actions CI pipeline
  src/
    main.py                  # CLI entry point and check orchestration
    config.py                # Configuration constants (regions, bucket names, project IDs)
    aws_checks.py            # AWS IAM and S3 security checks
    gcp_checks.py            # GCP IAM and GCS security checks
    reporting.py             # Markdown and JSON report generation
  tests/
    test_aws_checks.py       # Unit tests for AWS checks (17 tests)
    test_gcp_checks.py       # Unit tests for GCP checks (18 tests)
  .gitignore
  requirements.txt
  README.md
```

---

## Prerequisites

- **Python 3.10 or later.** The codebase uses `list[str]` and `set[str]` built-in generic syntax, which requires Python 3.9+. Python 3.10+ is recommended.

- **AWS credentials configured.** The tool uses `boto3`, which reads credentials from the standard AWS credential chain: environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), the `~/.aws/credentials` file, or an IAM instance profile. Configure a profile with `aws configure` if you have not already done so.

- **GCP Application Default Credentials configured.** The tool uses `google.auth.default()` to obtain credentials. Set this up by running `gcloud auth application-default login`, or by setting the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the path of a service account JSON key file.

---

## Installation

Clone the repository and install the Python dependencies:

```bash
git clone <repository-url>
cd CrossCloudRoleSanityChecker
pip install -r requirements.txt
```

The dependencies are:

| Package | Purpose |
|---------|---------|
| `boto3` | AWS SDK for IAM and S3 API calls |
| `google-cloud-storage` | GCS bucket inspection |
| `google-cloud-iam` | GCP IAM operations |
| `google-api-python-client` | Cloud Resource Manager and IAM Admin API access |
| `google-auth` | Application Default Credentials resolution |
| `google-auth-httplib2` | HTTP transport for Google auth |
| `google-auth-oauthlib` | OAuth2 authentication flow support |

---

## Configuration

Before running the tool, edit `src/config.py` to match your environment:

```python
# AWS Configuration
AWS_REGION = "us-east-1"              # AWS region for API calls
S3_BUCKET_NAME = "my-source-bucket"   # S3 bucket to check encryption and public access
AWS_PROFILE = "secure-sync"           # AWS CLI profile name

# GCP Configuration
GCP_PROJECT_ID = "my-gcp-project"     # Fallback project ID if not extractable from the service account email
GCS_BUCKET_NAME = "my-target-bucket"  # GCS bucket to check public access and CMEK
GOOGLE_APPLICATION_CREDENTIALS = "/path/to/your/service_account.json"

# Reporting Configuration
OUTPUT_FORMAT = "markdown"            # Default output format: 'markdown' or 'json'
ENABLE_STRICT_MODE = True             # Enforce strict IAM role policy rules
```

**Note on GCP project ID resolution:** The tool extracts the project ID from the GCP service account email address (the standard format is `NAME@PROJECT_ID.iam.gserviceaccount.com`). If the email does not follow this format (for example, Compute Engine default service accounts use `NUMBER-compute@developer.gserviceaccount.com`), the tool falls back to `GCP_PROJECT_ID` from `config.py`.

---

## Usage

Run the tool from the repository root:

```bash
python src/main.py \
  --aws-role my-data-sync-role \
  --gcp-account my-svc-account@my-gcp-project.iam.gserviceaccount.com \
  --output-format markdown
```

### Command-Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--aws-role` | Yes | -- | The name of the AWS IAM role to inspect (not the ARN, just the role name) |
| `--gcp-account` | Yes | -- | The full email address of the GCP service account to inspect |
| `--output-format` | No | `markdown` | Report format: `markdown` for human-readable output, `json` for machine-readable output |

### Example Run

```
$ python src/main.py \
    --aws-role DataSyncRole \
    --gcp-account sync-sa@my-project.iam.gserviceaccount.com \
    --output-format markdown

Running AWS checks...
  Checking IAM role permissions...
  Checking trust policy...
  Checking S3 bucket encryption...
  Checking S3 public access block...
Running GCP checks...
  Checking service account IAM bindings...
  Checking service account keys...
  Checking GCS bucket public access...
  Checking GCS bucket encryption...
# Security Preflight Check Report
## AWS IAM Role Issues
- Policy AdminAccess grants overly permissive access: *
- Trust policy allows all principals (*)
## GCP IAM Service Account Issues
- Service account sync-sa@my-project.iam.gserviceaccount.com has dangerous role 'roles/editor' on project my-project
- GCS bucket my-target-bucket does not use a Customer-Managed Encryption Key (CMEK)
```

If all checks pass cleanly, the report sections show `- None` under each heading.

---

## Output Formats

### Markdown (default)

Produces a human-readable report printed to stdout with headings for AWS and GCP issues. Each issue is a bullet point. Suitable for pasting into pull requests, Slack messages, or audit logs.

### JSON

Produces a JSON object with two keys, `aws` and `gcp`, each containing an array of issue strings:

```json
{
  "aws": [
    "Policy AdminAccess grants overly permissive access: *"
  ],
  "gcp": [
    "GCS bucket my-target-bucket does not use a Customer-Managed Encryption Key (CMEK)"
  ]
}
```

Suitable for piping into `jq`, ingesting into monitoring systems, or processing in automation scripts. Use `--output-format json` to enable.

---

## Security Considerations

This tool is designed to be safe to run against production cloud environments.

**Read-only API calls only.** Every AWS and GCP API call made by this tool is a read operation. The tool never creates, modifies, or deletes any cloud resource. The specific API methods used are: `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:GetRole`, `s3:GetBucketEncryption`, `s3control:GetPublicAccessBlock`, `sts:GetCallerIdentity`, `cloudresourcemanager.projects.getIamPolicy`, `iam.projects.serviceAccounts.keys.list`, GCS `bucket.get_iam_policy`, and GCS `bucket.default_kms_key_name`.

**No credential storage.** The tool does not store, cache, log, or transmit credentials. It relies entirely on the ambient AWS credential chain (environment variables, `~/.aws/credentials`, or instance profile) and GCP Application Default Credentials already configured in the runtime environment.

**No data access.** The tool does not read, copy, list, or transmit any objects or data from S3 or GCS buckets. It inspects only IAM policies and bucket-level configuration metadata.

**No network egress.** All output is printed to stdout. The tool does not send results to any external service, webhook, endpoint, or telemetry system.

**No privilege escalation.** The tool requires only read-level IAM permissions. It does not request, assume, or use write permissions on any resource. See the [Required IAM Permissions](#required-iam-permissions) section for the exact list.

**Fault isolation.** Each of the eight checks runs independently inside a try/except wrapper. A failure in one check (for example, a permissions error on `s3control:GetPublicAccessBlock`) does not prevent the remaining seven checks from completing. Failures appear as `ERROR:` prefixed entries in the report.

---

## Required IAM Permissions

### AWS

The AWS credentials used to run this tool must have the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "s3:GetEncryptionConfiguration",
        "s3control:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

This is strictly read-only. None of these actions allow modification of any AWS resource.

### GCP

The GCP credentials used to run this tool must have the following IAM permissions on the target project:

| Permission | Typical Role | Used By |
|------------|-------------|---------|
| `resourcemanager.projects.getIamPolicy` | `roles/browser` or `roles/viewer` | `check_gcp_service_account_permissions` |
| `iam.serviceAccountKeys.list` | `roles/iam.serviceAccountViewer` | `check_service_account_keys` |
| `storage.buckets.getIamPolicy` | `roles/storage.admin` or custom | `check_gcs_bucket_public_access` |
| `storage.buckets.get` | `roles/storage.objectViewer` or above | `check_gcs_bucket_encryption` |

All of these are read-only permissions.

---

## Limitations

- **GCP checks inspect project-level IAM bindings only.** Organization-level and folder-level IAM bindings are not evaluated. A service account could inherit dangerous roles from a higher level in the GCP resource hierarchy without this tool detecting it.

- **AWS checks cover attached managed policies only.** Inline policies embedded directly on IAM roles are not inspected. A role with no managed policy attachments but a permissive inline policy will not be flagged.

- **No recursive policy evaluation.** The tool checks for wildcard actions at face value. It does not evaluate effective permissions through IAM permission boundaries, AWS Service Control Policies (SCPs), or resource-based policies. A role may appear clean but still have broad access through other policy mechanisms.

- **Single-role scope.** The tool checks one AWS IAM role and one GCP service account per invocation. It does not scan an entire AWS account or GCP project for all roles and service accounts.

- **No credential validation.** The tool assumes that valid credentials are already configured and that the specified role name and service account email exist. If they do not, the corresponding checks will fail with API errors captured in the report.

- **S3 public access check is account-level.** The `check_s3_public_access` function checks the account-level S3 public access block configuration, not the individual bucket-level settings. A bucket could have its own public access settings that differ from the account defaults.

- **GCS CMEK check is metadata-only.** The tool checks whether `default_kms_key_name` is set on the bucket. It does not verify that the referenced KMS key is valid, active, or accessible.

- **No conditional binding evaluation.** GCP IAM bindings may include IAM Conditions that restrict when a role grant is active. The tool does not evaluate these conditions and will flag a conditional `roles/owner` binding the same as an unconditional one.

---

## Running Tests

The test suite uses `pytest` with `unittest.mock` to mock all AWS and GCP API calls. No cloud credentials are required to run tests.

Install pytest and run the full suite:

```bash
pip install pytest
pytest tests/ -v
```

Expected output:

```
tests/test_aws_checks.py    - 17 tests (IAM permissions, trust policy, S3 encryption, S3 public access)
tests/test_gcp_checks.py    - 18 tests (project ID extraction, IAM bindings, SA keys, GCS public access, GCS encryption)

35 passed
```

To run tests for a single module:

```bash
pytest tests/test_aws_checks.py -v
pytest tests/test_gcp_checks.py -v
```

---

## CI/CD

The repository includes a GitHub Actions workflow at `.github/workflows/ci.yml` that runs on every push and pull request to the `main` branch.

The pipeline:

1. Checks out the repository
2. Sets up Python 3.11 with pip dependency caching
3. Installs production dependencies from `requirements.txt` and `pytest`
4. Runs `pytest tests/`

No cloud credentials are needed in CI because all tests use mocked API clients.
