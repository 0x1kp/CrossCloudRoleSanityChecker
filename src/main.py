import argparse
from collections.abc import Callable
from typing import Any
import config
from aws_checks import (
    check_iam_role_permissions,
    check_trust_policy,
    check_s3_bucket_encryption,
    check_s3_public_access,
)
from gcp_checks import (
    check_gcp_service_account_permissions,
    check_service_account_keys,
    check_gcs_bucket_public_access,
    check_gcs_bucket_encryption,
)
from reporting import generate_report


def _run_check(description: str, check_fn: Callable[..., list[str]], *args: Any) -> list[str]:
    """Run a single security check with error handling.

    Args:
        description: Human-readable label for the check, printed to stdout.
        check_fn: Callable that performs the check and returns list[str].
        *args: Arguments forwarded to check_fn.

    Returns:
        A list of issue strings from the check, or an error message on failure.
    """
    print(f"  {description}...")
    try:
        return check_fn(*args)
    except Exception as e:
        return [f"ERROR: {description} failed: {e}"]


def main() -> None:
    """Run cross-cloud IAM security preflight checks and print the report.

    Parses CLI arguments for AWS role name, GCP service account email,
    and output format, then executes all AWS and GCP checks and prints results.
    """
    parser = argparse.ArgumentParser(description='Cross-cloud IAM Precheck Tool')
    parser.add_argument('--aws-role', required=True, help='AWS IAM Role name')
    parser.add_argument('--gcp-account', required=True, help='GCP Service Account email')
    parser.add_argument('--output-format', choices=['markdown', 'json'], default='markdown')
    args = parser.parse_args()

    # --- AWS checks ---
    print("Running AWS checks...")
    aws_issues: list[str] = []
    aws_issues.extend(_run_check(
        "Checking IAM role permissions", check_iam_role_permissions, args.aws_role
    ))
    aws_issues.extend(_run_check(
        "Checking trust policy", check_trust_policy, args.aws_role
    ))
    aws_issues.extend(_run_check(
        "Checking S3 bucket encryption", check_s3_bucket_encryption, config.S3_BUCKET_NAME
    ))
    aws_issues.extend(_run_check(
        "Checking S3 public access block", check_s3_public_access, config.S3_BUCKET_NAME
    ))

    # --- GCP checks ---
    print("Running GCP checks...")
    gcp_issues: list[str] = []
    gcp_issues.extend(_run_check(
        "Checking service account IAM bindings",
        check_gcp_service_account_permissions, args.gcp_account
    ))
    gcp_issues.extend(_run_check(
        "Checking service account keys",
        check_service_account_keys, args.gcp_account
    ))
    gcp_issues.extend(_run_check(
        "Checking GCS bucket public access",
        check_gcs_bucket_public_access, config.GCS_BUCKET_NAME
    ))
    gcp_issues.extend(_run_check(
        "Checking GCS bucket encryption",
        check_gcs_bucket_encryption, config.GCS_BUCKET_NAME
    ))

    report = generate_report(aws_issues, gcp_issues, output_format=args.output_format)
    print(report)

if __name__ == '__main__':
    main()
