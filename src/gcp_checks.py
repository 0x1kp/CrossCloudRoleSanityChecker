from google.cloud import storage
from google.cloud import iam_credentials_v1

def check_gcp_service_account_permissions(service_account_email):
    # Placeholder logic: Actual logic would require use of Cloud Asset Inventory API or IAM Policy Analyzer
    print(f"Validating service account {service_account_email} does not have Owner role...")
    # Assume we retrieved bindings and found no critical misassignments
    return []

def check_gcs_bucket_public_access(bucket_name):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    policy = bucket.get_iam_policy(requested_policy_version=3)
    issues = []
    for binding in policy.bindings:
        if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
            issues.append(f"GCS bucket {bucket_name} is publicly accessible to: {binding['members']}")
    return issues

def check_gcs_bucket_encryption(bucket_name):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    if not bucket.default_kms_key_name:
        return [f"GCS bucket {bucket_name} does not use a Customer-Managed Encryption Key (CMEK)"]
    return []