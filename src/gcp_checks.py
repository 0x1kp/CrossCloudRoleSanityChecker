from google.cloud import storage
from googleapiclient import discovery
from google.auth import default as google_auth_default
import config

DANGEROUS_ROLES: set[str] = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.organizationAdmin",
}


def _extract_project_id(service_account_email: str) -> str:
    """Extract the GCP project ID from a service account email.

    Args:
        service_account_email: Email in the format NAME@PROJECT.iam.gserviceaccount.com.

    Returns:
        The extracted project ID, or config.GCP_PROJECT_ID as a fallback.
    """
    try:
        domain_part = service_account_email.split("@")[1]
        project_id = domain_part.split(".iam.gserviceaccount.com")[0]
        if project_id and project_id != domain_part:
            return project_id
    except (IndexError, AttributeError):
        pass
    return config.GCP_PROJECT_ID


def check_gcp_service_account_permissions(service_account_email: str) -> list[str]:
    """Check project-level IAM bindings for dangerous roles on a service account.

    Uses the Cloud Resource Manager v1 API to retrieve the project's IAM policy
    and flags any binding where the service account holds a role considered
    overly permissive (e.g. roles/owner, roles/editor).

    Args:
        service_account_email: The email address of the GCP service account.

    Returns:
        A list of strings describing any dangerous role bindings found.
    """
    project_id = _extract_project_id(service_account_email)
    credentials, _ = google_auth_default()
    crm_service = discovery.build(
        "cloudresourcemanager", "v1", credentials=credentials
    )

    request = crm_service.projects().getIamPolicy(
        resource=project_id,
        body={"options": {"requestedPolicyVersion": 3}},
    )
    policy = request.execute()

    member_identifier = f"serviceAccount:{service_account_email}"
    issues: list[str] = []

    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        members = binding.get("members", [])
        if member_identifier in members and role in DANGEROUS_ROLES:
            issues.append(
                f"Service account {service_account_email} has dangerous "
                f"role '{role}' on project {project_id}"
            )

    return issues


def check_service_account_keys(service_account_email: str) -> list[str]:
    """Check whether a service account has user-managed keys.

    User-managed keys are a security risk because they do not auto-rotate
    and can be exfiltrated. GCP-managed keys are preferred.

    Args:
        service_account_email: The email address of the GCP service account.

    Returns:
        A list containing a warning if user-managed keys exist, or empty if none.
    """
    project_id = _extract_project_id(service_account_email)
    credentials, _ = google_auth_default()
    iam_service = discovery.build("iam", "v1", credentials=credentials)

    resource_name = (
        f"projects/{project_id}/serviceAccounts/{service_account_email}"
    )

    request = iam_service.projects().serviceAccounts().keys().list(
        name=resource_name,
        keyTypes=["USER_MANAGED"],
    )
    response = request.execute()

    keys = response.get("keys", [])
    if keys:
        return [
            f"Service account {service_account_email} has "
            f"{len(keys)} user-managed key(s), which pose a security risk"
        ]
    return []


def check_gcs_bucket_public_access(bucket_name: str) -> list[str]:
    """Check whether a GCS bucket is publicly accessible.

    Args:
        bucket_name: The name of the GCS bucket to check.

    Returns:
        A list of strings describing any public access issues found.
    """
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    policy = bucket.get_iam_policy(requested_policy_version=3)
    issues: list[str] = []
    for binding in policy.bindings:
        if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
            issues.append(f"GCS bucket {bucket_name} is publicly accessible to: {binding['members']}")
    return issues


def check_gcs_bucket_encryption(bucket_name: str) -> list[str]:
    """Check whether a GCS bucket uses a Customer-Managed Encryption Key.

    Args:
        bucket_name: The name of the GCS bucket to check.

    Returns:
        A list containing an error message if CMEK is not configured, or empty if it is.
    """
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    if not bucket.default_kms_key_name:
        return [f"GCS bucket {bucket_name} does not use a Customer-Managed Encryption Key (CMEK)"]
    return []
