import sys
import os
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock all third-party modules BEFORE importing gcp_checks, so the top-level
# imports in gcp_checks.py don't fail when the libraries aren't installed.
# ---------------------------------------------------------------------------
_google_mock = MagicMock()
sys.modules.setdefault("google", _google_mock)
sys.modules.setdefault("google.cloud", _google_mock.cloud)
sys.modules.setdefault("google.cloud.storage", _google_mock.cloud.storage)
sys.modules.setdefault("google.auth", MagicMock())
sys.modules.setdefault("googleapiclient", MagicMock())
sys.modules.setdefault("googleapiclient.discovery", MagicMock())

# Ensure src/ is on the import path so bare imports (config, gcp_checks) resolve
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from gcp_checks import (
    _extract_project_id,
    check_gcp_service_account_permissions,
    check_service_account_keys,
    check_gcs_bucket_public_access,
    check_gcs_bucket_encryption,
    DANGEROUS_ROLES,
)


# ---------------------------------------------------------------------------
# _extract_project_id
# ---------------------------------------------------------------------------

class TestExtractProjectId:
    def test_standard_service_account_email(self):
        email = "my-svc@my-cool-project.iam.gserviceaccount.com"
        assert _extract_project_id(email) == "my-cool-project"

    def test_project_with_numeric_id(self):
        email = "runner@project-123456.iam.gserviceaccount.com"
        assert _extract_project_id(email) == "project-123456"

    @patch("gcp_checks.config")
    def test_malformed_email_falls_back_to_config(self, mock_config):
        mock_config.GCP_PROJECT_ID = "fallback-project"
        assert _extract_project_id("not-an-email") == "fallback-project"

    @patch("gcp_checks.config")
    def test_empty_string_falls_back_to_config(self, mock_config):
        mock_config.GCP_PROJECT_ID = "fallback-project"
        assert _extract_project_id("") == "fallback-project"

    @patch("gcp_checks.config")
    def test_compute_default_falls_back_to_config(self, mock_config):
        mock_config.GCP_PROJECT_ID = "fallback-project"
        # Compute Engine default SA format doesn't match the standard pattern
        email = "123456789-compute@developer.gserviceaccount.com"
        assert _extract_project_id(email) == "fallback-project"


# ---------------------------------------------------------------------------
# check_gcp_service_account_permissions
# ---------------------------------------------------------------------------

class TestCheckGcpServiceAccountPermissions:
    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_detects_owner_role(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_policy = {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [f"serviceAccount:{email}"],
                }
            ]
        }
        mock_execute = MagicMock(return_value=mock_policy)
        mock_discovery.build.return_value.projects.return_value.getIamPolicy.return_value.execute = mock_execute

        issues = check_gcp_service_account_permissions(email)
        assert len(issues) == 1
        assert "roles/owner" in issues[0]
        assert email in issues[0]

    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_detects_multiple_dangerous_roles(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_policy = {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [f"serviceAccount:{email}"],
                },
                {
                    "role": "roles/editor",
                    "members": [f"serviceAccount:{email}"],
                },
            ]
        }
        mock_execute = MagicMock(return_value=mock_policy)
        mock_discovery.build.return_value.projects.return_value.getIamPolicy.return_value.execute = mock_execute

        issues = check_gcp_service_account_permissions(email)
        assert len(issues) == 2

    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_ignores_safe_roles(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_policy = {
            "bindings": [
                {
                    "role": "roles/viewer",
                    "members": [f"serviceAccount:{email}"],
                }
            ]
        }
        mock_execute = MagicMock(return_value=mock_policy)
        mock_discovery.build.return_value.projects.return_value.getIamPolicy.return_value.execute = mock_execute

        issues = check_gcp_service_account_permissions(email)
        assert issues == []

    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_ignores_dangerous_role_on_other_member(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_policy = {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["serviceAccount:other@my-project.iam.gserviceaccount.com"],
                }
            ]
        }
        mock_execute = MagicMock(return_value=mock_policy)
        mock_discovery.build.return_value.projects.return_value.getIamPolicy.return_value.execute = mock_execute

        issues = check_gcp_service_account_permissions(email)
        assert issues == []

    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_empty_bindings(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_policy = {"bindings": []}
        mock_execute = MagicMock(return_value=mock_policy)
        mock_discovery.build.return_value.projects.return_value.getIamPolicy.return_value.execute = mock_execute

        issues = check_gcp_service_account_permissions(email)
        assert issues == []


# ---------------------------------------------------------------------------
# check_service_account_keys
# ---------------------------------------------------------------------------

class TestCheckServiceAccountKeys:
    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_flags_user_managed_keys(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_response = {
            "keys": [
                {"name": "projects/my-project/serviceAccounts/svc/keys/key1", "keyType": "USER_MANAGED"},
                {"name": "projects/my-project/serviceAccounts/svc/keys/key2", "keyType": "USER_MANAGED"},
            ]
        }
        (mock_discovery.build.return_value
         .projects.return_value
         .serviceAccounts.return_value
         .keys.return_value
         .list.return_value
         .execute.return_value) = mock_response

        issues = check_service_account_keys(email)
        assert len(issues) == 1
        assert "2 user-managed key(s)" in issues[0]

    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_no_keys_is_clean(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_response = {"keys": []}
        (mock_discovery.build.return_value
         .projects.return_value
         .serviceAccounts.return_value
         .keys.return_value
         .list.return_value
         .execute.return_value) = mock_response

        issues = check_service_account_keys(email)
        assert issues == []

    @patch("gcp_checks.discovery")
    @patch("gcp_checks.google_auth_default")
    def test_missing_keys_field_is_clean(self, mock_auth, mock_discovery):
        mock_auth.return_value = (MagicMock(), "project-id")
        email = "svc@my-project.iam.gserviceaccount.com"

        mock_response = {}
        (mock_discovery.build.return_value
         .projects.return_value
         .serviceAccounts.return_value
         .keys.return_value
         .list.return_value
         .execute.return_value) = mock_response

        issues = check_service_account_keys(email)
        assert issues == []


# ---------------------------------------------------------------------------
# check_gcs_bucket_public_access
# ---------------------------------------------------------------------------

class TestCheckGcsBucketPublicAccess:
    @patch("gcp_checks.storage")
    def test_flags_allUsers(self, mock_storage):
        mock_policy = MagicMock()
        mock_policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
        ]
        mock_storage.Client.return_value.bucket.return_value.get_iam_policy.return_value = mock_policy

        issues = check_gcs_bucket_public_access("test-bucket")
        assert len(issues) == 1
        assert "publicly accessible" in issues[0]

    @patch("gcp_checks.storage")
    def test_flags_allAuthenticatedUsers(self, mock_storage):
        mock_policy = MagicMock()
        mock_policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}
        ]
        mock_storage.Client.return_value.bucket.return_value.get_iam_policy.return_value = mock_policy

        issues = check_gcs_bucket_public_access("test-bucket")
        assert len(issues) == 1
        assert "publicly accessible" in issues[0]

    @patch("gcp_checks.storage")
    def test_private_bucket_is_clean(self, mock_storage):
        mock_policy = MagicMock()
        mock_policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["serviceAccount:sa@proj.iam.gserviceaccount.com"]}
        ]
        mock_storage.Client.return_value.bucket.return_value.get_iam_policy.return_value = mock_policy

        issues = check_gcs_bucket_public_access("test-bucket")
        assert issues == []


# ---------------------------------------------------------------------------
# check_gcs_bucket_encryption
# ---------------------------------------------------------------------------

class TestCheckGcsBucketEncryption:
    @patch("gcp_checks.storage")
    def test_flags_missing_cmek(self, mock_storage):
        mock_bucket = MagicMock()
        mock_bucket.default_kms_key_name = None
        mock_storage.Client.return_value.bucket.return_value = mock_bucket

        issues = check_gcs_bucket_encryption("test-bucket")
        assert len(issues) == 1
        assert "CMEK" in issues[0]

    @patch("gcp_checks.storage")
    def test_cmek_present_is_clean(self, mock_storage):
        mock_bucket = MagicMock()
        mock_bucket.default_kms_key_name = "projects/p/locations/l/keyRings/kr/cryptoKeys/k"
        mock_storage.Client.return_value.bucket.return_value = mock_bucket

        issues = check_gcs_bucket_encryption("test-bucket")
        assert issues == []
