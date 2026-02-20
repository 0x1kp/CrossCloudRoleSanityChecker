import sys
import os
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock boto3 BEFORE importing aws_checks, so the top-level import doesn't
# fail when the library isn't installed.
# ---------------------------------------------------------------------------
sys.modules.setdefault("boto3", MagicMock())

# Ensure src/ is on the import path so bare imports (config, aws_checks) resolve
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aws_checks import (
    check_iam_role_permissions,
    check_trust_policy,
    check_s3_bucket_encryption,
    check_s3_public_access,
)


# ---------------------------------------------------------------------------
# check_iam_role_permissions
# ---------------------------------------------------------------------------

class TestCheckIamRolePermissions:
    @patch("aws_checks.boto3")
    def test_flags_wildcard_star_action(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::123:policy/BadPolicy", "PolicyName": "BadPolicy"}
            ]
        }
        mock_iam.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ]
                }
            }
        }

        issues = check_iam_role_permissions("test-role")
        assert len(issues) == 1
        assert "BadPolicy" in issues[0]
        assert "*" in issues[0]

    @patch("aws_checks.boto3")
    def test_flags_service_wildcard_action(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::123:policy/S3Full", "PolicyName": "S3Full"}
            ]
        }
        mock_iam.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                    ]
                }
            }
        }

        issues = check_iam_role_permissions("test-role")
        assert len(issues) == 1
        assert "s3:*" in issues[0]

    @patch("aws_checks.boto3")
    def test_ignores_specific_actions(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::123:policy/GoodPolicy", "PolicyName": "GoodPolicy"}
            ]
        }
        mock_iam.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}
                    ]
                }
            }
        }

        issues = check_iam_role_permissions("test-role")
        assert issues == []

    @patch("aws_checks.boto3")
    def test_handles_action_as_string(self, mock_boto3):
        """Action can be a string instead of a list — should still be processed."""
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::123:policy/P", "PolicyName": "P"}
            ]
        }
        mock_iam.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"}
                    ]
                }
            }
        }

        issues = check_iam_role_permissions("test-role")
        assert len(issues) == 1
        assert "iam:*" in issues[0]

    @patch("aws_checks.boto3")
    def test_multiple_policies_multiple_issues(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::123:policy/A", "PolicyName": "PolicyA"},
                {"PolicyArn": "arn:aws:iam::123:policy/B", "PolicyName": "PolicyB"},
            ]
        }
        mock_iam.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_iam.get_policy_version.side_effect = [
            {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ]
                    }
                }
            },
            {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}
                        ]
                    }
                }
            },
        ]

        issues = check_iam_role_permissions("test-role")
        assert len(issues) == 2
        assert "PolicyA" in issues[0]
        assert "PolicyB" in issues[1]

    @patch("aws_checks.boto3")
    def test_no_attached_policies(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": []
        }

        issues = check_iam_role_permissions("test-role")
        assert issues == []

    @patch("aws_checks.boto3")
    def test_empty_statement_list(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::123:policy/Empty", "PolicyName": "Empty"}
            ]
        }
        mock_iam.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {"Statement": []}
            }
        }

        issues = check_iam_role_permissions("test-role")
        assert issues == []


# ---------------------------------------------------------------------------
# check_trust_policy
# ---------------------------------------------------------------------------

class TestCheckTrustPolicy:
    @patch("aws_checks.boto3")
    def test_flags_aws_wildcard_principal(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.get_role.return_value = {
            "Role": {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
                    ]
                }
            }
        }

        issues = check_trust_policy("test-role")
        assert len(issues) == 1
        assert "all principals" in issues[0]

    @patch("aws_checks.boto3")
    def test_flags_service_wildcard_principal(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.get_role.return_value = {
            "Role": {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "*"}, "Action": "sts:AssumeRole"}
                    ]
                }
            }
        }

        issues = check_trust_policy("test-role")
        assert len(issues) == 1
        assert "all principals" in issues[0]

    @patch("aws_checks.boto3")
    def test_ignores_specific_service_principal(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.get_role.return_value = {
            "Role": {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                }
            }
        }

        issues = check_trust_policy("test-role")
        assert issues == []

    @patch("aws_checks.boto3")
    def test_ignores_specific_aws_account(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.get_role.return_value = {
            "Role": {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                }
            }
        }

        issues = check_trust_policy("test-role")
        assert issues == []

    @patch("aws_checks.boto3")
    def test_empty_statements(self, mock_boto3):
        mock_iam = MagicMock()
        mock_boto3.client.return_value = mock_iam

        mock_iam.get_role.return_value = {
            "Role": {
                "AssumeRolePolicyDocument": {"Statement": []}
            }
        }

        issues = check_trust_policy("test-role")
        assert issues == []


# ---------------------------------------------------------------------------
# check_s3_bucket_encryption
# ---------------------------------------------------------------------------

class TestCheckS3BucketEncryption:
    @patch("aws_checks.boto3")
    def test_encryption_enabled_is_clean(self, mock_boto3):
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {}
        }

        issues = check_s3_bucket_encryption("my-bucket")
        assert issues == []

    @patch("aws_checks.boto3")
    def test_no_encryption_flags_issue(self, mock_boto3):
        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3

        # Create a real exception class that the except clause can catch.
        # The source code catches `s3.exceptions.ClientError`, which resolves
        # to mock_s3.exceptions.ClientError — so we make that a real class.
        client_error = type("ClientError", (Exception,), {})
        mock_s3.exceptions.ClientError = client_error
        mock_s3.get_bucket_encryption.side_effect = client_error(
            "ServerSideEncryptionConfigurationNotFoundError"
        )

        issues = check_s3_bucket_encryption("my-bucket")
        assert len(issues) == 1
        assert "my-bucket" in issues[0]
        assert "encryption" in issues[0]


# ---------------------------------------------------------------------------
# check_s3_public_access
# ---------------------------------------------------------------------------

class TestCheckS3PublicAccess:
    @patch("aws_checks.boto3")
    def test_all_blocked_is_clean(self, mock_boto3):
        mock_s3control = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service, **kwargs):
            if service == 's3control':
                return mock_s3control
            elif service == 'sts':
                return mock_sts
            return MagicMock()

        mock_boto3.client.side_effect = client_factory

        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_s3control.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        issues = check_s3_public_access("my-bucket")
        assert issues == []

    @patch("aws_checks.boto3")
    def test_partial_block_flags_issue(self, mock_boto3):
        mock_s3control = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service, **kwargs):
            if service == 's3control':
                return mock_s3control
            elif service == 'sts':
                return mock_sts
            return MagicMock()

        mock_boto3.client.side_effect = client_factory

        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_s3control.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        }

        issues = check_s3_public_access("my-bucket")
        assert len(issues) == 1
        assert "my-bucket" in issues[0]
        assert "not fully enforced" in issues[0]

    @patch("aws_checks.boto3")
    def test_no_blocking_flags_issue(self, mock_boto3):
        mock_s3control = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service, **kwargs):
            if service == 's3control':
                return mock_s3control
            elif service == 'sts':
                return mock_sts
            return MagicMock()

        mock_boto3.client.side_effect = client_factory

        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_s3control.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }

        issues = check_s3_public_access("my-bucket")
        assert len(issues) == 1
        assert "not fully enforced" in issues[0]
