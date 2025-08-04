import boto3

def check_iam_role_permissions(role_name):
    iam = boto3.client('iam')
    attached_policies = iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
    
    issues = []
    for policy in attached_policies:
        policy_arn = policy['PolicyArn']
        version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']['Document']
        statements = policy_doc.get('Statement', [])
        for stmt in statements:
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*" or action.endswith(":*"):
                    issues.append(f"Policy {policy['PolicyName']} grants overly permissive access: {action}")
    return issues

def check_trust_policy(role_name):
    iam = boto3.client('iam')
    role = iam.get_role(RoleName=role_name)
    trust_doc = role['Role']['AssumeRolePolicyDocument']
    issues = []
    statements = trust_doc.get('Statement', [])
    for stmt in statements:
        principal = stmt.get('Principal', {})
        if principal.get('AWS') == "*" or "Service" in principal and principal["Service"] == "*":
            issues.append("Trust policy allows all principals (*)")
    return issues

def check_s3_bucket_encryption(bucket_name):
    s3 = boto3.client('s3')
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return []
    except s3.exceptions.ClientError:
        return [f"S3 bucket {bucket_name} does not have encryption enabled"]

def check_s3_public_access(bucket_name):
    s3 = boto3.client('s3control')
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    result = s3.get_public_access_block(AccountId=account_id)
    config = result['PublicAccessBlockConfiguration']
    if not all(config.values()):
        return [f"S3 bucket {bucket_name} public access block settings are not fully enforced"]
    return []