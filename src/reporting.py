import json

def generate_report(aws_issues: list[str], gcp_issues: list[str], output_format: str = 'markdown') -> str:
    """Generate a security preflight check report in the specified format.

    Args:
        aws_issues: List of AWS security issue descriptions.
        gcp_issues: List of GCP security issue descriptions.
        output_format: Report format, either 'markdown' or 'json'.

    Returns:
        The formatted report as a string.
    """
    if output_format == 'json':
        return json.dumps({'aws': aws_issues, 'gcp': gcp_issues}, indent=2)
    else:
        md = "# Security Preflight Check Report\n"
        md += "## AWS IAM Role Issues\n" + ("- None\n" if not aws_issues else ''.join(f"- {i}\n" for i in aws_issues))
        md += "## GCP IAM Service Account Issues\n" + ("- None\n" if not gcp_issues else ''.join(f"- {i}\n" for i in gcp_issues))
        return md
