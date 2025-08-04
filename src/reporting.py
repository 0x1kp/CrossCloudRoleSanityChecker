import json

def generate_report(aws_issues, gcp_issues, output_format='markdown'):
    if output_format == 'json':
        return json.dumps({'aws': aws_issues, 'gcp': gcp_issues}, indent=2)
    else:
        md = "# Security Preflight Check Report\\n"
        md += "## AWS IAM Role Issues\\n" + ("- None\\n" if not aws_issues else ''.join(f"- {i}\\n" for i in aws_issues))
        md += "## GCP IAM Service Account Issues\\n" + ("- None\\n" if not gcp_issues else ''.join(f"- {i}\\n" for i in gcp_issues))
        return md