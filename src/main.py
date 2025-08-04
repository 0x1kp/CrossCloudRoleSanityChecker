import argparse
from aws_checks import check_iam_role_permissions
from gcp_checks import check_gcp_service_account_permissions
from reporting import generate_report

def main():
    parser = argparse.ArgumentParser(description='Cross-cloud IAM Precheck Tool')
    parser.add_argument('--aws-role', required=True, help='AWS IAM Role name')
    parser.add_argument('--gcp-account', required=True, help='GCP Service Account email')
    parser.add_argument('--output-format', choices=['markdown', 'json'], default='markdown')
    args = parser.parse_args()

    print("Running AWS IAM checks...")
    aws_issues = check_iam_role_permissions(args.aws_role)

    print("Running GCP IAM checks...")
    gcp_issues = check_gcp_service_account_permissions(args.gcp_account)

    report = generate_report(aws_issues, gcp_issues, output_format=args.output_format)
    print(report)

if __name__ == '__main__':
    main()