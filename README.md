# Cross-Cloud Role Sanity Checker

## 🔍 Overview

**Cross-Cloud Role Sanity Checker** is a security-focused utility designed to validate AWS IAM roles and GCP service accounts before initiating cross-cloud data transfers — such as AWS DataSync operations targeting GCP.

The tool ensures that both cloud roles conform to defined least privilege and encryption standards, helping prevent privilege escalation, misconfiguration risks, and unauthorized data access.


## ✅ Features

- **AWS Checks:**
  - Detect wildcard (`*`) permissions in IAM policies
  - Analyze trust policies for overly permissive principals
  - Validate S3 encryption and block public access configurations

- **GCP Checks:**
  - Flag public GCS buckets
  - Check use of Customer-Managed Encryption Keys (CMEK)
  - Evaluate service account privilege levels (e.g., 'roles/owner' misuse)

- **Reporting:**
  - Outputs human-readable security reports in **Markdown** or **JSON**


## 🚀 Usage

### Prerequisites

- Python 3.8+
- AWS CLI profile configured
- GCP service account JSON credentials

### Install Requirements

```bash
pip install -r requirements.txt

python src/main.py \\
  --aws-role my-data-sync-role \\
  --gcp-account my-svc-account@gcp-project.iam.gserviceaccount.com \\
  --output-format markdown
```

### Configuration
See src/config.py to customize:
- AWS region
- Bucket names
- GCP project ID
- Reporting format