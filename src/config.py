# config.py

# AWS Configuration
AWS_REGION = "us-east-1"
S3_BUCKET_NAME = "my-source-bucket"
AWS_PROFILE = "secure-sync"

# GCP Configuration
GCP_PROJECT_ID = "my-gcp-project"
GCS_BUCKET_NAME = "my-target-bucket"
GOOGLE_APPLICATION_CREDENTIALS = "/path/to/your/service_account.json"

# Reporting Configuration
OUTPUT_FORMAT = "markdown"  # Options: 'markdown' or 'json'
ENABLE_STRICT_MODE = True  # Enforce strict IAM role policy rules