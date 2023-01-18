# Download multiple s3 files (esp. Loca balancer logs)
aws s3 ls s3://<log path>/elasticloadbalancing/us-east-1/2022/01/14/  --recursive | awk '/^2022-01-14/{system("aws s3 cp s3://<log path>/elasticloadbalancing/us-east-1/2022/01/14/$4 .") }'
for g in *.gz; do gunzip $g; done