#!/bin/bash

#aws logs get-log-events \
--log-group-name /aws/codebuild/sonar-pipeline-build \
--log-stream-name 1f33a600-e8fe-492e-b5b4-ae37045afe42 \
--output text

#aws logs get-log-events \
--log-group-name /aws/codebuild/sonar-pipeline-build \
--log-stream-name 1f33a600-e8fe-492e-b5b4-ae37045afe42 \
--start-time $(date "+%s%N" -d "5 minutes ago" | cut -b1-13) \
--output text > output.txt

AWSARGS="--profile dev-profile --region us-east-1"
LOGGROUP="/aws/codebuild/sonar-pipeline-build"
while read stream; do
  aws $AWSARGS logs get-log-events \
    --start-from-head --start-time $starttime \
    --log-group-name $LOGGROUP --log-stream-name $stream --output text
done