profile=dev-profile
program=value

# Describe all instances
aws ec2 describe-instances \
   --filters "Name=tag:Program,Values=$program" \
   --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,InstanceId:InstanceId,InstanceType:InstanceType,Platform:Platform,ImageId:ImageId,PrivateIpAddress:PrivateIpAddress}" \
   --output table --profile $profile

# Describe instance termination protection
for value in $(aws ec2 describe-instances --filters "Name=tag:Program,Values=$program" --query 'Reservations[*].Instances[*].[InstanceId]' --output text --profile $profile)
do
 aws ec2 describe-instance-attribute \
    --instance-id $value \
    --attribute disableApiTermination \
    --output text \
    --profile $profile;
done

# Describe volume and tags
for value in $(aws ec2 describe-instances --filters "Name=tag:Program,Values=$program" --query 'Reservations[*].Instances[*].[BlockDeviceMappings[0].Ebs.VolumeId]' --output text --profile $profile)
do
    aws ec2 describe-volumes \
        --volume-id $value \
        --query "Volumes[*].{Name:Tags[?Key=='Name']|[0].Value,Backup:Tags[?Key=='Backup']|[0].Value,Size:Size}" \
        --output table \
        --profile $profile;
done

# ToDo: Verify cloudwatch log is configured