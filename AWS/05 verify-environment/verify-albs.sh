#########################################################################################################################
# Describe all ALBs
#########################################################################################################################
profile=dev-profile
for value in $(aws elbv2 describe-load-balancers --query 'LoadBalancers[*].[LoadBalancerArn]' --output text --profile $profile)
do
    aws elbv2 describe-load-balancers \
        --load-balancer-arn $value \
        --query 'LoadBalancers[*].{Name:LoadBalancerName}' \
        --output text \
        --profile $profile
    aws elbv2 describe-load-balancer-attributes \
        --load-balancer-arn $value \
        --query "Attributes[?Key=='deletion_protection.enabled']" \
        --output table \
        --profile $profile;
done