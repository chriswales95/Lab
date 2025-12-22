# Start EC2 via CLI
aws ec2 run-instances \
--image-id $amiId \
--instance-type t2.micro \
--key-name keypair \
--subnet-id $subnet \
--security-group-ids $sg \
--user-data file://user-data-script.sh

# Stop an Instance
aws ec2 stop-instances --instance-ids $instanceId

# Terminate an Instance
aws ec2 terminate-instances --instance-ids $instanceId

# Get Running Instances
aws ec2 describe-instances --filters Name=instance-state-name,Values=running
