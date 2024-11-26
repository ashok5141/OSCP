# Enumerating AWS Cloud Infreastructure

##

## Reconnaissance via Cloud Service Provider's API



### Preparing the Lab - Configure AWS CLI


### Publicly Shared Resources



### Obtaining Account IDs from S3 Buckets


### Enumerating IAM Users in Other Accounts


Typically, we use the AWS Resource Name (ARN) to specify an IAM identity, as shown below:
```
"Principal": {
  "AWS": ["arn:aws:iam::AccountID:user/user-name"]
}
```
Create S3 bucket with Random number
```
aws --profile attacker s3 mb s3://offseclab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM
#offseclab-dummy-bucket-28967-25641-13328
```
By default, the newly-created bucket is private. Now we are going to define a policy document in which we'll grant read permission only to a specific IAM user in the target account. We can use any text editor 
of our preference to write the policy. We'll use the ARN we crafted earlier to test if the cloudadmin user exists in the account 123456789012.

```bash
nano grant-s3-bucket-read.json
cat grant-s3-bucket-read.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::offseclab-dummy-bucket-28967-25641-13328",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"]
            },
            "Action": "s3:ListBucket"

        }
    ]
}
```
Checking the Above policy with valid user, If no error returns after running the command, our policy was applied successfully. This also means that the cloudadmin user exists in the target account.
```
aws --profile attacker s3api put-bucket-policy --bucket offseclab-dummy-bucket-28967-25641-13328 --policy file://grant-s3-bucket-read.json
```
Update the policy added the no existed used 

```bash
nano grant-s3-bucket-read-userDoNotExist.json
cat grant-s3-bucket-read-userDoNotExist.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::offseclab-dummy-bucket-28967-25641-13328",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/nonexistant"]
            },
            "Action": "s3:ListBucket"

        }
    ]
}
```
Checking the Above policy with Non valid user, If no error returns after running the command, our policy was applied successfully. This also means that the cloudadmin user exists in the target account.
```bash
aws --profile attacker s3api put-bucket-policy --bucket offseclab-dummy-bucket-28967-25641-13328 --policy file://grant-s3-bucket-read-userDoNotExist.json
# Error An error occurred (MalformedPolicy) when calling the PutBucketPolicy operation: Invalid principal in policy
```
Trying to check existing crafted sample user names
```bash
echo -n "lab_admin
security_auditor
content_creator
student_access
lab_builder
instructor
network_config
monitoring_logging
backup_restore
content_editor" > aws-role-names.txt
```
[Pacu](https://github.com/RhinoSecurityLabs/pacu): The Open Source AWS Exploitation Framework
```bash
sudo apt update
sudo apt install pacu
pacu -h
pacu # It prompt for would like to name this new session?
Pacu(No Keys Set)>import_keys attacker # attacker profile is already set in the AWS CLI
Pacu>ls # it will all the options
Pacu>help iam__enum_roles # Helpoptions
Pacu>run iam__enum_roles --word-list /tmp/role-names.txt --account-id 123456789012 #this is the enum user account ID Identified "lab_admin" 
# Tasked to add the add the "saphire", "ruby", and "amethyst" starting of the in aws-role-names.txt
Pacu>run iam__enum_roles --word-list /tmp/role-names.txt --account-id 123456789012 # Identified amethyst-lab_admin
```
Tasked to find VPC configuration user identified in the above (user:amethyst-lab_admin) it will provide Session ID, Session Key, Session token export these details

```bash
# First export these 3 details of the user-amethyst-lab_admin identified in the above command
export AWS_ACCESS_KEY_ID=ASIAT7HC76KDHAY56JLG
export AWS_SECRET_ACCESS_KEY=KlS9b8fZMj72nCfTsdhcwex/7mrH1PGdnLB1ZCBi
export AWS_SESSION_TOKEN=FwoGZXI---TRUNKATED--SfTktvIrSwwA==
#Run this command identify the VPC configuration for user-amethyst-lab_admin
aws ec2 describe-vpcs --region us-east-1
```
