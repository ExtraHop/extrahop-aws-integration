# Integrate ExtraHop with AWS

The AWS Integration with Reveal(x) provides additional device context and detection remediation capabilities for AWS environments. The integration, built with AWS Serverless Application Model, deploys Lambda functions to apply tags to Reveal(x) devices representing EC2 instances. In addition, the integration installs a trigger to send Reveal(x) detection data to an SNS topic. Users can create subscriptions to the SNS topic to integrate detections into existing workflows. The integration includes a Lambda function to quarantine EC2 instances that are identified as offenders in a detection with a very high risk score.

## Requirements

 - ExtraHop Reveal(x) or Command Appliance version 8.0 or later with administrator privileges.
 - Access key and secret key for an [AWS IAM User](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_change-permissions.html) used for programmatic access to AWS APIs.
 - [NAT gateway in your VPC subnet](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html#nat-gateway-creating) may be necessary for Lambda connectivity to AWS services.


## Installation and Configuration

This integration is [built on AWS Serverless Application Model](https://aws.amazon.com/serverless/sam/). The following instructions will build the required code for the application and will deploy AWS resources into a specified region in your AWS account using CloudFormation. The created resources and their associated IAM permissions are described in the template file, template.yaml, in the integration package on this page.

 1. Open the AWS Integration for ExtraHop in the AWS Serverless Application Repository.
 2. Click **Deploy**.
 3. Under the Application Settings section, provide values for the following parameters:
	 - Application Name: A name for the CloudFormation stack, e.g. **extrahop-integration**.
	 - ExtraHopSecrets: JSON text string specifying key/value pairs of Reveal(x) system address and API key. e.g. `{"revealx.example.com": "acbdcef123abcdef", "command.example.com": "456789fdb456789"}`
	 - LambdaSubnet: Subnet ID for the AWS VPC subnet in which to deploy the integration's lambda functions. This subnet must be able to route to the addresses provided in ExtraHopSecrets.
	 - LambdaVPC: VPC ID of the subnet provided earlier as the LambdaSubnet parameter.
	 - ImportTags: Comma-separated list of [AWS tag](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html)  keys to import to Reveal(x). Tag keys are case-sensitive.
	 - QuarantineRiskScore: Integer value for risk score threshold. This value is associated with a subscription filter to the integration's SNS topic for ExtraHop detections. Detections with risk scores at or above this value will trigger the quarantine Lambda function for detection participants. A value of 100 effectively disables the subscription.
 4. Click **Deploy**. 
 5.  Wait until you see the message 'Your application has been deployed'
 6.  Click on 'View CloudFormation Stack'. Values for the following parameters will be provided under the "Outputs" section:
	 - NewDeviceTaggingARN: ARN for created ExtraHop device tagging SNS topic
	 - DetectionTopicARN: ARN for created Reveal(x) Detections SNS Topic
 7. Attach the following policy to the IAM user that will be used for this integration. Replace the values of DetectionTopicARN and NewDeviceTaggingArn with the ARNs output by the CloudFormation template at the end of step 6:
```
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sns:Publish"],
                "Resource": [
	                "DetectionTopicARN",
	                "NewDeviceTaggingARN"
                ]
            }
        ]
    }
```
 5. [Configure an HTTP target for an open data stream](https://docs.extrahop.com/current/ods-http/) with the following parameters on each Reveal(x) with the AWS integration:
 - Name: **sns** 
 - Host: **sns.us-west-2.amazonaws.com** or other SNS API
   endpoint; see AWS documentation for the full list of endpoints for
   your region. 
  - Port: **443**. 
   - Type: **HTTPS**. 
   - Additional HTTP header: **Content-Type: application/x-www-form-urlencoded** 
   - Authentication: **Amazon Web Services** 
   - Access key ID field: Your IAM user access key ID 
   - Secret key: Your IAM user secret key 
   - Service: **sns**. 
   - Region: Your SNS API endpoint region; for example, **us-west-2**

## Lambda Functions and Related Resources

### AWS Secrets Manager -- extrahop/awsintegration

Reveal(x) addresses and API keys for this integration are stored in the [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html) secret named "extrahop/awsintegration". AWS admins can add, edit, or remove ExtraHop devices and associated API keys by [modifying the secret in AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_update-secret.html). The "extrahop/awsintegration" secret is configured with values from the ExtraHopSecrets parameter when the integration's CloudFormation stack is deployed.

### installer

The installer Lambda installs the AWS Integration bundle on Reveal(x) and ExtraHop Command Appliances defined in the AWS Secrets Manager secret named "extrahop/awsintegration".

### devicetagger

The devicetagger Lambda applies tags to Reveal(x) devices representing EC2 instances and updates the devices' custom names with its EC2 name or EC2 instance ID. The Lambda function will operate on all Reveal(x) and ExtraHop Command Appliances defined in the AWS Secrets Manager secret named "extrahop/awsintegration". 

The following properties are applied as tags for each EC2 instance device:
- Availability Zone
- VPC ID
- Subnet ID
- VPC Security Groups
- Instance Type
- Any user-defined AWS tags

Any user-defined keys in the Lambda's `IMPORT_TAGS` environment variable will also be applied to ExtraHop devices. The  value of `IMPORT_TAGS` must be a comma-delimited string of AWS tag keys. The value of this environment variable is defined when the SAM template is deployed and can be updated by modifying the [Lambda's environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html) or the IMPORT_TAGS parameter in the CloudFormation template.

The following information is added to the device description:
- Public IP
- Public DNS
- Instance ID
- AMI Name

The devicetagger Lambda is configured to run every hour and will update all device tags. In addition, the AWS Integration -- New Device Publisher trigger fires when the Reveal(x) discovers a new device and publishes information about the device to the SNS topic identified by NewDeviceTaggingARN. The devicetagger Lambda is subscribed to this SNS topic and updates the Reveal(x) device.

### quarantine
The quarantine Lambda isolates and shuts down EC2 instances identified as the offender in an ExtraHop detection. The Lambda is subscribed to the SNS topic identified by DetectionTopicARN. The Lambda will take quarantine action on any detection it receives from SNS, so its SNS topic subscription is configured with a filter to only accept detections with a risk score greater than or equal to the QuarantineRiskScore parameter in the integration's CloudFormation template.

The quarantine Lambda will attempt to take the following actions on any EC2 instance identified as an offender in a detection:

 1. Enable termination protection
 2. Change the instance's VPC security group to a "quarantine" group with no ingress or egress rules
 3. Detach the instance from any AWS Auto Scaling groups
 4. Deregister the instance from any Elastic Load Balancers
 5. Stop the instance and snapshot its volumes
 6. Apply an AWS tag to the instance, with the key "ExtraHopQuarantine" and a value of the detection ID which triggered the quarantine action.
