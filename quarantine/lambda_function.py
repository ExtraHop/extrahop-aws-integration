"""
Isolates and shuts down EC2 instances identified as the offender in an ExtraHop detection. 
"""
# COPYRIGHT 2020 BY EXTRAHOP NETWORKS, INC.
#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
# This file is part of an ExtraHop Supported Integration. Make NO MODIFICATIONS below this line
import json
import logging
import os

import boto3
from botocore.exceptions import ClientError, WaiterError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

AUTOSCALE_CLIENT = boto3.client("autoscaling")
EC2_CLIENT = boto3.client("ec2")
ELB_CLIENT = boto3.client("elb")

SNAPSHOT_EXCLUDE_BOOT = False
QUARANTINE_SECURITY_GROUP = os.environ["QUARANTINE_SECURITY_GROUP"]
DRY_RUN_FLAG = False


def get_instance_ids(ipaddr: str = "", macaddr: str = ""):
    """Get EC2 instance ID from IPv4 address and MAC address.
    
    Args:
        ipaddr (str, optional): IPv4 address
        macaddr (str, optional): MAC address
    
    Raises:
        ValueError: Must specify ipaddr or macaddr (or both)
    
    Returns:
        List[str]: List of instance IDs
    """
    if not (ipaddr or macaddr):
        raise ValueError("Must specify ipaddr or macaddr.")
    ec2_filter = []
    if ipaddr:
        ec2_filter.append({"Name": "private-ip-address", "Values": [ipaddr]})
    if macaddr:
        ec2_filter.append(
            {"Name": "network-interface.mac-address", "Values": [macaddr.lower()],}
        )
    ec2_data = EC2_CLIENT.describe_instances(Filters=ec2_filter)
    return [
        inst["InstanceId"]
        for res in ec2_data["Reservations"]
        for inst in res["Instances"]
    ]


def enable_termination_protection(instance_id: str):
    """Enables termination protection for an EC2 instance.
    
    Args:
        instance_id (str): EC2 instance ID
    """
    result = EC2_CLIENT.modify_instance_attribute(
        InstanceId=instance_id,
        DisableApiTermination={"Value": True},
        DryRun=DRY_RUN_FLAG,
    )
    LOGGER.debug(result)


def modify_security_group(instance_id: str, securitygroup_id: str):
    """Replaces all security groups assignments on an EC2 instance to the given group.
    
    Args:
        instance_id (str): EC2 instance ID
        securitygroup_id (str): Security Group ID
    """
    network_interfaces = EC2_CLIENT.describe_network_interfaces(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
    )
    if len(network_interfaces["NetworkInterfaces"]) == 0:
        LOGGER.warning(
            f">> Couldn't find network interfaces for instance {instance_id} when attempting security group reassignment"
        )
        return
    network_interface_id = network_interfaces["NetworkInterfaces"][0][
        "NetworkInterfaceId"
    ]
    try:
        EC2_CLIENT.modify_network_interface_attribute(
            NetworkInterfaceId=network_interface_id,
            Groups=[securitygroup_id],
            DryRun=DRY_RUN_FLAG,
        )
    except ClientError as err:
        if "DryRunOperation" not in str(err):
            raise


def detach_from_autoscalers(instance_id: str):
    """Detaches an EC2 instance from all autoscale groups.
    
    Args:
        instance_id (str): EC2 instance ID
    """
    autoscale_groups = AUTOSCALE_CLIENT.describe_auto_scaling_groups()
    detach_targets = []
    for as_group in autoscale_groups["AutoScalingGroups"]:
        for as_instance in as_group["Instances"]:
            if as_instance["InstanceId"] == instance_id:
                detach_targets.append(as_group["AutoScalingGroupName"])
    for autoscaler_name in detach_targets:
        try:
            AUTOSCALE_CLIENT.detach_instances(
                InstanceIds=[instance_id],
                AutoScalingGroupName=autoscaler_name,
                ShouldDecrementDesiredCapacity=False,
                DryRun=DRY_RUN_FLAG,
            )
        except ClientError as err:
            if "DryRunOperation" not in str(err):
                raise


def deregister_from_elbs(instance_id: str):
    """Deregister EC2 instance from all Elastic Load Balancers
    
    Args:
        instance_id (str): EC2 instance ID
    """
    load_balancers = ELB_CLIENT.describe_load_balancers()
    deregister_targets = []
    for elb in load_balancers["LoadBalancerDescriptions"]:
        for elb_instance in elb["Instances"]:
            if elb_instance["InstanceId"] == instance_id:
                deregister_targets.append(elb["LoadBalancerName"])
    for elb_name in deregister_targets:
        try:
            ELB_CLIENT.deregister_instances_from_load_balancer(
                LoadBalancerName=elb_name,
                Instances=[{"InstanceId": instance_id}],
                DryRun=DRY_RUN_FLAG,
            )
            waiter = ELB_CLIENT.get_waiter("instance_deregistered")
            waiter.wait(
                LoadBalancerName=elb_name,
                Instances=[{"InstanceId": instance_id}],
                WaiterConfig={"Delay": 5, "MaxAttempts": 20},
            )
        except WaiterError as err:
            LOGGER.warning(
                f"Timeout while waiting for instance {instance_id} to deregister from load balancer {elb_name}"
            )
        except ClientError as err:
            if "DryRunOperation" not in str(err):
                raise


def stop_instance(instance_id: str):
    """Stops an EC2 instance.
    
    Args:
        instance_id (str): EC2 instance ID
    """
    try:
        EC2_CLIENT.stop_instances(InstanceIds=[instance_id], DryRun=DRY_RUN_FLAG)
    except ClientError as err:
        if "DryRunOperation" not in str(err):
            raise


def snapshot_volume(instance_id: str, exclude_boot_volume: bool):
    """Takes a snapshot of EBS-backed volumes for an instance.
    If exclude_boot_volume=True, will additionally stop the instance
    and wait for a stopped state before snapshotting
    
    Args:
        instance_id (str): EC2 instance ID
        exclude_boot_volume (bool): Exclude boot volume shapshot if True
    """
    # some constants
    waiter_delay = 5  # unit=seconds
    waiter_max_attempts = 60
    try:
        volume_response = EC2_CLIENT.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
        )
        if len(volume_response["Volumes"]) == 0:
            return
        # need to shutdown instance before snapshotting if snapshotting root
        if exclude_boot_volume is False and not DRY_RUN_FLAG:
            try:
                stop_instance(instance_id)
                waiter = EC2_CLIENT.get_waiter("instance_stopped")
                waiter.wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={
                        "Delay": waiter_delay,
                        "MaxAttempts": waiter_max_attempts,
                    },
                )
            except WaiterError as err:
                LOGGER.warning(
                    "Timeout waiting for instance to stop, attempting snapshot anyway."
                )
        EC2_CLIENT.create_snapshots(
            Description="ExtraHop Quarantine snapshot",
            InstanceSpecification={
                "InstanceId": instance_id,
                "ExcludeBootVolume": exclude_boot_volume,
            },
            DryRun=DRY_RUN_FLAG,
        )
    except ClientError as err:
        if "DryRunOperation" not in str(err):
            raise


def tag_instance(instance_id: str, tag_key: str, tag_value: str):
    """Creates a tag on an EC2 instance.
    
    Args:
        instance_id (str): EC2 instance ID
        tag_key (str): Tag key
        tag_value (str): Tag value
    """
    try:
        EC2_CLIENT.create_tags(
            Resources=[instance_id],
            Tags=[{"Key": tag_key, "Value": tag_value}],
            DryRun=DRY_RUN_FLAG,
        )
    except ClientError as err:
        if "DryRunOperation" not in str(err):
            raise


def quarantine_action(instance_id: str, detection_id: int):
    """Quarantines an EC2 instance.

    The actions taken in this function are adapted from
    "Incident Response Examples" for "Infrastructure Domain Incidents" (page 34) in
    __AWS Security Incident Response Guide, June 2019__
    https://d1.awsstatic.com/whitepapers/aws_security_incident_response.pdf
    
    Args:
        instance_id (str): [description]
        detection_id (int): [description]
    """
    # Try to do as many steps as possible, even if some fail.

    # 1. Capture metadata from the EC2 instance
    # ### Not implemented
    # 2. Protect EC2 from accidental termination by enabling termination protection
    try:
        enable_termination_protection(instance_id)
    except Exception as err:
        LOGGER.error(
            f">> Failed to enable termination protection for {instance_id}:\n{err}"
        )
    # 3. Isolate the EC2 instance by switching VPC Security Group
    try:
        modify_security_group(instance_id, QUARANTINE_SECURITY_GROUP)
    except Exception as err:
        LOGGER.error(f">> Failed to modify security group for {instance_id}:\n{err}")
    # 4. Detach the Amazon EC2 instance from AWS Auto Scaling groups
    try:
        detach_from_autoscalers(instance_id)
    except Exception as err:
        LOGGER.error(f">> Failed to detach autoscalers for {instance_id}:\n{err}")
    # 5. Deregister the EC2 instance from ELB
    try:
        deregister_from_elbs(instance_id)
    except Exception as err:
        LOGGER.error(f">> Failed to deregister for {instance_id}:\n{err}")
    # 6. Snapshot the Amazon EBS data volumes attached the EC2 for preservation
    try:
        snapshot_volume(instance_id, SNAPSHOT_EXCLUDE_BOOT)
    except Exception as err:
        LOGGER.error(f">> Failed to snapshot {instance_id}:\n{err}")
    # 7. Tag the EC2 instance as quarantined, add pertinent metadata
    try:
        tag_instance(instance_id, "ExtraHopQuarantine", f"Detection ID {detection_id}")
    except Exception as err:
        LOGGER.error(f">> Failed to add detection ID tags to {instance_id}:\n{err}")


def lambda_handler(event, context):
    """Handles Lambda invocations.
    
    Args:
        event (dict): Event data passed to handler
        context (object): Runtime information
    """
    sns_message = event["Records"][0]["Sns"]["Message"]
    detection = json.loads(sns_message)
    try:
        detection_id = int(detection["id"])
    except ValueError:
        detection_id = 0

    for participant in detection["participants"]:
        if participant["role"] == "offender":
            ipaddr = ""
            macaddr = ""
            if participant["object_type"] == "device":
                ipaddr = (
                    participant["object"]["ipaddrs"][0]
                    if len(participant["object"]["ipaddrs"]) > 0
                    else ""
                )
                macaddr = participant["object"]["hwaddr"]
            elif participant["object_type"] == "ipaddr":
                ipaddr = participant["object"]
            LOGGER.info(f">> Looking for instance with IP {ipaddr}, MAC {macaddr}")
            instance_id_list = get_instance_ids(ipaddr, macaddr)
            LOGGER.info(f">> Found instances: {instance_id_list}")
            for instance_id in instance_id_list:
                LOGGER.info(f">> Taking action on instance_id {instance_id}")
                quarantine_action(instance_id, detection_id)
