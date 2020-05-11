"""
Applies tags to Reveal(x) devices representing EC2 instances and 
updates the devices' custom names with its EC2 name or EC2 instance ID.
"""
# COPYRIGHT 2020 BY EXTRAHOP NETWORKS, INC.
#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
# This file is part of an ExtraHop Supported Integration. Make NO MODIFICATIONS below this line
import json
import logging
import os
import sys

import boto3
from extrahop import ExtraHopClient
from requests.exceptions import HTTPError
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

EC2_CLIENT = boto3.client("ec2")
SECRETS_CLIENT = boto3.client("secretsmanager")


class ExtraHopConnection(object):
    """Class to encapsulate an ExtraHop client and related data."""

    def __init__(self, host, api_key, verify_certs=False):
        self.client = ExtraHopClient(host, api_key, verify_certs)
        self.tags = self._fetch_all_tags()
        self.appliance_data = self._get_appliance_data()
        self.uuid = self.appliance_data.get("uuid").replace("-", "")

    def _get_appliance_data(self):
        try:
            rsp = self.client.get("appliances")
            appliances = rsp.json()
        except (HTTPError, json.JSONDecodeError) as err:
            LOGGER.error(f"Error getting information from ExtraHop: {err}")
        else:
            local_appliances = [
                app for app in appliances if app["connection_type"] == "local"
            ]
            if len(local_appliances) > 0:
                return local_appliances.pop()
            else:
                LOGGER.error(f"Could not find appliance UUID.")
                return {}

    def get_device(self, discovery_id: str = "", ipaddr: str = "", macaddr: str = ""):
        """Retrieves ExtraHop device data for device with matching
        IP and MAC addresses. Only returns the first result.
        
        Args:
            discovery_id (str, optional): ExtraHop Discovery ID
            ipaddr (str, optional): IPv4 address
            macaddr (str, optional): MAC address
        
        Raises:
            ValueError: Must specify ipaddr or macaddr (or both)
        
        Returns:
            [type]: [description]
        """
        if discovery_id:
            request = {
                "filter": {
                    "field": "discovery_id",
                    "operand": discovery_id,
                    "operator": "=",
                }
            }
        elif macaddr and ipaddr:
            request = {
                "filter": {
                    "operator": "and",
                    "rules": [
                        {"field": "macaddr", "operand": macaddr, "operator": "="},
                        {"field": "ipaddr", "operand": ipaddr, "operator": "="},
                    ],
                }
            }
        elif macaddr and not ipaddr:
            request = {
                "filter": {"field": "macaddr", "operand": macaddr, "operator": "="}
            }
        elif ipaddr and not macaddr:
            request = {
                "filter": {"field": "ipaddr", "operand": ipaddr, "operator": "="}
            }
        else:
            raise ValueError("Did not specify any search criteria.")

        try:
            rsp = self.client.post("devices/search", json=request)
            rsp_data = rsp.json()
        except (HTTPError, json.JSONDecodeError) as err:
            LOGGER.error(f"Error getting devices from ExtraHop: {err}")
            return None
        else:
            return rsp_data[0] if len(rsp_data) > 0 else None

    def get_device_tags(self, device_id: str):
        """Gets device tags from ExtraHop.
        
        Args:
            device_id (str): ExtraHop device API ID
        
        Returns:
            Set[str]: set of device tags
        """
        try:
            rsp = self.client.get(f"devices/{device_id}/tags")
            data = rsp.json()
        except (HTTPError, json.JSONDecodeError) as err:
            LOGGER.error(f"Error getting tags for device {device_id}: {err}")
            return set()
        else:
            return set([tag["name"] for tag in data])

    def set_device_attribs(self, device_id: str, device_name: str, device_desc: str):
        """Sets an ExtraHop device's custom name and description.
        
        Args:
            device_id (str): ExtraHop device API ID
            device_name (str): Device custom name
        
        Returns:
            [type]: [description]
        """
        try:
            rsp = self.client.patch(
                f"devices/{device_id}",
                json={"custom_name": device_name, "description": device_desc},
            )
        except HTTPError as err:
            LOGGER.error(f"Error setting custom name for device {device_id}: {err}")

    def tag_device(self, device_id, tag_name):
        tag_id = self.tags.get(tag_name)
        if not tag_id:
            tag_id = self._create_tag(tag_name)
        if not tag_id:
            LOGGER.error(f"Didn't find ID for tag name {tag_name}")
            return
        try:
            self.client.post(f"devices/{device_id}/tags/{tag_id}")
        except HTTPError as err:
            LOGGER.error(
                f"Failed to assign tag {tag_name} ({tag_id}) to device {device_id}: {err}"
            )

    def untag_device(self, device_id, tag_name):
        tag_id = self.tags.get(tag_name)
        if not tag_id:
            LOGGER.error(f"Didn't find ID for tag name {tag_name}")
            return
        try:
            self.client.delete(f"devices/{device_id}/tags/{tag_id}")
        except HTTPError as err:
            LOGGER.error(
                f"Failed to remove tag {tag_name} ({tag_id}) from device {device_id}: {err}"
            )

    def _fetch_all_tags(self):
        try:
            rsp = self.client.get("tags").json()
        except (HTTPError, json.JSONDecodeError) as err:
            LOGGER.error(f"Failed to retreive tags from ExtraHop.")
        else:
            return {tag["name"]: tag["id"] for tag in rsp}

    def _create_tag(self, tag_name):
        try:
            rsp = self.client.post("tags", json={"name": tag_name})
        except HTTPError as err:
            LOGGER.error(f"Failed to create new tag {tag_name}: {err}")
            return None
        else:
            tag_id = rsp.headers["Location"].split("/")[-1]
            self.tags[tag_name] = tag_id
            return tag_id


def initialize_extrahop_connections():
    """Gets Reveal(x) credentials from AWS Secrets Manager and
    creates ExtraHopClient conenctions to each Reveal(x).

    Reference: https://aws.amazon.com/blogs/security/how-to-securely-provide-database-credentials-to-lambda-functions-by-using-aws-secrets-manager/
    
    Returns:
        List(ExtraHopConnection): ExtraHop connections
    """
    secret_name = "extrahop/awsintegration"
    try:
        secret_cache = SecretCache(SecretCacheConfig(), SECRETS_CLIENT)
        secret_response_value = secret_cache.get_secret_string(secret_name)
    except ClientError as err:
        raise err
    else:
        secrets = secret_response_value
        secrets_dict = json.loads(secrets)
        extrahops = list()
        for host, api_key in secrets_dict.items():
            try:
                extrahop_connection = ExtraHopConnection(host=host, api_key=api_key)
            except Exception as error:
                LOGGER.warning(f"Could not connect to appliance at {host}: {error}")
                pass
            else:
                extrahops.append(extrahop_connection)
        return extrahops


EXTRAHOP_CLIENTS = initialize_extrahop_connections()

# All ExtraHop tags will be prepended with TAG_PREFIX
# to help identify the tag source (i.e. this lambda)
TAG_PREFIX = "aws:"


def get_ec2_instances(ipaddr: str = "", macaddr: str = ""):
    """Get EC2 instance ID from IPv4 address and MAC address.
    
    Args:
        ipaddr (str, optional): IPv4 address
        macaddr (str, optional): MAC address

    Returns:
        List[str]: List of instance IDs
    """
    ec2_filter = []
    if ipaddr:
        ec2_filter.append({"Name": "private-ip-address", "Values": [ipaddr]})
    if macaddr:
        ec2_filter.append(
            {"Name": "network-interface.mac-address", "Values": [macaddr.lower()]}
        )
    ec2_data = EC2_CLIENT.describe_instances(Filters=ec2_filter)
    return {
        instance["InstanceId"]: instance
        for res in ec2_data["Reservations"]
        for instance in res["Instances"]
    }


def get_image_name(image_id: str):
    ami_filter = [{"Name": "image-id", "Values": [image_id]}]
    images = EC2_CLIENT.describe_images(Filters=ami_filter)
    if len(images["Images"]) == 0:
        return None
    return images["Images"][0]["Name"]


def tag_extrahop_device(
    extrahop: ExtraHopConnection, device_id: str, instance_data: dict
):
    """Applies EC2 instance data and tags to an ExtraHop device.
    
    Args:
        device_id (str): ExtraHop API ID
        instance_data (dict): EC2 instance data
    """
    instance_id = instance_data["InstanceId"]
    device_tags = extrahop.get_device_tags(device_id)
    import_tags_raw = os.environ["IMPORT_TAGS"]
    import_tags = import_tags_raw.split(",")

    ### Apply instance data as ExtraHop device tags
    # Availability Zone
    az_tag = f"{TAG_PREFIX}zone:{instance_data['Placement']['AvailabilityZone']}"
    if az_tag not in device_tags:
        # overwrite old EC2 instance data tags if their data changed
        # e.g. instance moved to a new subnet
        # this should prevent devices from being tagged with more than one subnet, etc
        old_az_tags = [
            tag for tag in device_tags if tag.startswith(f"{TAG_PREFIX}zone:")
        ]
        for tag in old_az_tags:
            extrahop.untag_device(device_id, tag)
        extrahop.tag_device(device_id, az_tag)
    # VPC ID
    vpc_tag = f"{TAG_PREFIX}{instance_data['VpcId']}"
    if vpc_tag not in device_tags:
        old_vpc_tags = [
            tag for tag in device_tags if tag.startswith(f"{TAG_PREFIX}vpc")
        ]
        for tag in old_vpc_tags:
            extrahop.untag_device(device_id, tag)
        extrahop.tag_device(device_id, vpc_tag)
    # Subnet ID
    subnet_tag = f"{TAG_PREFIX}{instance_data['SubnetId']}"
    if subnet_tag not in device_tags:
        old_subnet_tags = [
            tag for tag in device_tags if tag.startswith(f"{TAG_PREFIX}subnet")
        ]
        for tag in old_subnet_tags:
            extrahop.untag_device(device_id, tag)
        extrahop.tag_device(device_id, subnet_tag)
    # Security Groups
    sg_prefix = f"{TAG_PREFIX}sg:"
    new_sg_tags = set(
        [
            f"{sg_prefix}{group['GroupName']}"
            for group in instance_data["SecurityGroups"]
        ]
    )
    current_sg_tags = set([tag for tag in device_tags if tag.startswith(sg_prefix)])
    for tag in current_sg_tags - new_sg_tags:
        extrahop.untag_device(device_id, tag)
    for tag in new_sg_tags - current_sg_tags:
        extrahop.tag_device(device_id, tag)

    # Instance Type
    itype_prefix = f"{TAG_PREFIX}instance-type:"
    itype_tag = f"{itype_prefix}{instance_data['InstanceType']}"
    if itype_tag not in device_tags:
        old_itype_tags = [tag for tag in device_tags if tag.startswith(itype_prefix)]
        for tag in old_itype_tags:
            extrahop.untag_device(device_id, tag)
        extrahop.tag_device(device_id, itype_tag)

    ### Apply AWS tags to ExtraHop device
    ec2_instance_tags = {tag["Key"]: tag["Value"] for tag in instance_data["Tags"]}
    LOGGER.debug(
        f">> ec2_instance_tags = {ec2_instance_tags.keys()}, import_tags = {import_tags}"
    )
    for tag_key in import_tags:
        if tag_key in ec2_instance_tags:
            # helpful key-based prefix to identify when tag values change
            aws_tag_prefix = f"{TAG_PREFIX}{tag_key}="
            # key:value tag name in ExtraHop
            aws_tag_extrahop_string = f"{aws_tag_prefix}{ec2_instance_tags[tag_key]}"
            if aws_tag_extrahop_string in device_tags:
                continue  # tag exists, nothing to do
            else:
                # overwrite old AWS tags if same key but different value
                # e.g. aws:Stack=Staging --> aws:Stack=Production
                duplicate_tags = [
                    tag for tag in device_tags if tag.startswith(aws_tag_prefix)
                ]
                for tag in duplicate_tags:
                    extrahop.untag_device(device_id, tag)
                extrahop.tag_device(device_id, aws_tag_extrahop_string)

    ### Set ExtraHop device attributes
    # Create device description
    image_name = get_image_name(instance_data["ImageId"])

    public_ip = instance_data.get("PublicIpAddress", "no-public-ip")
    public_dns = instance_data.get("PublicDnsName", "no-public-dns")
    device_desc = (
        f"{public_ip} *** "
        f"{public_dns} *** "
        f"Instance ID: {instance_id} *** "
        f"AMI: {image_name}"
    )
    # Set device name and description
    if "Name" in ec2_instance_tags:
        extrahop.set_device_attribs(device_id, ec2_instance_tags["Name"], device_desc)
    else:
        extrahop.set_device_attribs(device_id, instance_id, device_desc)


def lambda_handler_newdevice(event, context):
    """Handles Lambda invocations for tagging newly-discovered devices.

    Given an IP address and MAC address from the NEW_DEVICE ExtraHop event,
    looks for a corresponding EC2 instance, then applies instance tags to the device.
    
    Args:
        event (dict): Event data passed to handler
        context (object): Runtime information
    """
    sns_message = event["Records"][0]["Sns"]["Message"]
    sns_data = json.loads(sns_message)

    ipaddr = sns_data["ipaddrs"][0] if len(sns_data["ipaddrs"]) > 0 else ""
    macaddr = sns_data["hwaddr"]
    appliance_uuid = sns_data["appliance_uuid"]
    discovery_id = sns_data["id"]

    # Check to see if we can find an EC2 instance with this IP+MAC
    # If so, then let's try to tag a corresponding device in ExtraHop
    ec2_instances = get_ec2_instances(ipaddr, macaddr)
    if len(ec2_instances) == 0:
        LOGGER.debug(f">> No EC2 instance found for ({ipaddr}, {macaddr})")
        return

    # Just work with the first result.
    # Unexpected behavior if multiple instances returned for (ipaddr, macaddr)
    instance_id, instance_data = ec2_instances.popitem()
    LOGGER.debug(f">> Found instance matching ({ipaddr}, {macaddr}): {instance_id}")

    extrahop_sources = [
        item for item in EXTRAHOP_CLIENTS if item.uuid == appliance_uuid
    ]
    if len(extrahop_sources) == 0:
        LOGGER.debug(
            f">> Received message from appliance UUID {appliance_uuid}, but could not find matching appliance in configuration."
        )
        return
    extrahop = extrahop_sources.pop()
    device = extrahop.get_device(discovery_id=discovery_id)
    if device is None:
        LOGGER.debug(f">> No matching ExtraHop device for {instance_id}.")
        return
    else:
        device_id = device["id"]
        LOGGER.debug(
            f">> Found ExtraHop device matching ({ipaddr}, {macaddr}): {device_id}"
        )
        tag_extrahop_device(extrahop, device_id, instance_data)


def lambda_handler_scheduled(event, context):
    """Handles Lambda invocations for scheduled tagging of all devices.

    Iterates through all EC2 instances, looks for corresponding ExtraHop devices,
    then applies instance tags to the device.
    
    Args:
        event (dict): Event data passed to handler
        context (object): Runtime information
    """
    ec2_instances = get_ec2_instances()

    for extrahop in EXTRAHOP_CLIENTS:
        for instance_id, instance_data in ec2_instances.items():
            for interface in instance_data["NetworkInterfaces"]:
                macaddr = interface["MacAddress"]
                ipaddr = interface["PrivateIpAddress"]

                # Associate instance with ExtraHop device
                device = extrahop.get_device(ipaddr=ipaddr, macaddr=macaddr)
                if device is None:
                    device = extrahop.get_device(ipaddr="", macaddr=macaddr)
                if device is None:
                    LOGGER.debug(f">> No matching ExtraHop device for {instance_id}.")
                else:
                    device_id = device["id"]
                    LOGGER.debug(
                        f">> Tagging ExtraHop device {device_id} matching {instance_id} ({macaddr}, {ipaddr})"
                    )
                    tag_extrahop_device(extrahop, device_id, instance_data)
