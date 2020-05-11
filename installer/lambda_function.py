"""
Installs the AWS Integration bundle on the target Reveal(x) 
and creates an Open Data Stream endpoint to Amazon SNS.
"""
# COPYRIGHT 2020 BY EXTRAHOP NETWORKS, INC.
#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
# This file is part of an ExtraHop Supported Integration. Make NO MODIFICATIONS below this line
import json
import logging
import re
import os
import sys

import boto3
from crhelper import CfnResource
from extrahop import ExtraHopClient
from requests.exceptions import HTTPError
from aws_secretsmanager_caching import SecretCache, SecretCacheConfig
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

helper = CfnResource()


class ExtraHopConnection(object):
    """Class to encapsulate an ExtraHop client and related data."""

    def __init__(self, host, api_key, verify_certs=False):
        self.client = ExtraHopClient(host, api_key, verify_certs)
        self.appliance_data = self._get_appliance_data()
        self.uuid = self.appliance_data.get("uuid").replace("-", "")
        self.platform = self.appliance_data.get("platform")

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

    def get_eca_nodes(self):
        try:
            rsp = self.client.get("nodes")
            data = rsp.json()
        except (HTTPError, json.JSONDecodeError) as err:
            LOGGER.error(f"Could not retrieve bundle info from ExtraHop: {err}")
            return {}
        else:
            return {node["uuid"]: node["id"] for node in data}

    def get_all_bundles(self):
        """Get all installed bundles from ExtraHop.
        
        Returns:
            List(dict): JSON response from ExtraHop, if successful
            None: if error
        """
        try:
            rsp = self.client.get("bundles")
            data = rsp.json()
        except (HTTPError, json.JSONDecodeError) as err:
            LOGGER.error(f"Could not retrieve bundle info from ExtraHop: {err}")
            return None
        else:
            return data

    def post_bundle(self, bundle):
        """Posts a bundle to ExtraHop
        
        Args:
            bundle (JSON): ExtraHop bundle
        
        Returns:
            int: API ID for bundle, if successful
            None: if error
        """
        try:
            rsp = self.client.post("bundles", json=bundle)
            data = rsp.json()
        except (HTTPError, json.JSONDecodeError) as err:
            LOGGER.error(f"Could not install bundle file: {err}")
            return None
        else:
            bundle_id = rsp.headers["Location"].split("/")[-1]
            return bundle_id

    def apply_bundle(self, bundle_id, node_ids=[]):
        """Applies an installed bundle on ExtraHop
        
        Args:
            bundle_id (int): API ID for bundle
        """
        try:
            options = {"include_assignments": True, "policy": "skip"}
            if node_ids:
                options["node_ids"] = node_ids
            rsp = self.client.post(f"bundles/{bundle_id}/apply", json=options)
        except HTTPError as err:
            LOGGER.error(f"Could not apply bundle file: {err}")


def initialize_extrahop_connections():
    """Gets Reveal(x) credentials from AWS Secrets Manager and
    creates ExtraHopClient conenctions to each Reveal(x).

    Reference: https://aws.amazon.com/blogs/security/how-to-securely-provide-database-credentials-to-lambda-functions-by-using-aws-secrets-manager/
    
    Returns:
        List(ExtraHopConnection): ExtraHop connections
    """
    SECRETS_CLIENT = boto3.client("secretsmanager")
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


@helper.create
def bundle_installer(event, context):
    """Installs and configures AWS Integration bundle components on ExtraHop.
    
    Args:
        event (dict): Event data passed to handler
        context (object): Runtime information
    """
    EXTRAHOP_CLIENTS = initialize_extrahop_connections()
    BUNDLE_NAME = "AWS Integration"
    BUNDLE_PATH = "bundle.json"
    DETECTION_TRIGGER = "AWS Integration: Detections Publisher"
    NEWDEVICE_TRIGGER = "AWS Integration: New Device Publisher"
    detections_arn = event["ResourceProperties"]["DetectionsARN"]
    newdevice_arn = event["ResourceProperties"]["NewDeviceARN"]

    # load bundle file
    with open(BUNDLE_PATH) as bundle_fp:
        bundle = json.load(bundle_fp)
    # edit triggers in bundle code
    # replace the ARN placeholders with the real value from CloudFormation
    for trigger in bundle["Trigger"]:
        if trigger["name"] == DETECTION_TRIGGER:
            pattern = "const SNS_TOPIC_ARN = (.*?);\\n"
            replacement = f'const SNS_TOPIC_ARN = "{detections_arn}";\\n'
            trigger["script"] = re.sub(pattern, replacement, trigger["script"])
        elif trigger["name"] == NEWDEVICE_TRIGGER:
            pattern = "const SNS_TOPIC_ARN = (.*?);\\n"
            replacement = f'const SNS_TOPIC_ARN = "{newdevice_arn}";\\n'
            trigger["script"] = re.sub(pattern, replacement, trigger["script"])

    command_list = [item for item in EXTRAHOP_CLIENTS if item.platform == "command"]
    discover_list = [item for item in EXTRAHOP_CLIENTS if item.platform == "discover"]
    discover_uuids = set([item.uuid for item in discover_list])
    # If COMMAND appliance is present, push bundle to Command, and install from there
    for eca in command_list:
        bundles = eca.get_all_bundles()
        if bundles is None:
            LOGGER.error(
                f"Couldn't get bundles from Command appliance {eca.client.host}. Aborting install."
            )
            continue
        bundle_names = [bun["name"] for bun in bundles]
        if BUNDLE_NAME in bundle_names:
            LOGGER.info(
                f"{BUNDLE_NAME} bundle already installed on {eca.client.host}. Aborting install."
            )
            continue
        bundle_id = eca.post_bundle(bundle)
        if bundle_id is None:
            LOGGER.error(
                f"{BUNDLE_NAME} bundle failed to install on {eca.client.host}."
            )
            continue
        target_nodes_for_install = []
        attached_nodes = eca.get_eca_nodes()
        # only install on Discover appliances we have API keys for
        for node_uuid, node_id in attached_nodes.items():
            if node_uuid in discover_uuids:
                target_nodes_for_install.append(node_id)
        LOGGER.debug(
            f"Applying bundle to nodes {target_nodes_for_install} on ECA {eca.client.host}."
        )
        eca.apply_bundle(bundle_id, node_ids=target_nodes_for_install)

    for eda in discover_list:
        # Try to install bundle on all Discover appliances
        bundles = eda.get_all_bundles()
        if bundles is None:
            LOGGER.error(
                f"Couldn't get bundles from Command appliance {eda.client.host}. Aborting install."
            )
            continue
        bundle_names = [bun["name"] for bun in bundles]
        if BUNDLE_NAME in bundle_names:
            LOGGER.info(
                f"{BUNDLE_NAME} bundle already installed on {eda.client.host}. Aborting install."
            )
            continue
        bundle_id = eda.post_bundle(bundle)
        if bundle_id is None:
            LOGGER.error(
                f"{BUNDLE_NAME} bundle failed to install on {eda.client.host}."
            )
            continue
        LOGGER.debug(f"Applying bundle to {eda.client.host}")
        eda.apply_bundle(bundle_id)


@helper.update
@helper.delete
def no_op(event, context):
    """Don't do anything.
    
    Args:
        event (dict): Event data passed to handler
        context (object): Runtime information
    """
    # Just return a success code.
    return True


def lambda_handler(event, context):
    """Lambda handler called by CF Template.
    
    Args:
        event (dict): Event data passed to handler
        context (object): Runtime information
    """
    # Just pass everything to the CF Custom Resource handler.
    helper(event, context)
