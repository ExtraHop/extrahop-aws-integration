# encoding = utf-8
"""Wrapper for API calls to ExtraHop."""
# COPYRIGHT 2020 BY EXTRAHOP NETWORKS, INC.
#
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
# This file is part of an ExtraHop Supported Integration. Make NO MODIFICATIONS below this line

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ExtraHopClient(object):
    """
    ExtraHopClient is a simple wrapper around Requests.Session to save authentication and
    connection data.
    """

    def __init__(self, host, api_key, verify_certs=False):
        self.host = host

        self.session = requests.Session()
        self.session.headers = {
            "Accept": "application/json",
            "Authorization": f"ExtraHop apikey={api_key}",
        }
        self.session.verify = verify_certs

    def get(self, path):
        """Send GET request to ExtraHop API."""
        return self._api_request("get", path)

    def post(self, path, data=None, json=None):
        """Send POST request to ExtraHop API."""
        return self._api_request("post", path, data, json)

    def patch(self, path, data=None, json=None):
        return self._api_request("patch", path, data, json)

    def delete(self, path):
        return self._api_request("delete", path)

    def _api_request(self, method, path, data=None, json=None):
        """Handle API requests to ExtraHop API."""
        url = f"https://{self.host}/api/v1/{path}"

        if method == "get":
            rsp = self.session.get(url)
        elif method == "post":
            rsp = self.session.post(url, data=data, json=json)
        elif method == "patch":
            rsp = self.session.patch(url, data=data, json=json)
        elif method == "delete":
            rsp = self.session.delete(url)
        else:
            raise ValueError("Unsupported HTTP method {}".format(method))

        rsp.raise_for_status()

        return rsp
