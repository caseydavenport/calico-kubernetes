import logging
import sys
import json

import requests

from common.constants import KUBE_API_ROOT

logger = logging.getLogger(__name__)


def _get_api_token():
    """
    Get the kubelet Bearer token for this node, used for HTTPS auth.
    If no token exists, this method will return an empty string.
    :return: The token.
    :rtype: str
    """
    logger.info('Getting Kubernetes Authorization')

    try:
        with open('/var/lib/kubelet/kubernetes_auth') as f:
            json_string = f.read()
    except IOError as e:
        logger.warning("Failed to open auth_file (%s). Assuming insecure mode", e)
        if _api_root_secure():
            logger.error("Cannot use insecure mode. API root is set to"
                         "secure (%s). Exiting", KUBE_API_ROOT)
            sys.exit(1)
        else:
            return ""

    logger.info('Got kubernetes_auth: ' + json_string)
    auth_data = json.loads(json_string)
    return auth_data['BearerToken']


def _api_root_secure():
    """
    Checks whether the KUBE_API_ROOT is secure or insecure.
    If not an http or https address, exit.

    :return: Boolean: True if secure. False if insecure
    """
    if (KUBE_API_ROOT[:5] == 'https'):
        return True
    elif (KUBE_API_ROOT[:5] == 'http:'):
        return False
    else:
        logger.error('KUBE_API_ROOT is not set correctly (%s). Please specify '
                     'a http or https address. Exiting', KUBE_API_ROOT)
        sys.exit(1)

def _patch_api(path, patch):
    """
    Patch an api resource to a given path

    :param path: The relative path to an API endpoint.
    :param patch: The updated data
    :return: A list of JSON API objects
    :rtype list
    """
    logger.debug('Patching API Resource in path %s with data %s', path, patch)
    bearer_token = _get_api_token()
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + bearer_token,
                            'Content-type': 'application/strategic-merge-patch+json'})
    response = session.patch(url=KUBE_API_ROOT+path, data=patch, verify=True)
    return json.loads(response.text)