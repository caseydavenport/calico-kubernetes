#!/usr/bin/python
import os
import sys
import time
import json
import Queue
import logging
import requests
import pycalico

from threading import Thread
from subprocess import check_output
from contextlib import closing
from pycalico.datastore import DatastoreClient, PROFILE_PATH
from pycalico.datastore_datatypes import Rules

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://localhost:8080/api/v1/')

POLICY_LOG_DIR = "/var/log/calico/calico-policy"
POLICY_LOG = "%s/calico-policy.log" % POLICY_LOG_DIR

LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

_log = logging.getLogger(__name__)


class PolicyAgent():

    def __init__(self):
        self.client = DatastoreClient()
        self.q = Queue.Queue()
        self.pods = dict()
        self.services = dict()
        self.endpoints = dict()
        self.namespaces = dict()

        self.PodWatcher = Thread(target=_keep_watch,
                                 args=(self.q, "pods"))
        self.SvcWatcher = Thread(target=_keep_watch,
                                 args=(self.q, "services"))
        self.NsWatcher = Thread(target=_keep_watch,
                                args=(self.q, "namespaces"))
        self.EptsWatcher = Thread(target=_keep_watch,
                                  args=(self.q, "endpoints"))

        self.PodWatcher.daemon = True
        self.SvcWatcher.daemon = True
        self.NsWatcher.daemon = True
        self.EptsWatcher.daemon = True

    def run(self):
        self.PodWatcher.start()
        self.SvcWatcher.start()
        self.NsWatcher.start()
        self.EptsWatcher.start()

        while True:
            self.read_responses()

    def read_responses(self):
        try:
            response = self.q.get_nowait()
            r_json = json.loads(response)
            r_type = r_json["type"]
            r_obj = r_json["object"]
            r_kind = r_obj["kind"]

            _log.info("%s: %s" % (r_type, r_kind))

            if r_kind in ["Pod", "Namespace", "Service"]:
                self.process_resource(action=r_type, kind=r_kind, target=r_obj)
            else:
                _log.info(
                    "Resource %s not Pod, Service, or Namespace" % r_kind)

        except Queue.Empty:
            pass

    def process_resource(self, action, kind, target):
        """
        Takes a target object and an action and updates internal list
        """
        # Determine Resource Kind
        if kind == "Pod":
            resource_bin = self.pods
            obj = Pod(target)

        elif kind == "Service":
            resource_bin = self.services
            obj = Service(target)

        elif kind == "Endpoints":
            resource_bin = self.endpoints
            obj = Endopints(target)

        elif kind == "Namespace":
            resource_bin = self.namespaces
            obj = Namespace(target)

        else:
            _log.error("resource %s not Pod, Service, or Namespace" % kind)
            sys.exit(1)

        target_key = obj.key

        if action == "ADDED":
            if target_key not in resource_bin:
                resource_bin[target_key] = obj
                _log.info("%s added to Calico store" % target_key)

            else:
                _log.error("Tried to Add %s, but %s already in bin" %
                           (obj, target_key))

        elif action == "DELETED":
            if target_key in resource_bin:
                del resource_bin[target_key]
                _log.info("%s deleted from Calico store" % target_key)

            else:
                _log.error(
                    "Tried to Delete %s, but %s was not in bin" %
                    (obj, target_key))

        elif action == "MODIFIED":
            if target_key in resource_bin:
                _log.info("Updating %s\n%s\n=====>\n%s" %
                          (target_key, resource_bin[target_key], obj))
                resource_bin[target_key] = obj

            else:
                _log.warning("Tried to Modify %s, but %s was not in bin. "
                             "Treating as Addition" %
                             (target_key, target_key))
                self.process_resource(action="ADDED", kind=kind, target=obj)

    def define_namespace_policy(self, namespace):
        ns_tag = "namespace_%s" % namespace.name
        profile_path = PROFILE_PATH % {"profile_id": ns_tag}
        self.client.etcd_client.write(profile_path + "tags", '["%s"]' % ns_tag)
        default_allow = Rule(action="allow")

        if namespace.policy == "open":
            rules = Rules(id=ns_tag,
                      inbound_rules=[default_allow],
                      outbound_rules=[default_allow])

        elif namespace.policy == "closed":
            rules = Rules(id=ns_tag,
                      inbound_rules=[Rule(action="allow", src_tag=ns_tag)],
                      outbound_rules=[default_allow])

        else:
            _log.error("Namespace %s policy is neither open nor closed" % namespace.name)
            sys.exit(1)
        
        self.client.etcd_client.write(profile_path + "rules", rules.to_json())


class Resource():
    def __init__(self, json):
        self.json = json
        self.from_json(json)
        self.key = self.get_key()
        self.needs_resync = True

    def from_json(self, json):
        self.uid = None
        return

    def get_key(self):
        return self.uid

    def resync(self):
        self.needs_resync = False


class Pod(Resource):
    def from_json(self, json):
        self.kind = "Pod"
        self.uid = json["metadata"]["uid"]
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]


class Service(Resource):
    def from_json(self, json):
        self.kind = "Service"
        self.uid = json["metadata"]["uid"]
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]


class Endpoints(Resource):
    def from_json(self, json):
        self.kind = "Endopints"
        self.selfLink = json["metadata"]["selfLink"]
        self.items = json["items"]

    def get_key(self):
        return self.selfLink


class Namespace(Resource):
    def from_json(self, json):
            self.kind = "Namespace"
        try:
            self.uid = json["metadata"]["uid"]
            self.name = json["metadata"]["name"]
        except KeyError:
            _log.error("Namespace does not have uid or name")

        try:
            self.policy = json["metadata"]["annotations"]["projectcalico.org/policy"]
        except KeyError:
            _log.warning("Namespace does not have policy, assumed open")
            self.policy = "open"


def _keep_watch(queue, path):
    response = _get_api_path("watch/%s" % path)
    for line in response.iter_lines():
        if line:
            queue.put(line)


def _get_api_token():
    """
    Get the kubelet Bearer token for this node, used for HTTPS auth.
    If no token exists, this method will return an empty string.
    :return: The token.
    :rtype: str
    """
    try:
        with open('/var/lib/kubelet/kubernetes_auth') as f:
            json_string = f.read()
    except IOError as e:
        return ""

    auth_data = json.loads(json_string)
    return auth_data['BearerToken']


def _get_api_path(path):
    """Get a resource from the API specified API path.

    e.g.
    _get_api_path('pods')

    :param path: The relative path to an API endpoint.
    :return: A list of JSON API objects
    :rtype list
    """
    bearer_token = _get_api_token()
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + bearer_token})
    session = requests.Session()
    return session.get("%s%s" % (KUBE_API_ROOT, path),
                       verify=False, stream=True)

if __name__ == '__main__':

    if not os.path.exists(POLICY_LOG_DIR):
        os.makedirs(POLICY_LOG_DIR)

    hdlr = logging.FileHandler(filename=POLICY_LOG)
    hdlr.setFormatter(logging.Formatter(LOG_FORMAT))
    _log.addHandler(hdlr)
    _log.setLevel(LOG_LEVEL)

    app = PolicyAgent()
    app.run()
