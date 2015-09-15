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
from pycalico.datastore_datatypes import Rules, Rule

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://localhost:8080/api/v1/')

ANNOTATION_NAMESPACE = "projectcalico.org"
POLICY_ANNOTATION_KEY = "%s/policy" % ANNOTATION_NAMESPACE
EPID_ANNOTATION_KEY = "%s/endpointID" % ANNOTATION_NAMESPACE

POLICY_LOG_DIR = "/var/log/calico/calico-policy"
POLICY_LOG = "%s/calico-policy.log" % POLICY_LOG_DIR

LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

_log = logging.getLogger(__name__)
_datastore_client = DatastoreClient()


class PolicyAgent():
    """
    The Policy Agent is responsible for maintaining Watch Threads/Queues and internal resource lists
    """

    def __init__(self):
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
        """
        PolicyAgent.run() is called at program init to spawn watch threads and parse their responses 
        """
        self.PodWatcher.start()
        self.SvcWatcher.start()
        self.NsWatcher.start()
        self.EptsWatcher.start()

        while True:
            self.read_responses()

    def read_responses(self):
        """
        Read Responses pulls a response off the Queue and processes it
        If no responses remain in the queue, it will trigger a resync for all resource lists
        """
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
            self.resync()

    def process_resource(self, action, kind, target):
        """
        Takes a target object and an action and updates internal resource pools
        :param action: String of ["ADDED", "DELETED", "MODIFIED"] (returned by api watch)
        :param kind: String of ["Pod", "Namespace", "Service", "Endpoints"]
        :param target: json dict of resource info
        """
        # Determine Resource Pool 
        if kind == "Pod":
            resource_pool = self.pods
            obj = Pod(target)

        elif kind == "Service":
            resource_pool = self.services
            obj = Service(target)

        elif kind == "Endpoints":
            resource_pool = self.endpoints
            obj = Endopints(target)

        elif kind == "Namespace":
            resource_pool = self.namespaces
            obj = Namespace(target)

        else:
            _log.error("resource %s not Pod, Service, or Namespace" % kind)
            sys.exit(1)

        target_key = obj.key

        if action == "ADDED":
            if target_key not in resource_pool:
                resource_pool[target_key] = obj
                _log.info("%s added to Calico store" % target_key)

            else:
                _log.error("Tried to Add %s, but %s already in bin" %
                           (obj, target_key))

        elif action == "DELETED":
            if target_key in resource_pool:
                del resource_pool[target_key]
                _log.info("%s deleted from Calico store" % target_key)

            else:
                _log.error(
                    "Tried to Delete %s, but %s was not in bin" %
                    (obj, target_key))

        elif action == "MODIFIED":
            if target_key in resource_pool:
                _log.info("Updating %s\n%s\n=====>\n%s" %
                          (target_key, resource_pool[target_key], obj))
                resource_pool[target_key] = obj

            else:
                _log.warning("Tried to Modify %s, but %s was not in bin. "
                             "Treating as Addition" %
                             (target_key, target_key))
                self.process_resource(action="ADDED", kind=kind, target=target)

    def resync(self):
        """
        Tells all resource objects to resync their profile information
        """
        for resource_pool in [self.pods, self.services, self.endpoints, self.namespaces]:
            for resource_key in resource_pool:
                resource_pool[resource_key].resync()


class Resource():
    """
    Resource objects pull pertinent info from json blobs and maintain universal functions  
    """

    def __init__(self, json):
        """
        On init, each Resource saves the raw json, pulls necessary info (unique), defines a unique key identifier, and sets self.needs_resync to True
        """
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
        """
        Each Resource hits this loop. resyncs info with the datastore
        """
        if self.needs_resync:
            if self.sync():
                self.needs_resync = False

    def sync(self):
        return True

    def __str__(self):
        return "%s: %s\n%s" % (self.kind, self.key, self.json)


class Pod(Resource):

    def from_json(self, json):
        self.kind = "Pod"
        self.uid = json["metadata"]["uid"]
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        try:
            self.ep_id = json["metadata"]["annotations"][EPID_ANNOTATION_KEY]
        except KeyError:
            _log.error("Pod %s has no calico endpoint" % self.get_key())
            self.ep_id = None

    def get_key(self):
        return "%s/%s" % (self.namespace, self.name)

    def sync(self):
        ns_tag = "namespace_%s" % self.namespace

        if _datastore_client.profile_exists(ns_tag) and self.ep_id:
            _datastore_client.set_profiles_on_endpoint(
                [ns_tag], endpoint_id=self.ep_id)
            return True
        else:
            _log.error("Pod Resource %s found before Namespace Resource %s" % (
                self.name, self.namespace))
            return False


class Service(Resource):

    def from_json(self, json):
        self.kind = "Service"
        self.uid = json["metadata"]["uid"]
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]


class Endpoints(Resource):

    def from_json(self, json):
        self.kind = "Endpoints"
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
            self.policy = json["metadata"]["annotations"][POLICY_ANNOTATION_KEY]
        except KeyError:
            _log.warning("Namespace does not have policy, assumed closed")
            self.policy = "closed"

    def sync(self):
        # Derive NS tag
        ns_tag = "namespace_%s" % self.name

        # Add Tags
        profile_path = PROFILE_PATH % {"profile_id": ns_tag}
        _datastore_client.etcd_client.write(profile_path + "tags", '["%s"]' % ns_tag)

        # Determine rule set based on policy
        default_allow = Rule(action="allow")

        if self.policy == "open":
            rules = Rules(id=ns_tag,
                      inbound_rules=[default_allow],
                      outbound_rules=[default_allow])
            _log.info("Applying Open Rules to NS Profile %s" % ns_tag)

        elif self.policy == "closed":
            rules = Rules(id=ns_tag,
                      inbound_rules=[Rule(action="allow", src_tag=ns_tag)],
                      outbound_rules=[default_allow])
            _log.info("Applying Closed Rules to NS Profile %s" % ns_tag)

        else:
            _log.error(
                "Namespace %s policy is neither open nor closed" % self.name)
            sys.exit(1)

        # Write rules to profile
        _datastore_client.etcd_client.write(profile_path + "rules", rules.to_json())
        return True


def _keep_watch(queue, path):
    """
    Called by watcher threads. Adds watch events to Queue
    """
    response = _get_api_stream("watch/%s" % path)
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


def _get_api_stream(path):
    """
    Get a resource from the API specified API path.

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
