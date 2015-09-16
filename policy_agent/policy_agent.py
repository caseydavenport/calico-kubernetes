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
from pycalico.datastore_datatypes import Rules, Rule
from pycalico.datastore_errors import ProfileNotInEndpoint
from pycalico.datastore import DatastoreClient, PROFILE_PATH

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

        self.changed_pods = dict()
        self.changed_services = dict()
        self.changed_endpoints = dict()
        self.changed_namespaces = dict()

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
                if r_type == "DELETED":
                    self.delete_resource(kind=r_kind, target=r_obj)
                elif r_type in ["ADDED", "MODIFIED"]:
                    self.process_resource(action=r_type, kind=r_kind, target=r_obj)
                else:
                    _log.error("Event from watch not recognized: %s" % r_type)

            else:
                _log.info(
                    "Resource %s not Pod, Service, or Namespace" % r_kind)

        except Queue.Empty:
            self.resync()

    def process_resource(self, action, kind, target):
        """
        Takes a target object and an action and updates internal resource pools
        :param action: String of ["ADDED", "MODIFIED"] (returned by api watch)
        :param kind: String of ["Pod", "Namespace", "Service", "Endpoints"]
        :param target: json dict of resource info
        """
        # Determine Resource Pool
        if kind == "Pod":
            resource_pool = self.changed_pods
            obj = Pod(target)

        elif kind == "Service":
            resource_pool = self.changed_services
            obj = Service(target)

        elif kind == "Endpoints":
            resource_pool = self.changed_endpoints
            obj = Endpoints(target)

        elif kind == "Namespace":
            resource_pool = self.changed_namespaces
            obj = Namespace(target)

        else:
            _log.error("resource %s not Pod, Service, or Namespace" % kind)
            return

        target_key = obj.key

        if action == "ADDED":
            if target_key not in resource_pool:
                resource_pool[target_key] = obj
                _log.info("%s added to Calico store" % target_key)

            else:
                _log.error("Tried to Add %s, but %s already in bin" %
                           (obj, target_key))

        elif action == "MODIFIED":
            if target_key in resource_pool:
                _log.info("Updating\n%s\n=====>\n%s" %
                          (resource_pool[target_key], obj))
                resource_pool[target_key] = obj

            else:
                _log.warning("Tried to Modify %s, but %s was not in bin. "
                             "Treating as Addition" %
                             (target_key, target_key))
                self.process_resource(action="ADDED", kind=kind, target=target)
        
        else:
            _log.error("Event in process_resource not recognized: %s" % r_type)

    def delete_resource(kind, target):
        if kind == "Pod":
            resource_pool = self.pods
            obj = Pod(target)

        elif kind == "Service":
            resource_pool = self.services
            obj = Service(target)

        elif kind == "Endpoints":
            resource_pool = self.endpoints
            obj = Endpoints(target)

        elif kind == "Namespace":
            resource_pool = self.namespaces
            obj = Namespace(target)
        
        target_key = obj.key

        if target_key in resource_pool:
            del resource_pool[target_key]
            _log.info("%s deleted from Calico store" % target_key)

        else:
            _log.error(
                "Tried to Delete %s, but %s was not in bin" %
                (obj, target_key))

    def resync(self):
        """
        Tells all resource objects to resync their profile information
        """
        for resource_pool in [self.pods, self.services, self.endpoints, self.namespaces]:
            for resource_key in resource_pool:
                resource_pool[resource_key].resync()

        for namespace_key in self.changed_namespaces:
            if self.changed_namespaces[namespace_key].create_ns_profile():
                self.namespaces[namespace_key] = self.changed_namespaces[namespace_key]
                del self.changed_namespaces[namespace_key]

        for pod_key in self.changed_pods:
            if self.changed_pods[pod_key].apply_ns_policy():
                if self.changed_pods[pod_key].remove_default_profile()
                    self.pods[pod_key] = self.changed_pods[pod_key]
                    del self.changed_pods[pod_key]


class Resource():

    """
    Resource objects pull pertinent info from json blobs and maintain universal functions  
    """

    def __init__(self, json):
        """
        On init, each Resource saves the raw json, pulls necessary info (unique), 
        and defines a unique key identifier
        """
        self.json = json
        self.from_json(json)
        self.key = self.get_key()

    def from_json(self, json):
        self.name = "noop"
        return

    def get_key(self):
        return self.name

    def __str__(self):
        return "%s: %s\n%s" % (self.kind, self.key, self.json)


class Pod(Resource):

    def from_json(self, json):
        self.kind = "Pod"
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        try:
            self.ep_id = json["metadata"]["annotations"][EPID_ANNOTATION_KEY]
        except KeyError:
            # If the annotations do not contain a Calico endpoint, it is likely because the plugin
            # hasn't processed this pod yet.
            _log.info("Pod %s has no calico endpoint" % self.get_key())
            self.ep_id = None

    def get_key(self):
        return "%s/%s" % (self.namespace, self.name)

    def apply_ns_policy(self):
        ns_tag = "namespace_%s" % self.namespace

        if _datastore_client.profile_exists(ns_tag) and self.ep_id:
            ep = _datastore_client.get_endpoint(endpoint_id=self.ep_id)
            ep.profile_ids.append(ns_tag)
            _datastore_client.update_endpoint(ep)
            return True
        else:
            _log.error("Pod Resource %s found before Namespace Resource %s" % (
                self.name, self.namespace))
            return False

    def remove_default_profile(self):
        """
        remove the default reject all rule programmed by the plugin
        """
        default_profile = "REJECT_ALL"
        try:
            _log.info("Removing Default Profile")
            _datastore_client.remove_profiles_from_endpoint(profile_names=[default_profile], endpoint_id=self.ep_id)
            return True
        except ProfileNotInEndpoint:
            _log.info("Default Profile not on Endpoint")
            return True
        else:
            _log.info("Default Profile Removal Failed")
            return False


class Service(Resource):

    def from_json(self, json):
        self.kind = "Service"
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]

    def get_key(self):
        return "%s/%s" % (self.namespace, self.name)

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
            self.policy = json["metadata"][
                "annotations"][POLICY_ANNOTATION_KEY]
        except KeyError:
            _log.warning("Namespace does not have policy, assumed closed")
            self.policy = "closed"

    def get_key(self):
        return self.name

    def create_ns_profile(self):
        # Derive NS tag
        ns_tag = "namespace_%s" % self.name

        # Add Tags
        profile_path = PROFILE_PATH % {"profile_id": ns_tag}
        _datastore_client.etcd_client.write(
            profile_path + "tags", '["%s"]' % ns_tag)

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
            return False

        # Write rules to profile
        _datastore_client.etcd_client.write(
            profile_path + "rules", rules.to_json())
        return True

    def delete_ns_profile(self):
        # Derive NS tag
        ns_tag = "namespace_%s" % self.name

        # Remove from Store
        _datastore_client.remove_profile(ns_tag)
        return True


def _keep_watch(queue, path):
    """
    Called by watcher threads. Adds watch events to Queue
    """
    while True:
        try:
            response = _get_api_path("watch/%s" % path)
            for line in response.iter_lines():
                if line:
                    queue.put(line)
        except:
            # If we hit an exception attempting to watch this path, log it, and retry the watch
            # after a short sleep in order to prevent tight-looping.  We catch all BaseExceptions
            # so that the thread never dies.
            _log.exception("Exception watching path %s", path)
            time.sleep(10)


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
