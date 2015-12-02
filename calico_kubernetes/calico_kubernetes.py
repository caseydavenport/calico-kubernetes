# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Import print_function to use a testable "print()" function
# instead of keyword "print".
from __future__ import print_function

import os
import re
import requests
import logging
import sys
import json
import socket
import ConfigParser

from docker import Client
from docker.errors import APIError

from netaddr import IPAddress, IPNetwork, AddrFormatError
from policy import PolicyParser
from subprocess import check_output, CalledProcessError, check_call

import common
from common.util import _patch_api, configure_logger, IdentityFilter
from common.constants import *

import pycalico
from pycalico import netns
from pycalico.block import AlreadyAssignedError
from pycalico.datastore import IF_PREFIX
from pycalico.datastore_datatypes import Rule, Rules
from pycalico.ipam import IPAMClient
from pycalico.util import generate_cali_interface_name, get_host_ips

from logutils import *

util_logger = logging.getLogger(common.util.__name__)
pycalico_logger = logging.getLogger(pycalico.__name__)
logger = logging.getLogger(__name__)

# Docker and Host information.
DOCKER_VERSION = "1.16"
ORCHESTRATOR_ID = "docker"
HOSTNAME = socket.gethostname()

# Config filename.
CONFIG_FILENAME = "calico_kubernetes.ini"

# Key to look for annotations.
POLICY_ANNOTATION_KEY = "projectcalico.org/policy"

# Values in configuration dictionary.
ETCD_AUTHORITY_VAR = "ETCD_AUTHORITY"
LOG_LEVEL_VAR = "LOG_LEVEL"
KUBE_AUTH_TOKEN_VAR = "KUBE_AUTH_TOKEN"
KUBE_API_ROOT_VAR = "KUBE_API_ROOT"
CALICO_IPAM_VAR = "CALICO_IPAM"
CALICO_POLICY_VAR = "CALICO_POLICY"

# All environment variables used by the plugin.
ENVIRONMENT_VARS = [ETCD_AUTHORITY_VAR,
                    LOG_LEVEL_VAR,
                    KUBE_AUTH_TOKEN_VAR,
                    KUBE_API_ROOT_VAR,
                    CALICO_IPAM_VAR,
                    CALICO_POLICY_VAR]


class NetworkPlugin(object):

    def __init__(self, config):
        # These get set in the create / delete / status methods.
        self.pod_name = None
        self.namespace = None
        self.docker_id = None

        # Get configuration from the given dictionary.
        logger.debug("Plugin running with config: %s", config)
        self.auth_token = config[KUBE_AUTH_TOKEN_VAR]
        self.api_root = config[KUBE_API_ROOT_VAR]
        self.calico_ipam = config[CALICO_IPAM_VAR].lower()
        self.policy_enabled = config[CALICO_POLICY_VAR]

        # Determine profile to use.
        if self.policy_enabled:
            self.profile_name = DEFAULT_PROFILE_REJECT
        else:
            self.profile_name = DEFAULT_PROFILE_ACCEPT

        self._datastore_client = IPAMClient()
        self._docker_client = Client(
            version=DOCKER_VERSION,
            base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))

    def create(self, namespace, pod_name, docker_id):
        """"Create a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace

        logger.info('Configuring pod %s/%s (container_id %s)',
                    self.namespace, self.pod_name, self.docker_id)

        try:
            endpoint = self._configure_interface()
            logger.info("Created Calico endpoint: %s", endpoint.endpoint_id)
            self._configure_profile(endpoint)
        except CalledProcessError as e:
            logger.error('Error code %d creating pod networking: %s\n%s',
                         e.returncode, e.output, e)
            sys.exit(1)
        logger.info("Successfully configured networking for pod %s/%s",
                    self.namespace, self.pod_name)

        # Give the policy agent a reference to the endpoint in the API.
        # Only done after Endpoint configuration to avoid Policy Agent Race Condition.
        resource_path = "namespaces/%(namespace)s/pods/%(podname)s" % \
                        {"namespace": self.namespace, "podname": self.pod_name}
        ep_data = '{"metadata":{"annotations":{"%s":"%s"}}}' % (
            EPID_ANNOTATION_KEY, endpoint.endpoint_id)
        logger.info('Adding endpoint annotation to pod %s', self.pod_name)
        _patch_api(path=resource_path, patch=ep_data)
        logger.info('Endpoint annotation succeeded %s', self.pod_name)

    def delete(self, namespace, pod_name, docker_id):
        """Cleanup after a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace
        logger.info('Removing networking from pod %s/%s (container id %s)',
                    self.namespace, self.pod_name, self.docker_id)

        # Remove the profile for the workload.
        self._container_remove()

        logger.info("Successfully removed networking for pod %s/%s",
                    self.namespace, self.pod_name)

    def status(self, namespace, pod_name, docker_id):
        self.namespace = namespace
        self.pod_name = pod_name
        self.docker_id = docker_id

        if self._uses_host_networking(self.docker_id):
            # We don't perform networking / assign IP addresses for pods running
            # in the host namespace, and so we can't return a status update
            # for them.
            logger.debug("Ignoring status for pod %s/%s in host namespace",
                         self.namespace, self.pod_name)
            sys.exit(0)

        # Find the endpoint
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            # Obtain information from Docker Client and validate container state
            self._validate_container_state(self.docker_id)
            logger.error("Error in status: No endpoint for pod: %s/%s",
                         self.namespace, self.pod_name)
            sys.exit(1)

        # Retrieve IPAddress from the attached IPNetworks on the endpoint
        # Since Kubernetes only supports ipv4, we'll only check for ipv4 nets
        if not endpoint.ipv4_nets:
            logger.error("Error in status: No IPs attached to pod %s/%s",
                         self.namespace, self.pod_name)
            sys.exit(1)
        else:
            ip_net = list(endpoint.ipv4_nets)
            if len(ip_net) is not 1:
                logger.warning("There is more than one IPNetwork attached "
                               "to pod %s/%s", self.namespace, self.pod_name)
            ip = ip_net[0].ip

        logger.debug("Retrieved pod IP Address: %s", ip)

        json_dict = {
            "apiVersion": "v1beta1",
            "kind": "PodNetworkStatus",
            "ip": str(ip)
        }

        logger.debug("Writing status to stdout: \n%s", json.dumps(json_dict))
        print(json.dumps(json_dict))

    def _configure_profile(self, endpoint):
        """
        Configure the calico profile on the given endpoint.
        """
        logger.info('Configuring Pod Profile: %s', self.profile_name)

        if self._datastore_client.profile_exists(self.profile_name):
            logger.debug("Profile %s already exists, no work to do", 
                    self.profile_name)
        else:
            # CD4 TODO: Generate rules and pass in when creating profile.
            logger.info("Creating Profile %s", self.profile_name)
            rules = self._get_rules()
            self._datastore_client.create_profile(self.profile_name, rules)

        # Set the profile for the workload.
        logger.info('Setting profile %s on endpoint %s',
                    self.profile_name, endpoint.endpoint_id)
        self._datastore_client.set_profiles_on_endpoint(
            [self.profile_name], endpoint_id=endpoint.endpoint_id
        )
        logger.debug('Finished configuring profile.')

    def _configure_interface(self):
        """
        Configure the Calico interface for a pod.

        This involves the following steps:
        1) Obtain container PID and create a Calico endpoint using PID
        2) Delete the docker-assigned veth pair that's attached to the docker
           bridge
        3) Create a new calico veth pair, using the docker-assigned IP for the
           end in the container's namespace
        4) Assign the node's IP to the host end of the veth pair (required for
           compatibility with kube-proxy REDIRECT iptables rules).
        """
        logger.info('Configuring Calico network interface')

        # Set up parameters
        container_pid = self._get_container_pid(self.docker_id)
        interface = 'eth0'
        namespace = netns.PidNamespace(container_pid)

        # Delete the existing veth connecting to the docker bridge.
        self._delete_docker_interface()

        # Add Calico networking.
        logger.info('Configuring Calico network interface')
        endpoint = self._container_add(container_pid, interface)

        # Log our container's interfaces after adding the new interface.
        _log_interfaces(container_pid)

        ifce_name = generate_cali_interface_name(IF_PREFIX, 
                                                 endpoint.endpoint_id)
        node_ip = self._get_node_ip()
        logger.debug("Adding node IP %s to host-side veth %s", 
                     node_ip, ifce_name)

        # This is slightly tricky. Since the kube-proxy sometimes
        # programs REDIRECT iptables rules, we MUST have an IP on the host end
        # of the caliXXX veth pairs. This is because the REDIRECT rule
        # rewrites the destination ip/port of traffic from a pod to a service
        # VIP. The destination port is rewriten to an arbitrary high-numbered
        # port, and the destination IP is rewritten to one of the IPs allocated
        # to the interface. This fails if the interface doesn't have an IP,
        # so we allocate an IP which is already allocated to the node. We set
        # the subnet to /32 so that the routing table is not affected;
        # no traffic for the node_ip's subnet will use the /32 route.
        check_call(['ip', 'addr', 'add', node_ip + '/32',
                    'dev', endpoint.name])

        logger.info('Finished configuring Calico network interface')
        return endpoint

    def _container_add(self, pid, interface):
        """
        Adds a new endpoint to the Calico datastore
        """
        # Check if the container already exists. If it does, exit.
        try:
            _ = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            # Calico doesn't know about this container.  Continue.
            pass
        else:
            logger.error("This container has already been configured "
                         "with Calico Networking.")
            sys.exit(1)

        # Obtain information from Docker Client and validate container state
        self._validate_container_state(self.docker_id)

        # Assign and retrieve container IP address
        ip_list = [self._assign_container_ip()]

        # Create Endpoint object
        try:
            logger.info("Creating endpoint with IPs %s", ip_list)
            ep = self._datastore_client.create_endpoint(HOSTNAME,
                                                        ORCHESTRATOR_ID,
                                                        self.docker_id,
                                                        ip_list)
        except (AddrFormatError, KeyError):
            logger.exception("Failed to create endpoint with IPs %s. "
                             "Unassigning IP address, then exiting.", ip_list)
            self._datastore_client.release_ips(set(ip_list))
            sys.exit(1)

        # Create the veth, move into the container namespace, add the IP and
        # set up the default routes.
        logger.debug("Creating the veth with namespace pid %s on interface "
                     "name %s", pid, interface)
        ep.mac = ep.provision_veth(netns.PidNamespace(pid), interface)

        logger.debug("Setting mac address %s to endpoint %s", ep.mac, ep.name)
        self._datastore_client.set_endpoint(ep)

        # Let the caller know what endpoint was created.
        return ep

    def _assign_container_ip(self):
        """
        Assign IPAddress either with the assigned docker IPAddress or utilize
        calico IPAM.

        True indicates to utilize Calico's auto_assign IPAM policy.
        False indicate to utilize the docker assigned IPAddress

        :return IPAddress which has been assigned
        """
        def _assign(ip):
            """
            Local helper function for assigning an IP and checking for errors.
            Only used when operating with CALICO_IPAM=false
            """
            try:
                logger.info("Attempting to assign IP %s", ip)
                self._datastore_client.assign_ip(ip, str(self.docker_id), None)
            except (ValueError, RuntimeError):
                logger.exception("Failed to assign IPAddress %s", ip)
                sys.exit(1)

        if self.calico_ipam == 'true':
            logger.info("Using Calico IPAM")
            try:
                ipv4s, ipv6s = self._datastore_client.auto_assign_ips(1, 0,
                                                        self.docker_id, None)
                ip = ipv4s[0]
                logger.debug("IPAM assigned ipv4=%s; ipv6= %s", ipv4s, ipv6s)
            except RuntimeError as err:
                logger.error("Cannot auto assign IPAddress: %s", err.message)
                sys.exit(1)
        else:
            logger.info("Using docker assigned IP address")
            ip = self._read_docker_ip()

            try:
                # Try to assign the address using the _assign helper function.
                _assign(ip)
            except AlreadyAssignedError:
                # If the Docker IP is already assigned, it is most likely that
                # an endpoint has been removed under our feet.  When using
                # Docker IPAM, treat Docker as the source of
                # truth for IP addresses.
                logger.warning("Docker IP is already assigned, finding "
                               "stale endpoint")
                self._datastore_client.release_ips(set([ip]))

                # Clean up whatever existing endpoint has this IP address.
                # We can improve this later by making use of IPAM attributes
                # in libcalico to store the endpoint ID.  For now,
                # just loop through endpoints on this host.
                endpoints = self._datastore_client.get_endpoints(
                    hostname=HOSTNAME,
                    orchestrator_id=ORCHESTRATOR_ID)
                for ep in endpoints:
                    if IPNetwork(ip) in ep.ipv4_nets:
                        logger.warning("Deleting stale endpoint %s",
                                       ep.endpoint_id)
                        for profile_id in ep.profile_ids:
                            self._datastore_client.remove_profile(profile_id)
                        self._datastore_client.remove_endpoint(ep)
                        break

                # Assign the IP address to the new endpoint.  It shouldn't
                # be assigned, since we just unassigned it.
                logger.warning("Retry Docker assigned IP")
                _assign(ip)
        return ip

    def _container_remove(self):
        """
        Remove the indicated container on this host from Calico networking
        """
        # Find the endpoint ID. We need this to find any ACL rules
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            logger.exception("Container %s doesn't contain any endpoints",
                             self.docker_id)
            sys.exit(1)

        # Remove any IP address assignments that this endpoint has
        ip_set = set()
        for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
            ip_set.add(net.ip)
        logger.info("Removing IP addresses %s from endpoint %s",
                    ip_set, endpoint.name)
        self._datastore_client.release_ips(ip_set)

        # Remove the veth interface from endpoint
        logger.info("Removing veth interfaces")
        try:
            netns.remove_veth(endpoint.name)
        except CalledProcessError:
            logger.exception("Could not remove veth interface from "
                             "endpoint %s", endpoint.name)

        # Remove the container/endpoint from the datastore.
        try:
            self._datastore_client.remove_workload(
                HOSTNAME, ORCHESTRATOR_ID, self.docker_id)
        except KeyError:
            logger.exception("Failed to remove workload.")
        logger.info("Removed Calico endpoint %s", endpoint.endpoint_id)

    def _validate_container_state(self, container_name):
        info = self._get_container_info(container_name)

        # Check the container is actually running.
        if not info["State"]["Running"]:
            logger.error("The container is not currently running.")
            sys.exit(1)

        # We can't set up Calico if the container shares the host namespace.
        if info["HostConfig"]["NetworkMode"] == "host":
            logger.warning("Calico cannot network container because "
                           "it is running NetworkMode = host.")
            sys.exit(0)

    def _uses_host_networking(self, container_name):
        """
        Returns true if the given container is running in the
        host network namespace.
        """
        info = self._get_container_info(container_name)
        return info["HostConfig"]["NetworkMode"] == "host"

    def _get_container_info(self, container_name):
        try:
            info = self._docker_client.inspect_container(container_name)
        except APIError as e:
            if e.response.status_code == 404:
                logger.error("Container %s was not found. Exiting.",
                             container_name)
            else:
                logger.error(e.message)
            sys.exit(1)
        return info

    def _get_container_pid(self, container_name):
        return self._get_container_info(container_name)["State"]["Pid"]

    def _read_docker_ip(self):
        """Get the IP for the pod's infra container."""
        container_info = self._get_container_info(self.docker_id)
        ip = container_info["NetworkSettings"]["IPAddress"]
        logger.info('Docker-assigned IP is %s', ip)
        return IPAddress(ip)

    def _get_node_ip(self):
        """
        Determine the IP for the host node.
        """
        # Compile list of addresses on network, return the first entry.
        # Try IPv4 and IPv6.
        addrs = get_host_ips(version=4) or get_host_ips(version=6)

        try:
            addr = addrs[0]
            logger.debug("Node's IP address: %s", addr)
            return addr
        except IndexError:
            # If both get_host_ips return empty lists, log message and exit.
            logger.exception('No Valid IP Address Found for Host - cannot '
                             'configure networking for pod %s. '
                             'Exiting', self.pod_name)
            sys.exit(1)

    def _delete_docker_interface(self):
        """Delete the existing veth connecting to the docker bridge."""
        logger.debug('Deleting docker interface eth0')

        # Get the PID of the container.
        pid = str(self._get_container_pid(self.docker_id))
        logger.debug('Container %s running with PID %s', self.docker_id, pid)

        # Set up a link to the container's netns.
        logger.debug("Linking to container's netns")
        logger.debug(check_output(['mkdir', '-p', '/var/run/netns']))
        netns_file = '/var/run/netns/' + pid
        if not os.path.isfile(netns_file):
            logger.debug(check_output(['ln', '-s', '/proc/' + pid + '/ns/net',
                                       netns_file]))

        # Log our container's interfaces before making any changes.
        _log_interfaces(pid)

        # Reach into the netns and delete the docker-allocated interface.
        logger.debug(check_output(['ip', 'netns', 'exec', pid,
                                   'ip', 'link', 'del', 'eth0']))

        # Log our container's interfaces after making our changes.
        _log_interfaces(pid)

        # Clean up after ourselves (don't want to leak netns files)
        logger.debug(check_output(['rm', netns_file]))

    def _get_rules(self):
        """
        Generate default rules for a Calico profile.

        If Calico policy is enabled, all traffic will be rejected.
        Otherwise, all traffic will be allowed.
        """
        # Determine rule set based on policy
        if self.profile_name == DEFAULT_PROFILE_REJECT:
            default_rule = Rule(action="deny")
            logger.info("Using deny all rules")
        else:
            default_rule = Rule(action="allow")
            logger.info("Using allow all rules")

        rules = Rules(self.profile_name,
                      inbound_rules=[default_rule],
                      outbound_rules=[Rule(action="allow")])
        return rules

    def _api_root_secure(self):
        """
        Checks whether the Kubernetes api root is secure or insecure.
        If not an http or https address, exit.

        :return: Boolean: True if secure. False if insecure
        """
        if (self.api_root[:5] == 'https'):
            logger.debug('Using Secure API access.')
            return True
        elif (self.api_root[:5] == 'http:'):
            logger.debug('Using Insecure API access.')
            return False
        else:
            logger.error('%s is not set correctly (%s). '
                         'Please specify as http or https address. Exiting',
                         KUBE_API_ROOT_VAR, self.api_root)
            sys.exit(1)


def _log_interfaces(namespace):
    """
    Log interface state in namespace and default namespace.

    :param namespace
    :type namespace str
    """
    try:
        if logger.isEnabledFor(logging.DEBUG):
            interfaces = check_output(['ip', 'addr'])
            logger.debug("Interfaces in default namespace:\n%s", interfaces)

            namespaces = check_output(['ip', 'netns', 'list'])
            logger.debug("Namespaces:\n%s", namespaces)

            cmd = ['ip', 'netns', 'exec', str(namespace), 'ip', 'addr']
            namespace_interfaces = check_output(cmd)

            logger.debug("Interfaces in namespace %s:\n%s",
                         namespace, namespace_interfaces)
    except BaseException:
        # Don't exit if we hit an error logging out the interfaces.
        logger.exception("Ignoring error logging interfaces")


def load_config():
    """
    Loads configuration for the plugin - returns a dictionary.

    Looks first in environment, then in local config file.
    """
    # First, read the config file and get defaults.
    config = read_config_file()

    # Get config from environment, if defined.
    for var in ENVIRONMENT_VARS:
        config[var] = os.environ.get(var, config[var])

    # ETCD_AUTHORITY is handled slightly differently - we need to set it in the
    # environment so that libcalico works correctly.
    if not ETCD_AUTHORITY_VAR in os.environ:
        logger.debug("Use env variable: %s=%s",
                     ETCD_AUTHORITY_VAR,
                     config[ETCD_AUTHORITY_VAR])
        os.environ[ETCD_AUTHORITY_VAR] = config[ETCD_AUTHORITY_VAR]

    # Ensure case is correct.
    config[LOG_LEVEL_VAR] = config[LOG_LEVEL_VAR].upper()

    return config


def read_config_file():
    """
    Reads the config file on disk and returns configuration dictionary.
    """
    # Get the current directory and find path to config file.
    executable = sys.argv[0]
    cur_dir = os.path.dirname(executable)
    config_file = os.path.join(cur_dir, CONFIG_FILENAME)

    # Create dictionary of default values.
    defaults = {
        ETCD_AUTHORITY_VAR: "127.0.0.1:2379",
        CALICO_IPAM_VAR: "true",
        KUBE_API_ROOT_VAR: "http://kubernetes-master:8080/api/v1",
        CALICO_POLICY_VAR: "false",
        KUBE_AUTH_TOKEN_VAR: None,
        LOG_LEVEL_VAR: "INFO",
    }
    config = {}

    # Check that the file exists.  If not, return default values.
    if not os.path.isfile(config_file):
        return defaults

    # Read the config file.
    parser = ConfigParser.ConfigParser(defaults)
    parser.read(config_file)

    # Make sure the config section exists
    if not "config" in parser.sections():
        sys.exit("No [config] section in file %s" % config_file)

    # Get any values from the configuration file and populate dictionary.
    for var in ENVIRONMENT_VARS:
        config[var] = parser.get("config", var)

    return config


def run_protected():
    """
    Runs the plugin, intercepting all exceptions.
    """
    # Parse arguments and configure logging
    global logger, pycalico_logger
    mode = sys.argv[1]
    namespace = sys.argv[2].replace('/', '_') if len(sys.argv) >=3 else None
    pod_name = sys.argv[3].replace('/', '_') if len(sys.argv) >=4 else None
    docker_id = sys.argv[4] if len(sys.argv) >=5 else None

    # Get config from file / environment.
    config = load_config()

    # Filter the logger to append the Docker ID to logs.
    # If docker_id is not supplied, do not include it in logger config.
    if docker_id:
        configure_logger(logger=logger,
                         log_level=config[LOG_LEVEL_VAR],
                         docker_id=str(docker_id)[:12],
                         log_format=DOCKER_ID_ROOT_LOG_FORMAT)
        configure_logger(logger=pycalico_logger,
                         log_level=config[LOG_LEVEL_VAR],
                         docker_id=str(docker_id)[:12],
                         log_format=DOCKER_ID_LOG_FORMAT)

    else:
        configure_logger(logger=logger,
                         log_level=config[LOG_LEVEL_VAR],
                         log_format=ROOT_LOG_FORMAT)
        configure_logger(logger=pycalico_logger,
                         log_level=config[LOG_LEVEL_VAR],
                         log_format=LOG_FORMAT)

    # Try to run the plugin, logging out any BaseExceptions raised.
    logger.debug("Begin Calico network plugin execution")
    logger.debug('Plugin Args: %s', sys.argv)
    rc = 0
    try:
        run(mode=mode,
            namespace=namespace,
            pod_name=pod_name,
            docker_id=docker_id,
            config=config)
    except SystemExit, e:
        # If a SystemExit is thrown, we've already handled the error and have
        # called sys.exit().  No need to produce a duplicate exception
        # message, just return the exit code.
        rc = e.code
    except BaseException:
        # Log the exception and set the return code to 1.
        logger.exception("Unhandled Exception killed plugin")
        rc = 1
    finally:
        # Log that we've finished, and exit with the correct return code.
        logger.debug("Calico network plugin execution complete, rc=%s", rc)
        sys.exit(rc)


def run(mode, namespace, pod_name, docker_id, config):
    if mode == 'init':
        logger.info('No initialization work to perform')
    elif mode == "status":
        # Status is called on a regular basis - handle separately
        # to avoid flooding the logs.
        logger.info('Executing Calico pod-status hook')
        NetworkPlugin().status(namespace, pod_name, docker_id)
    else:
        if mode == 'setup':
            logger.info('Executing Calico pod-creation hook')
            NetworkPlugin(config).create(namespace, pod_name, docker_id)
        elif mode == 'teardown':
            logger.info('Executing Calico pod-deletion hook')
            NetworkPlugin(config).delete(namespace, pod_name, docker_id)
        elif mode == "status":
            logger.debug('Executing Calico pod-status hook')
            NetworkPlugin(config).status(namespace, pod_name, docker_id)


if __name__ == '__main__':  # pragma: no cover
    run_protected()
