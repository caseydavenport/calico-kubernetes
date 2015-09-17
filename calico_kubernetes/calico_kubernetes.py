#!/bin/python
import json
import os
import sys
import re
import socket
from docker import Client
from docker.errors import APIError
from subprocess import check_output, CalledProcessError, check_call
import requests
import sh
import logging
from netaddr import IPAddress, AddrFormatError
from logutils import configure_logger
import pycalico
from pycalico import netns
from pycalico.datastore import IF_PREFIX, DatastoreClient, RULES_PATH
from pycalico.util import generate_cali_interface_name, get_host_ips
from pycalico.ipam import IPAMClient
from pycalico.block import AlreadyAssignedError

logger = logging.getLogger(__name__)
pycalico_logger = logging.getLogger(pycalico.__name__)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

DOCKER_VERSION = "1.16"
ORCHESTRATOR_ID = "docker"
HOSTNAME = socket.gethostname()

ANNOTATION_NAMESPACE = "projectcalico.org"
EPID_ANNOTATION_KEY = "%s/endpointID" % ANNOTATION_NAMESPACE

ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
if ETCD_AUTHORITY_ENV not in os.environ:
    os.environ[ETCD_AUTHORITY_ENV] = 'kubernetes-master:6666'

# Append to existing env, to avoid losing PATH etc.
# Need to edit the path here since calicoctl loads client on import.
CALICOCTL_PATH = os.environ.get('CALICOCTL_PATH', '/usr/bin/calicoctl')

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://kubernetes-master:8080/api/v1/')

# Flag to indicate whether or not to use Calico IPAM.
# If False, use the default docker container ip address to create container.
# If True, use libcalico's auto_assign IPAM to create container.
CALICO_IPAM = os.environ.get('CALICO_IPAM', 'true')

CALICO_POLICY = os.environ.get('CALICO_POLICY', 'true')

CALICO_NETWORKING = os.environ.get('CALICO_NETWORKING', 'true')


class NetworkPlugin(object):

    def __init__(self):
        self.pod_name = None
        self.profile_name = None
        self.namespace = None
        self.docker_id = None

        self._datastore_client = IPAMClient()
        self.calicoctl = sh.Command(CALICOCTL_PATH).bake(_env=os.environ)
        self._docker_client = Client(
            version=DOCKER_VERSION,
            base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))

    def create(self, namespace, pod_name, docker_id):
        """"Create a pod."""
        # Calicoctl does not support the '-' character in iptables rule names.
        # TODO: fix Felix to support '-' characters.
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace
        self.profile_name = "REJECT_ALL" if CALICO_POLICY == 'true' else "ALLOW_ALL"

        logger.info('Configuring docker container %s', self.docker_id)

        try:
            endpoint = self._configure_interface()
            self._configure_profile(endpoint)
        except CalledProcessError as e:
            logger.error('Error code %d creating pod networking: %s\n%s',
                         e.returncode, e.output, e)
            sys.exit(1)

    def delete(self, namespace, pod_name, docker_id):
        """Cleanup after a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace

        logger.info('Deleting container %s with profile %s',
                    self.docker_id, self.profile_name)

        # Remove the profile for the workload.
        self._container_remove()

    def status(self, namespace, pod_name, docker_id):
        self.namespace = namespace
        self.pod_name = pod_name
        self.docker_id = docker_id

        # Find the endpoint
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            logger.error(
                "Container %s doesn't contain any endpoints" % self.docker_id)
            sys.exit(1)

        # Retrieve IPAddress from the attached IPNetworks on the endpoint
        # Since Kubernetes only supports ipv4, we'll only check for ipv4 nets
        if not endpoint.ipv4_nets:
            logger.error(
                "Exiting. No IPs attached to endpoint %s", self.docker_id)
            sys.exit(1)
        else:
            ip_net = list(endpoint.ipv4_nets)
            if len(ip_net) is not 1:
                logger.warning(
                    "There is more than one IPNetwork attached to endpoint %s", self.docker_id)
            ip = ip_net[0].ip

        logger.info("Retrieved IP Address: %s", ip)

        json_dict = {
            "apiVersion": "v1beta1",
            "kind": "PodNetworkStatus",
            "ip": str(ip)
        }

        logger.debug(
            "Writing json dict to stdout: \n%s", json.dumps(json_dict))
        print json.dumps(json_dict)

    def _configure_profile(self, endpoint):
        """
        Configure the calico profile for a pod.

        Currently assumes one pod with each name.
        """
        pod = self._get_pod_config()

        logger.info('Configuring Pod Profile: %s', self.profile_name)

        if self._datastore_client.profile_exists(self.profile_name):
            logger.warning("Profile with name %s already exists.",
                           self.profile_name)
        else:
            self._datastore_client.create_profile(self.profile_name)
            self._apply_rules()

        # Also set the profile for the workload.
        logger.info('Setting profile %s on endpoint %s',
                    self.profile_name, endpoint.endpoint_id)

        self._datastore_client.append_profiles_to_endpoint(profile_names=[self.profile_name],
                                                           endpoint_id=endpoint.endpoint_id)
        logger.info('Finished configuring profile.')

    def _configure_interface(self):
        """Configure the Calico interface for a pod.

        This involves the following steps:
        1) Determine the IP that docker assigned to the interface inside the
           container
        2) Delete the docker-assigned veth pair that's attached to the docker
           bridge
        3) Create a new calico veth pair, using the docker-assigned IP for the
           end in the container's namespace
        4) Assign the node's IP to the host end of the veth pair (required for
           compatibility with kube-proxy REDIRECT iptables rules).
        """
        # Set up parameters
        container_pid = self._get_container_pid(self.docker_id)
        interface = 'eth0'

        self._delete_docker_interface()
        logger.info('Configuring Calico network interface')
        ep = self._container_add(container_pid, interface)
        interface_name = generate_cali_interface_name(
            IF_PREFIX, ep.endpoint_id)
        node_ip = self._get_node_ip()
        logger.info('Adding IP %s to interface %s', node_ip, interface_name)

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
                    'dev', interface_name])
        logger.info('Finished configuring network interface')
        return ep

    def _container_add(self, pid, interface):
        """
        Add a container (on this host) to Calico networking with the given IP.
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
            logger.error(
                "This container has already been configured with Calico Networking.")
            sys.exit(1)

        # Obtain information from Docker Client and validate container state
        self._validate_container_state(self.docker_id)

        ip_list = [self._assign_container_ip()]

        # Create Endpoint object
        try:
            logger.info("Creating endpoint with IPs %s", ip_list)
            ep = self._datastore_client.create_endpoint(HOSTNAME, ORCHESTRATOR_ID,
                                                        self.docker_id, ip_list)
        except (AddrFormatError, KeyError):
            logger.exception("Failed to create endpoint with IPs %s. Unassigning "
                             "IP address, then exiting.", ip_list)
            self._datastore_client.release_ips(set(ip_list))
            sys.exit(1)

        if CALICO_NETWORKING == 'true':
            # Create the veth, move into the container namespace, add the IP and
            # set up the default routes.
            logger.info(
                "Creating the veth with namespace pid %s on interface name %s", pid, interface)
            ep.mac = ep.provision_veth(netns.PidNamespace(pid), interface)

        logger.info("Setting mac address %s to endpoint %s", ep.mac, ep.name)
        self._datastore_client.set_endpoint(ep)

        # Give Kubernetes a link to the endpoint
        resource_path = "namespaces/%(namespace)s/pods/%(podname)s" % \
                        {"namespace": self.namespace, "podname": self.pod_name}
        ep_data = '{"metadata":{"annotations":{"%s":"%s"}}}' % (
            EPID_ANNOTATION_KEY, ep.endpoint_id)
        self._patch_api(path=resource_path, patch=ep_data)

        # Let the caller know what endpoint was created.
        return ep

    def _assign_container_ip(self):
        """
        Assign IPAddress either with the assigned docker IPAddress or utilize
        calico IPAM.

        The option to utilize IPAM is indicated by the environment variable
        "CALICO_IPAM".
        True indicates to utilize Calico's auto_assign IPAM policy.
        False indicate to utilize the docker assigned IPAddress

        :return IPAddress which has been assigned
        """
        if CALICO_IPAM == 'true':
            # Assign ip address through IPAM Client
            logger.info("Using Calico IPAM")
            try:
                ip_list, ipv6_addrs = self._datastore_client.auto_assign_ips(
                    1, 0, self.docker_id, None)
                ip = ip_list[0]
                logger.debug(
                    "ip_list is %s; ipv6_addrs is %s", ip_list, ipv6_addrs)
                assert not ipv6_addrs
            except RuntimeError as err:
                logger.error("Cannot auto assign IPAddress: %s", err.message)
                sys.exit(1)
        else:
            logger.info("Using docker assigned IP address")
            ip = self._read_docker_ip()
            try:
                self._datastore_client.assign_ip(ip, str(self.docker_id), None)
            except (ValueError, RuntimeError, AlreadyAssignedError):
                logger.exception("Cannot assign IPAddress %s", ip)
                sys.exit(1)

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
            logger.exception(
                "Container %s doesn't contain any endpoints", self.docker_id)
            sys.exit(1)

        # Remove any IP address assignments that this endpoint has
        ip_set = set()
        for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
            ip_set.add(net.ip)
        logger.info(
            "Removing IP addresses %s from endpoint %s", ip_set, endpoint.name)
        self._datastore_client.release_ips(ip_set)

        # Remove the veth interface from endpoint
        if CALICO_NETWORKING == 'true':
            logger.info(
                "Removing veth interface from endpoint %s", endpoint.name)
            try:
                netns.remove_veth(endpoint.name)
            except CalledProcessError:
                logger.exception("Could not remove veth interface from endpoint %s",
                                 endpoint.name)

        # Remove the container/endpoint from the datastore.
        try:
            self._datastore_client.remove_workload(
                HOSTNAME, ORCHESTRATOR_ID, self.docker_id)
            logger.info("Successfully removed workload from datastore")
        except KeyError:
            logger.exception("Failed to remove workload.")

        logger.info("Removed Calico interface from %s", self.docker_id)

    def _validate_container_state(self, container_name):
        info = self._get_container_info(container_name)

        # Check the container is actually running.
        if not info["State"]["Running"]:
            logger.error("The container is not currently running.")
            sys.exit(1)

        # We can't set up Calico if the container shares the host namespace.
        if info["HostConfig"]["NetworkMode"] == "host":
            logger.error(
                "Can't add the container to Calico because it is running NetworkMode = host.")
            sys.exit(1)

    def _get_container_info(self, container_name):
        try:
            info = self._docker_client.inspect_container(container_name)
        except APIError as e:
            if e.response.status_code == 404:
                logger.error(
                    "Container %s was not found. Exiting.", container_name)
            else:
                logger.error(e.message)
            sys.exit(1)
        return info

    def _get_container_pid(self, container_name):
        return self._get_container_info(container_name)["State"]["Pid"]

    def _read_docker_ip(self):
        """Get the IP for the pod's infra container."""
        ip = self._get_container_info(
            self.docker_id)["NetworkSettings"]["IPAddress"]
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
            logger.info('Using IP Address %s', addr)
            return addr
        except IndexError:
            # If both get_host_ips return empty lists, print message and exit.
            logger.exception('No Valid IP Address Found for Host - cannot '
                             'configure networking for pod %s. Exiting' % (self.pod_name))
            sys.exit(1)

    def _delete_docker_interface(self):
        """Delete the existing veth connecting to the docker bridge."""
        logger.info('Deleting docker interface eth0')

        # Get the PID of the container.
        pid = str(self._get_container_pid(self.docker_id))
        logger.info('Container %s running with PID %s', self.docker_id, pid)

        # Set up a link to the container's netns.
        logger.info("Linking to container's netns")
        logger.debug(check_output(['mkdir', '-p', '/var/run/netns']))
        netns_file = '/var/run/netns/' + pid
        if not os.path.isfile(netns_file):
            logger.debug(check_output(['ln', '-s', '/proc/' + pid + '/ns/net',
                                       netns_file]))

        # Reach into the netns and delete the docker-allocated interface.
        logger.debug(check_output(['ip', 'netns', 'exec', pid,
                                   'ip', 'link', 'del', 'eth0']))

        # Clean up after ourselves (don't want to leak netns files)
        logger.debug(check_output(['rm', netns_file]))

    def _get_pod_ports(self, pod):
        """
        Get the list of ports on containers in the Pod.

        :return list ports: the Kubernetes ContainerPort objects for the pod.
        """
        ports = []
        for container in pod['spec']['containers']:
            try:
                more_ports = container['ports']
                logger.info('Adding ports %s', more_ports)
                ports.extend(more_ports)
            except KeyError:
                pass
        return ports

    def _get_pod_config(self):
        """Get the list of pods from the Kube API server."""
        pods = self._get_api_path('pods')
        logger.debug('Got pods %s' % pods)

        for pod in pods:
            logger.debug('Processing pod %s', pod)
            if pod['metadata']['namespace'].replace('/', '_') == self.namespace and \
                    pod['metadata']['name'].replace('/', '_') == self.pod_name:
                this_pod = pod
                break
        else:
            raise KeyError('Pod not found: ' + self.pod_name)
        logger.debug('Got pod data %s', this_pod)
        return this_pod

    def _get_api_path(self, path):
        """Get a resource from the API specified API path.

        e.g.
        _get_api_path('pods')

        :param path: The relative path to an API endpoint.
        :return: A list of JSON API objects
        :rtype list
        """
        logger.info(
            'Getting API Resource: %s from KUBE_API_ROOT: %s', path, KUBE_API_ROOT)
        bearer_token = self._get_api_token()
        session = requests.Session()
        session.headers.update({'Authorization': 'Bearer ' + bearer_token})
        response = session.get(KUBE_API_ROOT + path, verify=False)
        response_body = response.text

        # The response body contains some metadata, and the pods themselves
        # under the 'items' key.
        return json.loads(response_body)['items']

    def _patch_api(self, path, patch):
        """
        Patch an api resource to a given path

        :param path: The relative path to an API endpoint.
        :param patch: The updated data
        :return: A list of JSON API objects
        :rtype list
        """
        logger.info(
            'Patching API Resource: %s from KUBE_API_ROOT: %s', path, KUBE_API_ROOT)
        logger.info('Patching API Resource: with %s', patch)
        bearer_token = self._get_api_token()
        session = requests.Session()
        session.headers.update({'Authorization': 'Bearer ' + bearer_token,
                                'Content-type': 'application/strategic-merge-patch+json'})
        response = session.patch(
            url=KUBE_API_ROOT+path, data=patch, verify=True)
        response_body = response.text

        return json.loads(response_body)

    def _get_api_token(self):
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
            logger.info(
                "Failed to open auth_file (%s), assuming insecure mode" % e)
            return ""

        logger.info('Got kubernetes_auth: ' + json_string)
        auth_data = json.loads(json_string)
        return auth_data['BearerToken']

    def _apply_rules(self):
        """
        Generate a default rules

        :return:
        """
        try:
            profile = self._datastore_client.get_profile(self.profile_name)
        except:
            logger.error(
                "Could not apply rules. Profile not found: %s, exiting", self.profile_name)
            sys.exit(1)

        # Determine rule set based on policy
        if CALICO_POLICY == 'true':
            default_rule = Rule(action="reject")
        else:
            default_rule = Rule(action="allow")

        rules = Rules(id=profile.name,
                      inbound_rules=[default_rule],
                      outbound_rules=[default_rule])

        # Write rules to profile
        rules_path = RULES_PATH % {"profile_id": profile.name}
        _datastore_client.etcd_client.write(
            RULES_PATH, rules.to_json())

        logger.info('Finished applying rules.')


if __name__ == '__main__':
    configure_logger(logger, LOG_LEVEL, True)
    configure_logger(pycalico_logger, LOG_LEVEL, False)

    mode = sys.argv[1]

    if mode == 'init':
        logger.info('No initialization work to perform')
    else:
        # These args only present for setup/teardown.
        namespace = sys.argv[2].replace('/', '_')
        pod_name = sys.argv[3].replace('/', '_')
        docker_id = sys.argv[4]

        logger.info('Args: %s' % sys.argv)
        logger.info("Using LOG_LEVEL=%s", LOG_LEVEL)
        logger.info("Using ETCD_AUTHORITY=%s", os.environ[ETCD_AUTHORITY_ENV])
        logger.info("Using CALICOCTL_PATH=%s", CALICOCTL_PATH)
        logger.info("Using KUBE_API_ROOT=%s", KUBE_API_ROOT)
        logger.info("Using CALICO_IPAM=%s", CALICO_IPAM)
        logger.info("Using CALICO_POLICY=%s", CALICO_POLICY)
        logger.info("Using CALICO_NETWORKING=%s", CALICO_NETWORKING)

        if mode == 'setup':
            logger.info('Executing Calico pod-creation hook')
            NetworkPlugin().create(namespace, pod_name, docker_id)
        elif mode == 'teardown':
            logger.info('Executing Calico pod-deletion hook')
            NetworkPlugin().delete(namespace, pod_name, docker_id)
        elif mode == 'status':
            logger.info('Executing Calico pod-status hook')
            NetworkPlugin().status(namespace, pod_name, docker_id)
