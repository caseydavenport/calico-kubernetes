#!/usr/bin/python
import os
import time
import json
import requests
import Queue
from threading import Thread
from subprocess import check_output
from contextlib import closing
from daemon import runner

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://kubernetes-master:8080/api/v1/')
POLICY_LOG_DIR = "/var/log/calico/calico-policy"
POLICY_LOG = "%s/calico-policy.log"

class PolicyDaemon():

    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/tty'
        self.stderr_path = '/dev/tty'
        self.pidfile_path = '/tmp/calico-policy.pid'
        self.pidfile_timeout = None
        self.q = Queue.Queue()
        self.watcher = Thread(target=_keep_watch, args=(self.q, "pods"))
        self.watcher.daemon = True

    def run(self):
        self.watcher.start()

        while True:
            self.read_responses()
            time.sleep(1)

    def read_responses(self):
        try:
            response = self.q.get_nowait()
            print(time.asctime(time.localtime()))
            print(response)

        except Queue.Empty:
            pass


def _keep_watch(queue, path):
    # print("keep watch")
    response = _get_api_path("%s?watch=true" % path)
    # print("response %s" % response.text)
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
    return session.get("%s%s" % (KUBE_API_ROOT, path), verify=False, stream=True)

app = PolicyDaemon()
daemon_runner = runner.DaemonRunner(app)
daemon_runner.do_action()
