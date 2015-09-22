import os

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT', 'http://localhost:8080/api/v1/')
ANNOTATION_NAMESPACE = "projectcalico.org/"
EPID_ANNOTATION_KEY = "%sendpointID" % ANNOTATION_NAMESPACE
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
DEFAULT_PROFILE_REJECT = "REJECT_ALL"
DEFAULT_PROFILE_ACCEPT = "ALLOW_ALL"