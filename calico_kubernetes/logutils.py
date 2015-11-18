#!/bin/python
import logging
import os
import sys

from cloghandler import ConcurrentRotatingFileHandler
from monotime import monotonic


LOG_DIR = '/var/log/calico/kubernetes/'
ROOT_LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(message)s'
DOCKER_ID_ROOT_LOG_FORMAT = '%(asctime)s %(process)d [%(identity)s] %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'
DOCKER_ID_LOG_FORMAT = '%(asctime)s %(process)d [%(identity)s] %(levelname)s %(filename)s: %(message)s'


def configure_logger(logger, log_level, docker_id=None, log_format=LOG_FORMAT,
                     log_to_stdout=True, log_dir=LOG_DIR):
    """
    Configures logging to the file 'calico.log' in the specified log directory

    If the logs are not coming from calico_kubernetes.py, format the log to
     include the filename of origin

    Additionally configures a stdout handler which logs INFO and
    above to stdout.

    :param logger: logger object to configure
    :param log_level: level at which logger starts logging.
    :param log_format: Indicates which logging scheme to use.
    :param log_to_stdout: If True, configure the stdout stream handler.
    :param log_dir: Directory where calico.log lives. If None set to default
    :return:
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    formatter = logging.Formatter(log_format)
    docker_filter = IdentityFilter(identity=docker_id)

    file_hdlr = ConcurrentRotatingFileHandler(filename=log_dir+'calico.log',
                                              maxBytes=1000000,
                                              backupCount=5)
    file_hdlr.setFormatter(formatter)
    if docker_id:
        file_hdlr.addFilter(docker_filter)

    logger.addHandler(file_hdlr)
    logger.setLevel(log_level)

    # Create an stdout handler and apply it to the logger
    if log_to_stdout:
        stdout_hdlr = logging.StreamHandler(sys.stdout)
        stdout_hdlr.setLevel(log_level)
        stdout_hdlr.setFormatter(formatter)
        if docker_id:
            stdout_hdlr.addFilter(docker_filter)
        logger.addHandler(stdout_hdlr)

class IdentityFilter(logging.Filter):
    """
    Filter class to impart contextual identity information onto loggers.
    """
    def __init__(self, identity):
        self.identity = identity

    def filter(self, record):
        record.identity = self.identity
        return True


class ExecutionTimer(object):
    def __init__(self, logger):
        self.logger = logger
        self.start_time = None
        self.last_mark = None

    def start(self):
        """
        Start the execution timer.
        """
        time = monotonic()
        self.start_time = time
        self.last_mark = time
        self.logger.debug("[timer] Starting execution")

    def end(self):
        # Log full execution.
        self.mark("Finished execution")

        # Clear
        self.start_time = None
        self.last_mark = None

    def mark(self, message):
        """
        Logs time since last mark, as well as from beginning.
        """
        now = monotonic()
        last = now - self.last_mark
        total = now - self.start_time
        self.last_mark = now
        self.logger.debug("[timer] %s: %s (%s total)", message, last, total)
