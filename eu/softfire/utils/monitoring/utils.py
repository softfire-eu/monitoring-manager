import logging
import logging.config
import random, string, json, time,os
from sdk.softfire.utils import *

config_path = '/etc/softfire/monitoring-manager.ini'

def get_logger(config_path):
    logging.config.fileConfig(config_path)
    return logging.getLogger("monitoring-manager")

def random_string(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

