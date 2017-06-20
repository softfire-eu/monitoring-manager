import logging
import logging.config
import random, string, json, time,os
from org.openbaton.cli.agents.agents import OpenBatonAgentFactory
from sdk.softfire.utils import *

config_path = '/etc/softfire/monitoring-manager.ini'

def get_logger(config_path):
    logging.config.fileConfig(config_path)
    return logging.getLogger("monitoring-manager")

def random_string(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

    
def get_keystone_creds():
    d = {}
    d['username'] = os.environ['OS_USERNAME']
    d['password'] = os.environ['OS_PASSWORD']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    d['tenant_name'] = os.environ['OS_TENANT_NAME']
    return d
 
def get_nova_creds():
    d = {}
    d['username'] = os.environ['OS_USERNAME']
    d['password'] = os.environ['OS_PASSWORD']
    d['auth_url'] = os.environ['OS_AUTH_URL']
    d['project_id'] = os.environ['OS_TENANT_NAME']
    d['version'] = os.environ['OS_IDENTITY_API_VERSION']
    return d
