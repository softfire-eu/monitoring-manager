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

def get_log_header(username,current_testbed):
    return "{}@{} - ".format(username,current_testbed)

def get_username_hash(username):
    return abs(hash(username))

def get_router_from_name(user_neutron, router_name, ext_net_id):
        for router in user_neutron.list_routers()['routers']:
            if router['name'] == router_name:
                return user_neutron.show_router(router['id'])
        request = {'router': {'name': router_name, 'admin_state_up': True}}
        router = user_neutron.create_router(request)
        body_value = {"network_id": ext_net_id}
        user_neutron.add_gateway_router(router=router['router']['id'], body=body_value)
        return router