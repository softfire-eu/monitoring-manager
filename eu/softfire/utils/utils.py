import logging
import logging.config
import random, string, json, time
from org.openbaton.cli.agents.agents import OpenBatonAgentFactory
from sdk.softfire.utils import *

config_path = '/etc/softfire/monitoring-manager.ini'

def get_logger(config_path):
    logging.config.fileConfig(config_path)
    return logging.getLogger("monitoring-manager")

def random_string(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

def deploy_package(path, project_id) :
    ob_conf = get_config_parser(config_path)["open-baton"]

    '''Open Baton Login'''
    agent = ob_login(project_id)

    '''Upload the VNFP'''
    #TODO Problem if same version is already present
    vnfp_agent = agent.get_vnf_package_agent(project_id=project_id)
    vnfp = vnfp_agent.create(path)

    '''Create and upload the NSD'''
    #TODO fix
    nsd_file_path = "etc/resources/nsd-fw.json"

    nsd_agent = agent.get_ns_descriptor_agent(project_id)
    nsd = {}
    with open(nsd_file_path, "r") as fd:
        nsd = json.load(fd)
    nsd["vnfd"] = [{"id" : vnfp["id"]}]
    print(nsd)
    nsd = nsd_agent.create(json.dumps(nsd))

    '''Deploy of the NSR'''
    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
    nsr = nsr_agent.create(entity=nsd["id"])

    nsr_details = nsr_agent.find(nsr["id"])

    '''Assuming 1 VNFR, 1 VDU, 1 VNC_Instance, 1 Floating IP'''
    #floating_ip = nsr_details["vnfr"][0]["vdu"][0]["vnfc_instance"][0]["floatingIps"][0]
    floating_ip = "test"
    return nsr_details

def delete_ns(nsr_id, nsd_id, project_id) :

    agent = ob_login(project_id)
    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
    nsr_agent.delete(nsr_id)

    nsd_agent = agent.get_ns_descriptor_agent(project_id)
    time.sleep(5) #Give Open Baton time to process the request
    nsd_agent.delete(nsd_id)

def ob_login(project_id):
    ob_conf = get_config_parser(config_path)["open-baton"]

    '''Open Baton Login'''
    agent = OpenBatonAgentFactory(nfvo_ip=ob_conf["ip"], nfvo_port=int(ob_conf["port"]),
                                  https=(ob_conf["https"] == "True"), version=int(ob_conf["version"]),
                                  username=ob_conf["username"], password=ob_conf["password"], project_id=project_id)
    return agent