from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2
from IPy import IP
from eu.softfire.utils.utils import *
from eu.softfire.exceptions.exceptions import *
import yaml, os
import sqlite3, requests, tarfile, shutil
from threading import Thread

logger = get_logger(config_path)

class UpdateStatusThread(Thread):
    def __init__(self, manager):
        Thread.__init__(self)
        self.stopped = False
        self.manager = manager

    def run(self):
        while not self.stopped:
            time.sleep(int(self.manager.get_config_value('system', 'update-delay', '10')))
            if not self.stopped:
                #try:
                self.manager.send_update()
                #except Exception as e:
                #    logger.error("got error while updating resources: %s " % e.args)

    def stop(self):
        self.stopped = True


class MonitoringManager(AbstractManager):

    def __init__(self, config_path):
        super(MonitoringManager, self).__init__(config_path)
        self.local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/monitoring-manager")
            
        os.environ["OS_USERNAME"]               = self.get_config_value("openstack-env", "OS_USERNAME", "")
        os.environ["OS_PASSWORD"]               = self.get_config_value("openstack-env", "OS_PASSWORD", "")
        os.environ["OS_AUTH_URL"]               = self.get_config_value("openstack-env", "OS_AUTH_URL", "")
        os.environ["OS_IDENTITY_API_VERSION"]   = self.get_config_value("openstack-env", "OS_IDENTITY_API_VERSION", "")
        os.environ["OS_TENANT_NAME"]            = self.get_config_value("openstack-env", "OS_TENANT_NAME", "")
        
        
        from keystoneauth1 import loading
        from keystoneauth1 import session
        from novaclient import client
        self.OSloader = loading.get_plugin_loader('password')
        self.OSauth = self.OSloader.load_from_options(auth_url=os.environ["OS_AUTH_URL"],
                                        username=os.environ["OS_USERNAME"],
                                        password=os.environ["OS_PASSWORD"],
                                        tenant_name=os.environ["OS_TENANT_NAME"])
        self.OSsession = session.Session(auth=self.OSauth)
        self.OSnova = client.Client(os.environ["OS_IDENTITY_API_VERSION"], session=self.OSsession)
        
        self.ZabbixServerName=self.get_config_value("openstack-params", "instance_name", "")
        self.ZabbixServerFloatingIp=self.get_config_value("openstack-params", "floating_ip", "")
        self.ZabbixServerFlavour=self.get_config_value("openstack-params", "flavour", "")
        self.ZabbixServerImageName=self.get_config_value("openstack-params", "image_name", "")
        self.ZabbixServerSecGroups=self.get_config_value("openstack-params", "security_group", "")
        self.ZabbixServerNetwork=self.get_config_value("openstack-params", "network", "")
        
        self.ZabbixInternalStatus="NONE" #NONE, FLOATING, ACTIVE
        self.JobInternalStatus="NONE" #NONE, TOCREATE, TODELETE
        self.ZabbixServerInternaIp=None
        self.ZabbixServerUserCreator=None
        self.expDeployed=False
        
    def create_user(self, username, password):
        user_info = messages_pb2.UserInfo(
            name=username,
            password=password,
            ob_project_id='id',
            testbed_tenants={}
        )
        print(user_info)
        return user_info
        
    def refresh_resources(self, user_info):
        logger.info("refresh_resources")
        return None

    def list_resources(self, user_info=None, payload=None):
        logger.debug("List resources")
        resource_id = "monitor"
        description = "This resource permits to deploy a ZabbixServer"
        cardinality = 1
        testbed = messages_pb2.ANY
        node_type = "MonitoringResource"
        result = []
        result.append(messages_pb2.ResourceMetadata(resource_id=resource_id, description=description, cardinality=cardinality, node_type=node_type, testbed=testbed))
        return result

    def provide_resources(self, user_info, payload=None):
        logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.debug("payload: %s" % payload)
        response = []
        return response

    def validate_resources(self, user_info=None, payload=None) -> None:
        logger.info("Requested validate_resources by user %s\n Payload %s" % (user_info.name,payload))
        resource = yaml.load(payload)
        if self.JobInternalStatus == "NONE":
            self.JobInternalStatus = "TOCREATE"
    
    def release_resources(self, user_info, payload=None):
        logger.info("Requested release_resources by user %s\n Payload %s" % (user_info.name,payload))
        if self.JobInternalStatus == "NONE":
            self.JobInternalStatus = "TODELETE"
        return

    def _update_status(self) -> dict:
    
        self.ZabbixServerInstance=None
        self.ZabbixServerIpAttached=False
        
        for s in self.OSnova.servers.list():
            if s.name==self.ZabbixServerName:
                self.ZabbixServerInstance=s
                for n in self.ZabbixServerInstance.networks.keys():
                    for ip in self.ZabbixServerInstance.networks[n]:                    
                        if str(ip)==self.ZabbixServerFloatingIp:
                            self.ZabbixServerIpAttached=True
                        else:
                            self.ZabbixServerInternaIp=ip
                break
        
        if self.ZabbixServerInstance:
            if self.ZabbixServerIpAttached:
                self.ZabbixInternalStatus="ACTIVE"
            else:
                self.ZabbixInternalStatus="FLOATING"       
        else:
                self.ZabbixInternalStatus="NONE"
        
        logger.info("ZabbixServerStatus {:>10}   JobStatus {:>10}".format(self.ZabbixInternalStatus,self.JobInternalStatus) )
        
        if self.JobInternalStatus == "TOCREATE":
            self.JobInternalStatus = "NONE"
            NewServer = self.OSnova.servers.create(
                            name=self.ZabbixServerName, 
                            image=self.OSnova.glance.find_image(self.ZabbixServerImageName), 
                            flavor=self.OSnova.flavors.find(name=self.ZabbixServerFlavour), 
                            nics=[{'net-id': self.OSnova.neutron.find_network(self.ZabbixServerNetwork).id}],
                            security_groups=[self.ZabbixServerSecGroups],
                            )
            id=NewServer.id   

            while 1:
                NewServer=self.OSnova.servers.get(id)
                status=NewServer.status
                if status!="BUILD":
                    break
                time.sleep(0.3)
            
            NewServer.add_floating_ip(self.ZabbixServerFloatingIp)
            self.ZabbixServerInstance = NewServer
            self.expDeployed = True

        if self.JobInternalStatus == "TODELETE":
            self.JobInternalStatus = "NONE"
            if self.ZabbixServerInstance:
                self.ZabbixServerInstance.delete()
                self.ZabbixServerInstance=None
                self.ZabbixServerInternaIp=None
                self.ZabbixInternalStatus="NONE"
            self.expDeployed = False
 
        if self.JobInternalStatus == "NONE":
            self.expDeployed = False
            
        result = {}
        s = {}
        
        s["status"] = self.ZabbixInternalStatus
        s["internalIp"] = self.ZabbixServerInternaIp
        
        result["root"] = []
        result["root"].append(json.dumps(s))
        if self.expDeployed:
            print(result)
            return result
        else:
            return {}
