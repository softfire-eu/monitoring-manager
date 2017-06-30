from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2

from eu.softfire.utils.monitoring.utils import *
from eu.softfire.exceptions.monitoring.exceptions import *

import yaml, os
import requests

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

                if self.manager.updating==True:
                    pass
                else:
                    self.manager.send_update()

                   
    def stop(self):
        self.stopped = True


class MonitoringManager(AbstractManager):

    def __init__(self, config_path):
        super(MonitoringManager, self).__init__(config_path)
        #self.local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/monitoring-manager")
            
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
        self.ZabbixServerInternalIp=None
        self.ZabbixServerCurrentFloatingIp=None
        self.ZabbixServerUserCreator=None
        self.ZabbixServerInstance=None
        self.expDeployed=False
        
        self.updating = False
        
        
    def create_user(self, username, password):
        user_info = messages_pb2.UserInfo(
            name=username,
            password=password,
            ob_project_id='id',
            testbed_tenants={}
        )
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
        logger.info("Requested validate_resources by user |%s|" % (user_info.name))
        resource = yaml.load(payload)
        self.ZabbixServerUserCreator = user_info.name
        if self.JobInternalStatus == "NONE":
            self.JobInternalStatus = "TOCREATE"
            
    def release_resources(self, user_info, payload=None):
        logger.info("Requested release_resources by user |%s|" % (user_info.name))
        if self.JobInternalStatus == "NONE":
            self.JobInternalStatus = "TODELETE"
            
    def _update_status(self) -> dict:
        
        self.updating = True
        
        if self.JobInternalStatus == "TODELETE":
            logger.info("preparing to delete zabbix server")
            self.JobInternalStatus = "NONE"
            for s in self.OSnova.servers.list():
                if s.name==self.ZabbixServerName:
                    self.ZabbixServerInstance=s
                    break
            if self.ZabbixServerInstance:
                logger.info("zabbix server to delete found")
                self.ZabbixServerInstance.delete()
                logger.info("zabbix server deleted")
                self.ZabbixServerInstance=None
                self.ZabbixServerInternalIp=None
                self.ZabbixServerCurrentFloatingIp=None
                self.ZabbixInternalStatus="NONE"
            else:
                logger.info("zabbix server not found, nothing done")
            self.expDeployed = False
            logger.info("ZabbixServerStatus {:>10}".format(self.ZabbixInternalStatus) )
            self.updating = False
            return {}
        
        if self.JobInternalStatus == "TOCREATE":
            logger.info("preparing to create zabbix server")
            self.JobInternalStatus = "NONE"
            for s in self.OSnova.servers.list():
                if s.name==self.ZabbixServerName:
                    self.ZabbixServerInstance=s
                    logger.info("zabbix server already online")
                    break
            if self.ZabbixServerInstance is None:
                logger.info("no zabbix server found, preparing to create it")
                NewServer = self.OSnova.servers.create(
                                name=self.ZabbixServerName, 
                                image=self.OSnova.glance.find_image(self.ZabbixServerImageName), 
                                flavor=self.OSnova.flavors.find(name=self.ZabbixServerFlavour), 
                                nics=[{'net-id': self.OSnova.neutron.find_network(self.ZabbixServerNetwork).id}],
                                security_groups=[self.ZabbixServerSecGroups],
                                )
                id=NewServer.id
                logger.info("zabbix server created, id is {}".format(id))

                while 1:
                    NewServer=self.OSnova.servers.get(id)
                    status=NewServer.status
                    logger.info("zabbix server status: {}".format(status))
                    if status!="BUILD":
                        break
                    time.sleep(0.3)
                    
                logger.info("adding floating ip {}".format(self.ZabbixServerFloatingIp))
                NewServer.add_floating_ip(self.ZabbixServerFloatingIp)
                NewServer=self.OSnova.servers.get(id)
                logger.info("floating ip added")
                self.ZabbixServerInstance = NewServer
                logger.info("zabbix deployed to {}".format(self.ZabbixServerInstance.networks))
                self.expDeployed = True
        
        else:
            self.ZabbixServerInstance=None
            self.ZabbixServerIpAttached=False        
            for s in self.OSnova.servers.list():
                if s.name==self.ZabbixServerName:
                    self.ZabbixServerInstance=s
                    break
        
        if self.ZabbixServerInstance:

            for n in self.ZabbixServerInstance.networks.keys():
                for ip in self.ZabbixServerInstance.networks[n]:                    
                    if str(ip)==self.ZabbixServerFloatingIp:
                        self.ZabbixServerIpAttached=True
                    else:
                        self.ZabbixServerInternalIp=ip
                break

            if self.ZabbixServerIpAttached:
                self.ZabbixInternalStatus="ACTIVE"
                self.ZabbixServerCurrentFloatingIp=self.ZabbixServerFloatingIp
            else:
                self.ZabbixInternalStatus="FLOATING"   
                self.ZabbixServerCurrentFloatingIp="---------"   
                
        else:
                self.ZabbixInternalStatus="NONE"

        if self.ZabbixServerInstance is None:
            self.expDeployed = False
        
        logger.info("ZabbixServerStatus {:>10}".format(self.ZabbixInternalStatus) )
        
        self.updating = False
        
        if self.expDeployed:
    
            result = {}
            s = {}
            
            s["status"] = self.ZabbixInternalStatus
            #s["internalIp"] = self.ZabbixServerInternalIp
            s["floatingIpIp"] = self.ZabbixServerCurrentFloatingIp
            s["url"] = "http://{}/zabbix/".format(s["floatingIpIp"])
            s["username"] = "Admin"
            s["password"] = "zabbix"
            
            result[self.ZabbixServerUserCreator] = []
            result[self.ZabbixServerUserCreator].append(json.dumps(s))

            return result
            
        else:
        
            return {}
