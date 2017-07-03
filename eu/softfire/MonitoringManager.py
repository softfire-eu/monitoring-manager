from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2

from eu.softfire.utils.monitoring.utils import *
from eu.softfire.exceptions.monitoring.exceptions import *

import yaml, os
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
                    self.manager.send_update()
                   
    def stop(self):
        self.stopped = True

class MonitoringManager(AbstractManager):

    def __init__(self, config_path):
        super(MonitoringManager, self).__init__(config_path)
        
        credentials_files_path = self.get_config_value("openstack-credentials", "credentials_file", "")
        with open(credentials_files_path) as json_data:
            self.openstack_credentials = json.load(json_data)
        
        self.testbeds=[]
        for t in self.openstack_credentials.keys():
            self.testbeds.append(t)
        
        self.usersData = {}
        
        self.ZabbixServerName=self.get_config_value("openstack-params", "instance_name", "")
        self.ZabbixServerFlavour=self.get_config_value("openstack-params", "flavour", "")
        self.ZabbixServerImageName=self.get_config_value("openstack-params", "image_name", "")
        self.ZabbixServerSecGroups=self.get_config_value("openstack-params", "security_group", "")
        self.ZabbixServerNetwork=self.get_config_value("openstack-params", "network", "")

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

    def getOpenstack(self,username):
        if self.usersData[username]["nova"] is None:
            from keystoneauth1 import loading
            from keystoneauth1 import session
            from novaclient import client
            from neutronclient.v2_0 import client as nclient
            OSloader = loading.get_plugin_loader('password')
            OSauth = OSloader.load_from_options(
                                            auth_url        =       self.openstack_credentials[self.usersData[username]["testbed"]]["auth_url"],
                                            username        =       self.openstack_credentials[self.usersData[username]["testbed"]]["username"],
                                            password        =       self.openstack_credentials[self.usersData[username]["testbed"]]["password"],
                                            tenant_name     =       self.openstack_credentials[self.usersData[username]["testbed"]]["tenant_name"],
                                            )

            OSsession = session.Session(auth=OSauth)
            self.usersData[username]["nova"] = client.Client(self.openstack_credentials[self.usersData[username]["testbed"]]["api_version"], session=OSsession)
            self.usersData[username]["neutron"] = nclient.Client(session=OSsession)

    def provide_resources(self, user_info, payload=None):
        #logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.info("preparing to create zabbix server")
        username = user_info.name
        self.getOpenstack(username)
        extended_name = self.ZabbixServerName + "_" + username
        for s in self.usersData[username]["nova"].servers.list():
            if s.name==extended_name:
                self.usersData[username]["serverInstance"]=s
                logger.info("zabbix server already online")
                break
                
        if self.usersData[username]["serverInstance"] is None:
            logger.info("no zabbix server found, preparing to create it")
            NewServer = self.usersData[username]["nova"].servers.create(
                            name=extended_name, 
                            image=self.usersData[username]["nova"].glance.find_image(self.ZabbixServerImageName), 
                            flavor=self.usersData[username]["nova"].flavors.find(name=self.ZabbixServerFlavour), 
                            nics=[{'net-id': self.usersData[username]["nova"].neutron.find_network(self.ZabbixServerNetwork).id}],
                            security_groups=[self.ZabbixServerSecGroups],
                            )
            id=NewServer.id
            logger.info("zabbix server created, id is {}".format(id))

            while 1:
                NewServer=self.usersData[username]["nova"].servers.get(id)
                status=NewServer.status
                logger.info("zabbix server status: {}".format(status))
                if status!="BUILD":
                    break
                time.sleep(0.3)
            
            self.usersData[username]["internalIp"] = NewServer.networks[self.ZabbixServerNetwork][0]
            
            floatingIp_toAdd=None
            flips = self.usersData[username]["neutron"].list_floatingips()
            for ip in flips["floatingips"]:
                if ip["fixed_ip_address"]==None:
                    floatingIp_toAdd = ip["floating_ip_address"]
                    break

            if floatingIp_toAdd==None:
                
                body = {
                    "floatingip": {
                        "floating_network_id": self.usersData[username]["nova"].neutron.find_network("public").id
                            }}
                self.usersData[username]["neutron"].create_floatingip(body=body)
                flips = self.usersData[username]["neutron"].list_floatingips()
                for ip in flips["floatingips"]:
                    if ip["fixed_ip_address"]==None:
                        floatingIp_toAdd = ip["floating_ip_address"]
                        break
            
            if floatingIp_toAdd:
                logger.info("adding floating ip {}".format(floatingIp_toAdd))
                NewServer.add_floating_ip(floatingIp_toAdd)
                NewServer=self.usersData[username]["nova"].servers.get(id)
                logger.info("floating ip added")
                self.usersData[username]["floatingIp"] = floatingIp_toAdd
            else:
                self.usersData[username]["floatingIp"] = "UNABLE TO ASSOCIATE"
            
            self.usersData[username]["serverInstance"] = NewServer
            logger.info("zabbix deployed to {}".format(self.usersData[username]["serverInstance"].networks))

            self.usersData[username]["output"]={
                "testbed" : self.usersData[username]["testbed"],
                "internalIp" : self.usersData[username]["internalIp"],
                "floatingIpIp" : self.usersData[username]["floatingIp"],
                "url" : "http://{}/zabbix/".format(self.usersData[username]["floatingIp"]),
                "username" : "Admin",
                "password" : "zabbix",
                }
                
            return json.dumps(self.usersData[username]["output"])
            
        return {}

    def validate_resources(self, user_info=None, payload=None) -> None:
        
        logger.info("Requested validate_resources by user |%s|" % (user_info.name))
        
        if user_info.name=='':
            raise MonitoringResourceValidationError(
                    message="user not configured as experimenter"
                    )
        
        try:
            resource = yaml.load(payload)
        except:
            return
            
        testbed = resource.get("properties").get("testbed")
        if testbed not in self.testbeds:
            raise MonitoringResourceValidationError(
                    message="testbed not available"
                    )
        
        self.usersData[user_info.name]={}
        self.usersData[user_info.name]["testbed"]=testbed
        self.usersData[user_info.name]["internalIp"]=None
        self.usersData[user_info.name]["floatingIp"]=None
        self.usersData[user_info.name]["serverInstance"]=None
        self.usersData[user_info.name]["nova"]=None
        self.usersData[user_info.name]["neutron"]=None

    def release_resources(self, user_info, payload=None):
        logger.debug("Requested release_resources by user |%s|" % (user_info.name))
        logger.debug("Requested release_resources payload |%s|" % (payload))
        logger.info("preparing to delete zabbix server")
        username = user_info.name
        resource = yaml.load(payload)
        testbed = resource.get("testbed")
        if testbed:
            if username not in self.usersData:
                self.usersData[username]={}
                self.usersData[username]["testbed"]=testbed
                self.usersData[user_info.name]["nova"]=None
                self.usersData[user_info.name]["neutron"]=None
                
            self.getOpenstack(username)
            
            extended_name = self.ZabbixServerName + "_" + username
            
            for s in self.usersData[username]["nova"].servers.list():
                if s.name==extended_name:
                    self.usersData[username]["serverInstance"]=s
                    break
            if self.usersData[username]["serverInstance"]:
                logger.info("zabbix server to delete found: {}".format(extended_name))
                self.usersData[username]["serverInstance"].delete()
                logger.info("zabbix server deleted")
            else:
                logger.info("zabbix server not found, nothing done")
            
            del(self.usersData[username])
        
        else:
            return
            

    def _update_status(self) -> dict:
        logger.debug("_update_status")
        result = {}
        for exps in self.usersData.keys():
            if "output" in self.usersData[exps]:
                logger.debug(self.usersData[exps]["output"])
                result[exps] = []
                result[exps].append(json.dumps(self.usersData[exps]["output"]))
        return result
        
