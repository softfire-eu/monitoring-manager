import yaml,random

from threading import Thread
from sdk.softfire.manager import AbstractManager

from eu.softfire.exceptions.monitoring.exceptions import *
from eu.softfire.utils.monitoring.utils import *

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
            
        self.testbeds = []
        for t in self.openstack_credentials.keys():
            self.testbeds.append(t)

        self.usersData = {}

        self.ZabbixServerName = self.get_config_value("openstack-params", "instance_name", "")
        self.ZabbixServerFlavour = self.get_config_value("openstack-params", "flavour", "")
        self.ZabbixServerImageName = self.get_config_value("openstack-params", "image_name", "")
        self.ZabbixServerSecGroups = self.get_config_value("openstack-params", "security_group", "")

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
        #logger.debug("List resources")
        resource_id = "monitor"
        description = "This resource permits to deploy a ZabbixServer"
        cardinality = 1
        testbed = messages_pb2.ANY
        node_type = "MonitoringResource"
        result = []
        result.append(
            messages_pb2.ResourceMetadata(resource_id=resource_id, description=description, cardinality=cardinality,
                                          node_type=node_type, testbed=testbed))
        return result

    def getOpenstack(self, username):

        current_testbed = self.usersData[username]["testbed"]
        log_header = get_log_header(username,current_testbed)
        
        if "nova" not in self.usersData[username]:  #clients (nova, neutron) have to be in the userdata, since openstack tenants are user bounded
            
            from keystoneauth1 import loading
            from keystoneauth1 import session
            from novaclient import client
            from neutronclient.v2_0 import client as nclient
            from keystoneauth1.identity import v2, v3
            
            if self.openstack_credentials[self.usersData[username]["testbed"]]["api_version"]==2:
                logger.info("{}connecting to {} using v2 auth".format(log_header,self.openstack_credentials[self.usersData[username]["testbed"]]["auth_url"]))
                OSloader = loading.get_plugin_loader('password')
                OSauth = OSloader.load_from_options(
                    auth_url=self.openstack_credentials[self.usersData[username]["testbed"]]["auth_url"],
                    username=self.openstack_credentials[self.usersData[username]["testbed"]]["username"],
                    password=self.openstack_credentials[self.usersData[username]["testbed"]]["password"],
                    tenant_name=self.openstack_credentials[self.usersData[username]["testbed"]]["tenant_name"],
                )
                
            if self.openstack_credentials[self.usersData[username]["testbed"]]["api_version"]==3:
                logger.info("{}connecting to {} using v3 auth".format(log_header,self.openstack_credentials[self.usersData[username]["testbed"]]["auth_url"]))
                OSauth = v3.Password(
                    auth_url=self.openstack_credentials[self.usersData[username]["testbed"]]["auth_url"],
                    username=self.openstack_credentials[self.usersData[username]["testbed"]]["username"],
                    password=self.openstack_credentials[self.usersData[username]["testbed"]]["password"],
                    user_domain_name=self.openstack_credentials[self.usersData[username]["testbed"]]["user_domain_name"],
                    project_id=self.openstack_credentials[self.usersData[username]["testbed"]]["project_id"],
                )

            OSsession = session.Session(auth=OSauth)
            
            self.usersData[username]["nova"] = client.Client( 2, session=OSsession)
            self.usersData[username]["neutron"] = nclient.Client(session=OSsession)

    def provide_resources(self, user_info, payload=None):
        #logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.info("***Requested*** provide_resources by user |%s|" % (user_info.name))
        # logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        
        username = user_info.name
        self.getOpenstack(username)
        
        extended_name = self.ZabbixServerName + "_" + username
        
        current_testbed = self.usersData[username]["testbed"]
        userNova = self.usersData[username]["nova"]
        userNeutron = self.usersData[username]["neutron"]
        lan_name= self.usersData[username]["lan_name"]
        
        log_header = get_log_header(username,current_testbed)
        
        logger.info("{}preparing to create zabbix server".format(log_header))
        
        for s in userNova.servers.list():

            if s.name==extended_name:

                self.usersData[username]["serverInstance"]=s
                self.usersData[username]["floatingIp"] = s.networks[lan_name][1]
                self.usersData[username]["internalIp"] = s.networks[lan_name][0]
                self.usersData[username]["output"]={
                    "testbed" : self.usersData[username]["testbed"],
                    "internalIp" : self.usersData[username]["internalIp"],
                    "floatingIpIp" : self.usersData[username]["floatingIp"],
                    "url" : "http://{}/zabbix/".format(self.usersData[username]["floatingIp"]),
                    "username" : "Admin",
                    "password" : "zabbix",
                }
                logger.info("{}zabbix server already online".format(log_header))
                logger.info(json.dumps(self.usersData[username]["output"]))
                return [json.dumps(self.usersData[username]["output"])]
                break

        if self.usersData[username]["serverInstance"] is None:
            logger.info("{}no zabbix server found, preparing to create it".format(log_header))
            NewServer = userNova.servers.create(
                name=extended_name,
                image=userNova.glance.find_image(self.ZabbixServerImageName),
                flavor=userNova.flavors.find(name=self.ZabbixServerFlavour),
                nics=[{'net-id': userNova.neutron.find_network(lan_name).id}],
                security_groups=[self.ZabbixServerSecGroups],
            )
            id = NewServer.id
            logger.info("{}zabbix server created, id is {}".format(log_header,id))

            while 1:
                NewServer = userNova.servers.get(id)
                status = NewServer.status
                logger.info("{}zabbix server status: {}".format(log_header,status))
                if status != "BUILD":
                    break
                time.sleep(0.3)

            self.usersData[username]["internalIp"] = NewServer.networks[lan_name][0]

            floatingIp_toAdd = None
            flips = userNeutron.list_floatingips()
            for ip in flips["floatingips"]:
                if ip["fixed_ip_address"] == None:
                    floatingIp_toAdd = ip["floating_ip_address"]
                    break

            if floatingIp_toAdd == None:
                body = {
                    "floatingip": {
                        "floating_network_id": self.usersData[username]["nova"].neutron.find_network("public").id
                    }}
                userNeutron.create_floatingip(body=body)
                flips = userNeutron.list_floatingips()
                for ip in flips["floatingips"]:
                    if ip["fixed_ip_address"] == None:
                        floatingIp_toAdd = ip["floating_ip_address"]
                        break

            if floatingIp_toAdd:
                logger.info("{}adding floating ip {}".format(log_header,floatingIp_toAdd))
                NewServer.add_floating_ip(floatingIp_toAdd)
                NewServer = userNova.servers.get(id)
                logger.info("{}floating ip added".format(log_header))
                self.usersData[username]["floatingIp"] = floatingIp_toAdd
            else:
                self.usersData[username]["floatingIp"] = "UNABLE TO ASSOCIATE"

            self.usersData[username]["serverInstance"] = NewServer
            logger.info("{}zabbix deployed to {}".format(log_header,self.usersData[username]["serverInstance"].networks))

            self.usersData[username]["output"]={
                "testbed" : self.usersData[username]["testbed"],
                "internalIp" : self.usersData[username]["internalIp"],
                "floatingIpIp" : self.usersData[username]["floatingIp"],
                "url" : "http://{}/zabbix/".format(self.usersData[username]["floatingIp"]),
                "username" : "Admin",
                "password" : "zabbix",
                }
                
            return [json.dumps(self.usersData[username]["output"])]
            
        return {}

    def validate_resources(self, user_info=None, payload=None) -> None:
        print()
        print()
        logger.info("***Requested*** validate_resources by user |%s|" % (user_info.name))

        if user_info.name == '':

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
        
        lan_name = resource.get("properties").get("lan_name")

        self.usersData[user_info.name] = {}
        self.usersData[user_info.name]["testbed"] = testbed
        self.usersData[user_info.name]["lan_name"] = lan_name
        self.usersData[user_info.name]["internalIp"] = None
        self.usersData[user_info.name]["floatingIp"] = None
        self.usersData[user_info.name]["serverInstance"] = None

    def release_resources(self, user_info, payload=None):
        logger.info("***Requested*** release_resources by user |%s|" % (user_info.name))
        #logger.debug("Requested release_resources payload |%s|" % (payload))
        username = user_info.name
        resource = yaml.load(payload)
        
        current_testbed = self.usersData[username]["testbed"]

        try:
            testbed = resource.get("testbed")
        except:
            logger.info("***ERROR*** release_resources |%s|" % (resource))
            return

        if testbed:
            if username not in self.usersData:
                self.usersData[username]={}
                self.usersData[username]["testbed"]=testbed

            log_header = get_log_header(username,testbed)
            
            logger.info("{}preparing to delete zabbix server".format(log_header))
            
            self.getOpenstack(username)
            
            extended_name = self.ZabbixServerName + "_" + username
            userNova = self.usersData[username]["nova"]
            
            for s in userNova.servers.list():
                if s.name==extended_name:
                    self.usersData[username]["serverInstance"]=s
                    break
            if self.usersData[username]["serverInstance"]:
                logger.info("{}zabbix server to delete found: {}".format(log_header,extended_name))
                self.usersData[username]["serverInstance"].delete()
                logger.info("{}zabbix server deleted".format(log_header))
            else:
                logger.info("{}zabbix server not found, nothing done".format(log_header))
            
            del(self.usersData[username])
        
        else:
            return
            
    def _update_status(self) -> dict:
        # logger.debug("_update_status")
        result = {}
        for exps in self.usersData.keys():
            if "output" in self.usersData[exps]:
                #logger.debug(self.usersData[exps]["output"])
                result[exps] = []
                result[exps].append(json.dumps(self.usersData[exps]["output"]))
                
        #print (result)
        return result
