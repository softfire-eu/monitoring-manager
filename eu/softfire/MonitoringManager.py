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
        self.connectionClients = {}
        for t in self.openstack_credentials.keys():
            self.testbeds.append(t)
            self.connectionClients[t]={}

        self.usersData = {}

        self.ZabbixServerName = self.get_config_value("openstack-params", "instance_name", "")
        self.ZabbixServerFlavour = self.get_config_value("openstack-params", "flavour", "")
        self.ZabbixServerImageName = self.get_config_value("openstack-params", "image_name", "")
        self.ZabbixServerSecGroups = self.get_config_value("openstack-params", "security_group", "")
        self.ZabbixServerNetwork = self.get_config_value("openstack-params", "network", "")

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
        if "nova" not in self.connectionClients[current_testbed]:
            from keystoneauth1 import loading
            from keystoneauth1 import session
            from novaclient import client
            from neutronclient.v2_0 import client as nclient
            OSloader = loading.get_plugin_loader('password')
            OSauth = OSloader.load_from_options(
                auth_url=self.openstack_credentials[self.usersData[username]["testbed"]]["auth_url"],
                username=self.openstack_credentials[self.usersData[username]["testbed"]]["username"],
                password=self.openstack_credentials[self.usersData[username]["testbed"]]["password"],
                tenant_name=self.openstack_credentials[self.usersData[username]["testbed"]]["tenant_name"],
            )
            OSsession = session.Session(auth=OSauth)
            self.connectionClients[current_testbed]["nova"] = client.Client(
                self.openstack_credentials[self.usersData[username]["testbed"]]["api_version"], session=OSsession)
            self.connectionClients[current_testbed]["neutron"] = nclient.Client(session=OSsession)

    def provide_resources(self, user_info, payload=None):
        #logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.info("***Requested*** provide_resources by user |%s|" % (user_info.name))

        # logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.info("preparing to create zabbix server")
        username = user_info.name
        self.getOpenstack(username)
        extended_name = self.ZabbixServerName + "_" + username
        
        current_testbed = self.usersData[username]["testbed"]
        userNova = self.connectionClients[current_testbed]["nova"]
        userNeutron = self.connectionClients[current_testbed]["neutron"]
        
        for s in userNova.servers.list():

            if s.name==extended_name:
                self.usersData[username]["serverInstance"]=s
                self.usersData[username]["floatingIp"] = s.networks[self.ZabbixServerNetwork][1]
                self.usersData[username]["internalIp"] = s.networks[self.ZabbixServerNetwork][0]
                self.usersData[username]["output"]={
                    "testbed" : self.usersData[username]["testbed"],
                    "internalIp" : self.usersData[username]["internalIp"],
                    "floatingIpIp" : self.usersData[username]["floatingIp"],
                    "url" : "http://{}/zabbix/".format(self.usersData[username]["floatingIp"]),
                    "username" : "Admin",
                    "password" : "zabbix",
                }
                logger.info("zabbix server already online")
                logger.info(json.dumps(self.usersData[username]["output"]))
                return [json.dumps(self.usersData[username]["output"])]
                break

        if self.usersData[username]["serverInstance"] is None:
            logger.info("no zabbix server found, preparing to create it")
            NewServer = userNova.servers.create(
                name=extended_name,
                image=userNova.glance.find_image(self.ZabbixServerImageName),
                flavor=userNova.flavors.find(name=self.ZabbixServerFlavour),
                nics=[{'net-id': userNova.neutron.find_network(self.ZabbixServerNetwork).id}],
                security_groups=[self.ZabbixServerSecGroups],
            )
            id = NewServer.id
            logger.info("zabbix server created, id is {}".format(id))

            while 1:
                NewServer = userNova.servers.get(id)
                status = NewServer.status
                logger.info("zabbix server status: {}".format(status))
                if status != "BUILD":
                    break
                time.sleep(0.3)

            self.usersData[username]["internalIp"] = NewServer.networks[self.ZabbixServerNetwork][0]

            floatingIp_toAdd = None
            flips = userNeutron.list_floatingips()
            #random.shuffle(flips["floatingips"])
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
                logger.info("adding floating ip {}".format(floatingIp_toAdd))
                NewServer.add_floating_ip(floatingIp_toAdd)
                NewServer = userNova.servers.get(id)
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
                
            return [json.dumps(self.usersData[username]["output"])]
            
        return {}

    def validate_resources(self, user_info=None, payload=None) -> None:

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

        self.usersData[user_info.name] = {}
        self.usersData[user_info.name]["testbed"] = testbed
        self.usersData[user_info.name]["internalIp"] = None
        self.usersData[user_info.name]["floatingIp"] = None
        self.usersData[user_info.name]["serverInstance"] = None

    def release_resources(self, user_info, payload=None):
        logger.info("***Requested*** release_resources by user |%s|" % (user_info.name))
        #logger.debug("Requested release_resources payload |%s|" % (payload))
        logger.info("preparing to delete zabbix server")
        username = user_info.name
        resource = yaml.load(payload)
        
        current_testbed = self.usersData[username]["testbed"]
        userNova = self.connectionClients[current_testbed]["nova"]
        userNeutron = self.connectionClients[current_testbed]["neutron"]
        try:
            testbed = resource.get("testbed")
        except:
            logger.info("***ERROR*** release_resources |%s|" % (resource))
            return

        if testbed:
            if username not in self.usersData:
                self.usersData[username]={}
                self.usersData[username]["testbed"]=testbed
                
            self.getOpenstack(username)
            
            extended_name = self.ZabbixServerName + "_" + username
            
            for s in userNova.servers.list():
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
        # logger.debug("_update_status")
        result = {}
        for exps in self.usersData.keys():
            if "output" in self.usersData[exps]:
                #logger.debug(self.usersData[exps]["output"])
                result[exps] = []
                result[exps].append(json.dumps(self.usersData[exps]["output"]))
                
        #print (result)
        return result
