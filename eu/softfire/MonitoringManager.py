from threading import Thread

import yaml
from keystoneauth1 import loading
from keystoneauth1 import session
from keystoneauth1.identity import v3
from neutronclient.v2_0 import client as nclient
from novaclient import client
from novaclient.exceptions import NotFound

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


def get_network_by_name(lan_name, neutron, project_id):
    for net in neutron.list_networks()['networks']:
        if net.get('name') == lan_name and (net.get('project_id') == project_id or net.get('shared')):
            return net
    # TODO create the network!
    raise MonitoringResourceValidationError("No network called: %s" % lan_name)


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
        # logger.debug("List resources")
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

    def get_openstack(self, username, password=None, project=None):

        current_testbed = self.usersData[username]["testbed"]

        log_header = get_log_header(username, current_testbed)
        admin_username = self.openstack_credentials[current_testbed]["username"]
        auth_url = self.openstack_credentials[current_testbed]["auth_url"]
        project = self.usersData[username]["destination_tenant"]
        user_and_project_domain_name = self.openstack_credentials[current_testbed]["user_domain_name"]

        if not password:
            password = self.openstack_credentials[current_testbed]["password"]

        if "nova" not in self.usersData[username]:
            # clients (nova, neutron) have to be in the userdata, since openstack tenants are user bounded

            if self.openstack_credentials[current_testbed]["api_version"] == 2:
                logger.info("{}connecting to {} using v2 auth".format(log_header, auth_url))
                OSloader = loading.get_plugin_loader('password')
                auth = OSloader.load_from_options(
                    auth_url=auth_url,
                    username=admin_username,
                    password=password,
                    # tenant_name=self.openstack_credentials[self.usersData[username]["testbed"]]["admin_tenant_name"],
                    tenant_name=project,
                )

            if self.openstack_credentials[current_testbed]["api_version"] == 3:
                logger.info("{}connecting to {} using v3 auth".format(log_header, auth_url))

                auth = v3.Password(
                    auth_url=auth_url,
                    username=admin_username,
                    password=password,
                    project_domain_name=user_and_project_domain_name,
                    user_domain_name=user_and_project_domain_name,
                    # project_id=self.openstack_credentials[self.usersData[username]["testbed"]]["project_id"],
                    project_id=project
                )

            os_session = session.Session(auth=auth)

            self.usersData[username]["nova"] = client.Client(2, session=os_session)
            self.usersData[username]["neutron"] = nclient.Client(session=os_session)

    def provide_resources(self, user_info, payload=None):
        logger.info("***Requested*** provide_resources by user |%s|" % (user_info.name))

        username = user_info.name
        self.get_openstack(username)

        extended_name = self.ZabbixServerName + "_" + username

        current_testbed = self.usersData[username]["testbed"]
        user_nova = self.usersData[username]["nova"]
        user_neutron = self.usersData[username]["neutron"]
        lan_name = self.usersData[username]["lan_name"]
        project_id = self.usersData[username]["destination_tenant"]

        log_header = get_log_header(username, current_testbed)

        logger.info("{}preparing to create zabbix server".format(log_header))

        for s in user_nova.servers.list():

            if s.name == extended_name:
                self.usersData[username]["serverInstance"] = s
                self.usersData[username]["internalIp"] = s.networks[lan_name][0]
                try:
                    self.usersData[username]["floatingIp"] = s.networks[lan_name][1]
                except IndexError:
                    pass

                self.usersData[username]["output"] = {
                    "testbed": self.usersData[username]["testbed"],
                    "internalIp": self.usersData[username]["internalIp"],
                    "floatingIp": self.usersData[username]["floatingIp"],
                    "url": "http://{}/zabbix/".format(self.usersData[username]["floatingIp"]),
                    "username": "Admin",
                    "password": "zabbix",
                }
                logger.info("{}zabbix server already online".format(log_header))
                logger.info(json.dumps(self.usersData[username]["output"]))
                return [json.dumps(self.usersData[username]["output"])]
                break

        if self.usersData[username]["serverInstance"] is None:
            logger.info("{}no zabbix server found, preparing to create it".format(log_header))
            
            try:
                zabbix_destination_network = user_nova.neutron.find_network(lan_name)
            except NotFound:
                zabbix_destination_network = None

            if zabbix_destination_network:
                logger.info("{}network found {}".format(log_header,zabbix_destination_network))
            else:
                logger.info("{}network not found, trying to create it".format(log_header))

            new_server = user_nova.servers.create(
                name=extended_name,
                image=user_nova.glance.find_image(self.ZabbixServerImageName),
                flavor=user_nova.flavors.find(name=self.ZabbixServerFlavour),
                nics=[{'net-id': get_network_by_name(lan_name, user_neutron, project_id).get('id')}],
                security_groups=[self.ZabbixServerSecGroups],
            )
            id = new_server.id
            logger.info("{}zabbix server created, id is {}".format(log_header, id))

            while True:
                new_server = user_nova.servers.get(id)
                status = new_server.status
                logger.info("{}zabbix server status: {}".format(log_header, status))
                if status != "BUILD":
                    break
                time.sleep(0.3)
                # TODO stop after a timeout

            self.usersData[username]["internalIp"] = new_server.networks[lan_name][0]

            floating_ip_to_add = None
            flips = user_neutron.list_floatingips()
            for ip in flips["floatingips"]:
                if hasattr(ip, "project_id"):
                    ip_project_id_ = ip['project_id']
                else:
                    ip_project_id_ = ip['tenant_id']
                if ip["fixed_ip_address"] is None and ip_project_id_ == self.usersData[username]["destination_tenant"]:
                    floating_ip_to_add = ip["floating_ip_address"]
                    break

            if floating_ip_to_add is None:
                body = {
                    "floatingip": {
                        "floating_network_id": self.get_ext_network(username).get('id')
                    }}
                user_neutron.create_floatingip(body=body)
                flips = user_neutron.list_floatingips()
                for ip in flips["floatingips"]:
                    if ip["fixed_ip_address"] is None:
                        # TODO check if fip belongs to tenant!
                        floating_ip_to_add = ip["floating_ip_address"]
                        break

            if floating_ip_to_add:
                logger.info("{}adding floating ip {}".format(log_header, floating_ip_to_add))
                new_server.add_floating_ip(floating_ip_to_add)
                new_server = user_nova.servers.get(id)
                logger.info("{}floating ip added".format(log_header))
                self.usersData[username]["floatingIp"] = floating_ip_to_add
            else:
                self.usersData[username]["floatingIp"] = "UNABLE TO ASSOCIATE"

            self.usersData[username]["serverInstance"] = new_server
            logger.info(
                "{}zabbix deployed to {}".format(log_header, self.usersData[username]["serverInstance"].networks))

            self.usersData[username]["output"] = {
                "testbed": self.usersData[username]["testbed"],
                "internalIp": self.usersData[username]["internalIp"],
                "floatingIp": self.usersData[username]["floatingIp"],
                "url": "http://{}/zabbix/".format(self.usersData[username]["floatingIp"]),
                "username": "Admin",
                "password": "zabbix",
            }

            return [json.dumps(self.usersData[username]["output"])]

        return {}

    def get_ext_network(self, username):
        # TODO check if the private net is attached to the router
        external_nets = [ext_net for ext_net in self.usersData[username]["neutron"].list_networks()['networks'] if
                         ext_net['router:external']]
        if external_nets:
            return external_nets[0]
        else:
            # TODO change to correct exception
            raise MonitoringResourceValidationError("No external net found!")

    def validate_resources(self, user_info=None, payload=None) -> None:
        logger.info("***Requested*** validate_resources by user |%s|" % (user_info.name))

        if user_info.name == '':
            raise MonitoringResourceValidationError(message="user not configured as experimenter")

        try:
            resource = yaml.load(payload)
        except:
            raise MonitoringResourceValidationError("Error parsing Yaml")

        testbed = resource.get("properties").get("testbed")

        if testbed not in self.testbeds:
            raise MonitoringResourceValidationError(message="testbed not available")

        lan_name = resource.get("properties").get("lan_name")

        username = user_info.name
        log_header = get_log_header(username, testbed)

        os_project_id = user_info.testbed_tenants[TESTBED_MAPPING[testbed]]

        if not os_project_id:

            if self.openstack_credentials[testbed]["api_version"] == 2:
                os_project_id = self.openstack_credentials[testbed]["tenant_name"]
                logger.info(
                    "{}tenant name taken from v2 auth options, field tenant_name: {}".format(log_header, os_project_id))
            if self.openstack_credentials[testbed]["api_version"] == 3:
                os_project_id = self.openstack_credentials[testbed]["project_id"]
                logger.info(
                    "{}tenant name taken from v3 auth options, field project_id: {}".format(log_header, os_project_id))
        else:

            logger.info("{}tenant name taken from nfv-manager: {}".format(log_header, os_project_id))

        self.usersData[user_info.name] = {}
        self.usersData[user_info.name]["testbed"] = testbed
        self.usersData[user_info.name]["lan_name"] = lan_name
        self.usersData[user_info.name]["destination_tenant"] = os_project_id
        self.usersData[user_info.name]["internalIp"] = None
        self.usersData[user_info.name]["floatingIp"] = None
        self.usersData[user_info.name]["serverInstance"] = None

    def release_resources(self, user_info, payload=None):
        logger.info("***Requested*** release_resources by user |%s|" % (user_info.name))
        # logger.debug("Requested release_resources payload |%s|" % (payload))
        username = user_info.name

        try:
            resource = yaml.load(payload)
        except:
            logger.warning("Error parsing the resource to delete, i will return", username)
            return

        try:
            testbed = resource.get("testbed")
        except:
            logger.info("***ERROR*** release_resources |%s|" % resource)
            return

        if testbed:
            if username not in self.usersData:
                self.usersData[username] = {}
                self.usersData[username]["testbed"] = testbed

            log_header = get_log_header(username, testbed)

            logger.info("{}preparing to delete zabbix server".format(log_header))
            try:
                self.get_openstack(username)
            except KeyError:
                logger.error("Not found username in userdata")
                return

            extended_name = self.ZabbixServerName + "_" + username
            userNova = self.usersData[username]["nova"]

            for s in userNova.servers.list():
                if s.name == extended_name:
                    self.usersData[username]["serverInstance"] = s
                    break
            if self.usersData[username]["serverInstance"]:
                logger.info("{}zabbix server to delete found: {}".format(log_header, extended_name))
                self.usersData[username]["serverInstance"].delete()
                logger.info("{}zabbix server deleted".format(log_header))
            else:
                logger.info("{}zabbix server not found, nothing done".format(log_header))

            del (self.usersData[username])

        else:
            return

    def _update_status(self) -> dict:
        result = {}
        for exps in self.usersData.keys():
            if "output" in self.usersData[exps]:
                result[exps] = []
                result[exps].append(json.dumps(self.usersData[exps]["output"]))

        return result


if __name__ == '__main__':
    with open("/etc/softfire/openstack-credentials.json") as json_data:
        openstack_credentials = json.load(json_data)
    testbed_under_test = 'fokus'
    project_id = "fcdaf143a95a4fada3f3fa9ee978ca8d"

    auth = v3.Password(
        auth_url=openstack_credentials.get(testbed_under_test).get("auth_url"),
        username=openstack_credentials.get(testbed_under_test).get("username"),
        password=openstack_credentials.get(testbed_under_test).get("password"),
        project_domain_name=openstack_credentials.get(testbed_under_test).get("user_domain_name"),
        user_domain_name=openstack_credentials.get(testbed_under_test).get("user_domain_name"),
        project_id=project_id
    )

    os_session = session.Session(auth=auth)

    nova = client.Client(2, session=os_session)
    neutron = nclient.Client(session=os_session)
    print(nova.servers.list())
    for n in neutron.list_networks()['networks']:
        print(n)
    print()
    for ip in neutron.list_floatingips()['floatingips']:
        print(ip)
