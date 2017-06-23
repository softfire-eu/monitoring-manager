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
        logger.debug("MROSSI:__init__")
        super(MonitoringManager, self).__init__(config_path)
        self.local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/monitoring-manager")
        self.resources_db = '%s/monitoring-manager.db' % self.local_files_path
        
        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources"
        
        try:
            res = cur.execute(query)
        except:
            logger.debug("table not found - creating it")
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS resources (username, project_id, nsr_id, nsd_id, random_id, log_dashboard_url)''')
            conn.commit()
        finally:
            conn.close()
            
        os.environ["OS_USERNAME"]               = self.get_config_value("openstack-env", "OS_USERNAME", "")
        os.environ["OS_PASSWORD"]               = self.get_config_value("openstack-env", "OS_PASSWORD", "")
        os.environ["OS_AUTH_URL"]               = self.get_config_value("openstack-env", "OS_AUTH_URL", "")
        os.environ["OS_IDENTITY_API_VERSION"]   = self.get_config_value("openstack-env", "OS_IDENTITY_API_VERSION", "")
        os.environ["OS_TENANT_NAME"]            = self.get_config_value("openstack-env", "OS_TENANT_NAME", "")
        
        #logger.debug(os.environ)
        
        from keystoneauth1 import loading
        from keystoneauth1 import session
        from novaclient import client
        self.OSloader = loading.get_plugin_loader('password')
        self.OSauth = self.OSloader.load_from_options(auth_url=os.environ["OS_AUTH_URL"],
                                        username=os.environ["OS_USERNAME"],
                                        password=os.environ["OS_PASSWORD"],
                                        tenant_name=os.environ["OS_TENANT_NAME"]
                                        )
        
        self.OSsession = session.Session(auth=self.OSauth)
        self.OSnova = client.Client(os.environ["OS_IDENTITY_API_VERSION"], session=self.OSsession)
        
        self.ZabbixServerName=self.get_config_value("openstack-params", "instance_name", "")
        self.ZabbixServerFloatingIp=self.get_config_value("openstack-params", "floating_ip", "")
        self.ZabbixInternalStatus="NONE" #NONE, FLOATING, ACTIVE
        self.JobInternalStatus="NONE" #NONE, TOCREATE, TODELETE
        
    def refresh_resources(self, user_info):
        logger.debug("MROSSI:refresh_resources")
        logger.debug("refresh_resources")
        return None

    def create_user(self, username, password):
        logger.debug("MROSSI:create_user")
        logger.debug("create_user")
        user_info = messages_pb2.UserInfo(
            name=username,
            password=password,
            ob_project_id='id',
            testbed_tenants={}
        )

        return user_info

    def list_resources(self, user_info=None, payload=None):
        logger.debug("MROSSI:list_resources")
        logger.debug("List resources")
        resource_id = "monitor"
        description = "This resource permits to deploy a ZabbixServer"
        cardinality = 1
        testbed = messages_pb2.ANY
        node_type = "MonitoringResource"
        result = []
        result.append(messages_pb2.ResourceMetadata(resource_id=resource_id, description=description, cardinality=cardinality, node_type=node_type, testbed=testbed))
        return result

    def validate_resources(self, user_info=None, payload=None) -> None:
        logger.info("Requested validate_resources by user %s" % user_info.name)
        resource = yaml.load(payload)
        logger.debug("Validating resource %s" % resource)
        logger.debug("user_info        %s" % user_info)
        self.JobInternalStatus = "TOCREATE"

    def provide_resources(self, user_info, payload=None):
        logger.debug("MROSSI:provide_resources")
        logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.debug("payload: %s" % payload)
        
        
        
        response = []
        return response
        
		
        # TODO store reference between resource and user. ADD status, api-ip, dashboard_url
        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS resources (username, project_id, nsr_id, nsd_id, random_id, log_dashboard_url)''')
        query = "INSERT INTO resources (username, project_id, nsr_id, nsd_id, random_id, log_dashboard_url) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')" % \
                (user_info.name, project_id, nsr_id, nsd_id, random_id, log_dashboard_url)
        logger.debug("Executing %s" % query)

        cur.execute(query)
        conn.commit()
        conn.close()

        '''
        Return an array of JSON strings with information about the resources
        '''
        return response

    def _update_status(self) -> dict:
        logger.debug("MROSSI:_update_status")
        self.ZabbixServerInstance=None
        self.ZabbixServerIpAttached=False
        
        sl = self.OSnova.servers.list()
        for s in sl:
            if s.name==self.ZabbixServerName:
                self.ZabbixServerInstance=s
                for n in self.ZabbixServerInstance.networks.keys():
                    for ip in self.ZabbixServerInstance.networks[n]:                    
                        if str(ip)==self.ZabbixServerFloatingIp:
                            self.ZabbixServerIpAttached=True
                break
        
        if self.ZabbixServerInstance:
            if self.ZabbixServerIpAttached:
                self.ZabbixInternalStatus="ACTIVE"
            else:
                self.ZabbixInternalStatus="FLOATING"       
        else:
                self.ZabbixInternalStatus="NONE"
        
        
        logger.info("ZabbixServerStatus {:>10}   JobStatus {:>10}".format(self.ZabbixInternalStatus,self.JobInternalStatus) )
                    
        #logger.debug("Checking status update")
        
        self.JobInternalStatus = "NONE"
        
        result = {}
        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources"
        
        res = cur.execute(query)
        
        rows = res.fetchall()
        for r in rows:
            #TODO nsr_id e project_id could be empty with want_agent
            nsr_id = r["nsr_id"]
            project_id = r["project_id"]
            username = r["username"]
            #TODO FIX THESE
            #download_link = r["download_link"]
            #dashboard_url = r["dashboard_url"]
            #api_url = r["api_url"]

            if nsr_id == "" :
                '''This resource does not correspond to a deployed NSR'''
                logger.debug("Uninstantiated resource")
                s = {"message" : "You have just downloaded the scripts to install the resource"}
                #s["download_link"] = download_link

            else :
                '''Open Baton resource'''
                logger.debug("Checking resource nsr_id: %s" % nsr_id)

                try :
                    agent = ob_login(project_id)
                    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
                    ob_resp = nsr_agent.find(nsr_id)
                    time.sleep(5)
                    ob_resp = json.loads(ob_resp)
                    logger.debug(ob_resp)
                except Exception as e :
                    logger.error("Error contacting Open Baton to validate resource nsr_id: %s\n%s" % (nsr_id, e))

                s = {}
                s["status"] = ob_resp["status"]

                print(s)
                #if ACTIVE
                if s["status"] == "ACTIVE" :
                    s["ip"] = ob_resp["vnfr"][0]["vdu"][0]["vnfc_instance"][0]["floatingIps"][0]["ip"]
                    s["api_url"] = "http://%s:5000" % s["ip"]
                    try :
                        api_resp = requests.get(s["api_url"])
                        logger.debug(api_resp)
                    except Exception:
                        s["status"] == "VM is running but API are unavailable"

            '''
            if dashboard_url != "" : 
                s["dashboard_url"] = dashboard_url
            '''
            if username not in result.keys():
                result[username] = []
            result[username].append(json.dumps(s))
        return result


    def release_resources(self, user_info, payload=None):
        logger.info("Requested release_resources by user %s" % user_info.name)
        logger.debug("Arrived release_resources\nPayload: %s" % payload)

        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources WHERE username = '%s'" % user_info.name
        res = cur.execute(query)
        rows = res.fetchall()
        for r in rows:
            delete_ns(nsr_id=r["nsr_id"], nsd_id=r["nsd_id"], project_id=r["project_id"])
            shutil.rmtree("%s/tmp/%s" % (self.local_files_path, r["random_id"]))

        query = "DELETE FROM resources WHERE username = '%s'" % user_info.name
        ################
        cur.execute(query)
        conn.commit()
        conn.close()

        #TODO delete folders
        
        
        self.JobInternalStatus = "TODELETE"
        return
