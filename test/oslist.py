import configparser,os

config = configparser.ConfigParser()
#config.read('git/monitoring-manager/etc/monitoring-manager.ini')
config.read(os.path.join(os.path.dirname(os.path.realpath(__file__)),'etc','monitoring-manager.ini'))

from keystoneauth1 import loading
from keystoneauth1 import session
from novaclient import client
loader = loading.get_plugin_loader('password')
auth = loader.load_from_options(auth_url="http://10.44.56.250:5000/v2.0/",username="admin",password="8xCYSLx7",tenant_name="Zabbix_Test")
sess = session.Session(auth=auth)
nova = client.Client("2", session=sess)

from neutronclient.v2_0 import client as nclient
neutron=nclient.Client(session=sess)

sl = nova.servers.list()
for s in sl:
   print (s,s.status,s.networks)
flips = neutron.list_floatingips()
for ip in flips["floatingips"]:
    print (ip["floating_ip_address"],ip["fixed_ip_address"])