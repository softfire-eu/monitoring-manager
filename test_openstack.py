import configparser,os

config = configparser.ConfigParser()
#config.read('git/monitoring-manager/etc/monitoring-manager.ini')
config.read(os.path.join(os.path.dirname(os.path.realpath(__file__)),'etc','monitoring-manager.ini'))

from keystoneauth1 import loading
from keystoneauth1 import session
from novaclient import client
loader = loading.get_plugin_loader('password')
auth = loader.load_from_options(auth_url=config['openstack-env']['OS_AUTH_URL'],
                                username=config['openstack-env']['OS_USERNAME'],
                                password=config['openstack-env']['OS_PASSWORD'],
                                tenant_name=config['openstack-env']['OS_TENANT_NAME'])
sess = session.Session(auth=auth)
nova = client.Client(config['openstack-env']['OS_IDENTITY_API_VERSION'], session=sess)

sl = nova.servers.list()
for s in sl:
    print (s)
