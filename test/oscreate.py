import configparser,os,time

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


serv = nova.servers.create(
                    name=config['openstack-params']['instance_name'], 
                    image=nova.glance.find_image(config['openstack-params']['image_name']), 
                    flavor=nova.flavors.find(name=config['openstack-params']['flavour']), 
                    nics=[{'net-id': nova.neutron.find_network(config['openstack-params']['network']).id}],
                    security_groups=[config['openstack-params']['security_group']],
                    )

id=serv.id

while 1:
    serv=nova.servers.get(id)
    status=serv.status
    print (status)
    if status!="BUILD":
        break
    time.sleep(0.3)

serv.add_floating_ip(config['openstack-params']['floating_ip'])

