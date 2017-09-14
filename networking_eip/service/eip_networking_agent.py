#   Copyright [2017] [Yoann Terrade]
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import eventlet
eventlet.monkey_patch()

import time
from oslo_config import cfg
from oslo_service import service
from oslo_log import log as logging
import oslo_messaging
import networking_eip.request_builder.eip_rest as eip_rest

from networking_eip.neutron_connector import connector


LOG=logging.getLogger("eipAgent")

DOMAIN="neutronNotifs"

cfg.CONF.log_file = '/var/log/eipNotifs.log'
logging.register_options(cfg.CONF)
logging.setup(cfg.CONF,DOMAIN)


def create_addr_scope_handler(payload):
	sitename = payload['address_scope']['name']
	res = eip_rest.create_site(sitename)
	if res is None:
		LOG.error("Failed to create site "+ sitename + " on SolidServer")
	else:
		LOG.info("Site "+ sitename + " successfully created")

def delete_addr_scope_handler(payload):
	sitename = payload['address_scope']['name']
	res = eip_rest.delete_site(sitename)
	if res is None:
		LOG.error("Failed to delete site "+ sitename + " on SolidServer")
	else:
		LOG.info("Site "+ sitename + " successfully deleted")

def create_subnet_pool_handler(payload):
	start_addr,_,prefix = payload['subnetpool']['prefixes'][0].partition('/')
	site_name = connector.NeutronConnector().get_connector().list_address_scopes(id=payload['subnetpool']['address_scope_id'])['address_scopes'][0]['name']
	name = payload['subnetpool']['name']
	if payload['subnetpool']['ip_version'] == 4:
		ret = eip_rest.create_block_subnet_v4(start_addr,prefix,site_name,name)
	elif payload['subnetpool']['ip_version'] == 6:
		ret = eip_rest.create_block_subnet_v6(start_addr,prefix,site_name,name)

	if ret:
		LOG.info("Successfully created block "+name)
	else:
		LOG.error("Failed to create block "+name)

def delete_subnet_pool_handler(payload):
	scope = connector.NeutronConnector().get_connector().list_address_scopes(id=payload['subnetpool']['address_scope_id'])['address_scopes'][0]
	name = payload['subnetpool']['name']
	sitename = scope['name']
	subnet_addr,_,prefix = payload['subnetpool']['prefixes'][0].partition('/')
	if scope['ip_version'] == 4:
		ret = eip_rest.delete_block_subnet_v4(sitename,subnet_addr,prefix)
	if scope['ip_version'] == 6:
		ret = eip_rest.delete_block_subnet_v6(sitename,subnet_addr,prefix)
        if ret:
                LOG.info("Successfully deleted block "+name)
        else:
                LOG.error("Failed to delete block "+name)



### code from oslo_messaging/notify/listener.py
class NotificationEndpoint(object):
	def __init__(self,pool):
		self.pool = pool
        def warn(self,ctxt,publisher_id,event_type,payload,metadata):
                LOG.error("event " + str(event_type) + ' ___ ' + payload)
        def info(self,ctxt,publisher_id,event_type,payload,metadata):
		if str(event_type) == 'address_scope.create.end':
			self.pool.spawn_n(create_addr_scope_handler,payload)

		elif str(event_type) == 'address_scope.delete.end':
			self.pool.spawn_n(delete_addr_scope_handler,payload)

		elif str(event_type) == 'subnetpool.create.end':
			self.pool.spawn_n(create_subnet_pool_handler,payload)
			
		elif str(event_type) == 'subnetpool.delete.end':
			self.pool.spawn_n(delete_subnet_pool_handler,payload)
		else:		
	                LOG.info("event " + str(event_type) + str(payload))

class EipNetworkingAgent(object):
	def __init__(self,pool):
### code from oslo_messaging/notify/listener.py
                self.transport = oslo_messaging.get_notification_transport(cfg.CONF)
                self.targets = [ oslo_messaging.Target(topic='notifications') ]
                self.endpoints = [ NotificationEndpoint(pool) ]
### TODO : use config file for pool
                self.server = oslo_messaging.get_notification_listener(self.transport,self.targets,self.endpoints,executor='eventlet')

	def start(self):
		self.server.start()
		self.server.wait()
	
	def stop(self):
		self.server.stop()

	def reset(self):
		self.server.reset()


class EipNetworkingAgentService(service.ServiceBase):  

	def __init__(self):
		self.pool = eventlet.GreenPool(50)
		self.agent=EipNetworkingAgent(self.pool)

	def start(self):
		self.agent.start()

	def wait(self):
		self.pool.waitall()

	def reset(self):
		self.agent.reset()

	def stop(self):
		self.agent.stop()
		



def main():
## doc says that we should use more than 1 worker
	launcher = service.launch(cfg.CONF,EipNetworkingAgentService(),workers=4)
	launcher.wait()


if __name__ == "__main__":
	main()




