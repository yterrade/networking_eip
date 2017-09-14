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

import os
from oslo_config import cfg
from keystoneauth1 import identity
from keystoneauth1 import session
from neutronclient.v2_0 import client
import threading


class NeutronConnector(object):
	class __NeutronConnector(object):
		def __init__(self):
			self.setParams()
			self.connect()

		def __str__(self):
			#return 'Neutron connector : '+self.CONF.keystone_authtoken.auth_uri + ' ' +\
			return 'Neutron connector : '+self.CONF.eip_connector.auth_uri + ' ' +\
				self.CONF.eip_connector.username+'/'+self.CONF.eip_connector.password +\
				'project : '+self.CONF.eip_connector.project_name + ' project_domain_id : '+\
				self.CONF.eip_connector.project_domain_id +' user_domain_id : '+self.CONF.eip_connector.user_domain_id

		def setParams(self):
#                        keystone_opt_group = cfg.OptGroup(name='keystone_authtoken',
 #                                       title='Keystone authentication')
			
			eip_connector_opt_group = cfg.OptGroup(name = 'eip_connector',
					title='Domain / tenant')

#			keystone_opts = [cfg.StrOpt('auth_uri',default='',help='Keystone authentication uri')]


			eip_connector_opts = [cfg.StrOpt('project_name',default='',help='Main project'),
				cfg.StrOpt('project_domain_id',default='',help='Project domain'),
				cfg.StrOpt('user_domain_id',default='',help='User domain'),
                                cfg.StrOpt('username',default='',help='Username'),
#                                cfg.StrOpt('password',default='',help='Password')]
                                cfg.StrOpt('password',default='',help='Password'),
                                cfg.StrOpt('auth_uri',default='',help='Password')]

			

                        self.CONF = cfg.CONF
 #                       self.CONF.register_group(keystone_opt_group)
                        self.CONF.register_group(eip_connector_opt_group)
  #                      self.CONF.register_opts(keystone_opts,keystone_opt_group)
                        self.CONF.register_opts(eip_connector_opts,eip_connector_opt_group)
                        self.CONF(default_config_files=['/etc/neutron/neutron.conf'])

		def connect(self):
			#auth = identity.Password(auth_url = self.CONF.keystone_authtoken.auth_uri,
			auth = identity.Password(auth_url = self.CONF.eip_connector.auth_uri,
						username = self.CONF.eip_connector.username,
						password = self.CONF.eip_connector.password,
						project_name = self.CONF.eip_connector.project_name,
						project_domain_id = self.CONF.eip_connector.project_domain_id,
						user_domain_id = self.CONF.eip_connector.user_domain_id)
			sess = session.Session(auth=auth)
			self.connector = client.Client(session=sess)




	__instance = None
	__lock = threading.Lock()

	def __init__(self):
		NeutronConnector.__lock.acquire()
		if NeutronConnector.__instance is None:
			NeutronConnector.__instance = NeutronConnector.__NeutronConnector()
		NeutronConnector.__lock.release()

	def get_connector(self):
		return NeutronConnector.__instance.connector


	def __str__(self):
		return str(NeutronConnector.__instance)

	


#neutron.conf
#[keystone_authtoken]
#auth_uri=http://10.10.17.92:5000/v3

#[nova]
#project_domain_id=default
#username=neutron
#password=0fb35f7d17944db3
#user_domain_name=default
#project_name=services
#project_domain_name=Default



#identity.Password(auth_url=auth_url,username=username,password=password,project_name='admin',project_domain_id='default',user_domain_id='default')




if __name__== '__main__':
	n = NeutronConnector()
	print n
	print n.get_connector().list_subnets()

	n = NeutronConnector()
	print n
	print n.get_connector().list_subnets()

