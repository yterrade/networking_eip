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



from oslo_config import cfg
import base64


class requestBuilder(object):

	server_params=dict()

	@staticmethod
	def setParams():
		if not requestBuilder.server_params:
	                opt_group = cfg.OptGroup(name='solidserver',
        	                        title='solidserver config')

                	solidserver_opts = [cfg.StrOpt('address',default='',help=('SolidServer IP address')),
                        	cfg.StrOpt('username',default='',help=('SolidServer admin login')),
	                        cfg.StrOpt('password',default='',help=('SolidServer admin password'))]
        	        CONF = cfg.CONF
                	CONF.register_group(opt_group)
	                CONF.register_opts(solidserver_opts,opt_group)

        	        CONF(default_config_files=['/etc/neutron/neutron.conf'])

                	requestBuilder.server_params['username'] = base64.b64encode(bytes(CONF.solidserver.username),'utf8')
	                requestBuilder.server_params['password'] = base64.b64encode(bytes(CONF.solidserver.password),'utf8')
        	        requestBuilder.server_params['address'] = CONF.solidserver.address

	@staticmethod
	def buildRequest(query):
		if not requestBuilder.server_params:
			requestBuilder.setParams()

	 	if 'find_free' in query:
			service_type = 'rpc'
		else:
			service_type = 'rest'

		url = "https://"+requestBuilder.server_params['address']+'/'+service_type+'/'+query
	        headers= {
        	        'x-ipm-username':requestBuilder.server_params['username'],
                	'x-ipm-password':requestBuilder.server_params['password'],
	                'cache-control': "no-cache"
        	        }
	        return url,headers


