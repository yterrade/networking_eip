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


from neutron.ipam import requests as neutron_requests
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class eipAddressRequestFactory(neutron_requests.AddressRequestFactory):

    @classmethod
    def get_request(cls,context,port,ip_dict):
	request = super(eipAddressRequestFactory,cls).get_request(context,port,ip_dict)
	request.name = port.get('name')
	request.mac  = port.get('mac_address')

	return request
