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


class eipSubnetRequestFactory(neutron_requests.SubnetRequestFactory):

    """Builds request using subnet info"""
    @classmethod
    def get_request(cls, context, subnet, subnetpool):
	# call neutron original get_request, we just want to append the subnet name
	# and the subnetpool name to it
	request  = super(eipSubnetRequestFactory, cls).get_request(context,subnet,subnetpool)
	# see neutron/db/cb_base_plugin_common.py to know the extra data we can happen
	# (_make_subnet_dict)
	request.subnet_name = subnet.get('name')

	return request

