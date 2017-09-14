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


import requests
import netaddr
import json
from networking_eip.request_builder import request_builder
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

def add_columns(ipv6Addr):
        ret_ipv6 = ipv6Addr[:4]+':'+ipv6Addr[4:8]+':'+ipv6Addr[8:12]+':'+ipv6Addr[12:16]+':'+\
                ipv6Addr[16:20]+':'+ipv6Addr[20:24]+':'+ipv6Addr[24:28]+':'+ipv6Addr[28:32]
        return ret_ipv6


def get_site_list(site_name):
	url, headers = request_builder.requestBuilder.buildRequest('ip_site_list')
	data = dict()
        data['WHERE'] = "site_name='"+site_name+"'"
        r = requests.get(url,headers=headers,params=data,verify=False)
	if r.status_code == 200:
		return 1
	else:
		return None

def create_site(site_name):
	url, headers = request_builder.requestBuilder.buildRequest('ip_site_add')
	data = dict()
	data['site_name'] = site_name
	r = requests.post(url,headers=headers,json=data,verify=False)
	if r.status_code == 201:
		return 1
        else:
		return None

def delete_site(site_name):
        url, headers = request_builder.requestBuilder.buildRequest('ip_site_delete')
        data = dict()
        data['site_name'] = site_name
        r = requests.delete(url,headers=headers,json=data,verify=False)
        if r.status_code == 201:
                return 1
        else:
                return None



def get_subnet_list_v4(start_addr,sitename,subnetpool_name):
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip_block_subnet_list')

	data['WHERE'] = "subnet_level='1' AND site_name='" + sitename +"' AND parent_subnet_name='"+subnetpool_name+"'"
	
	if start_addr:
		start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
		data['WHERE'] += "AND start_ip_addr='"+ start_addr_hexa+"'"
		

	r = requests.get(url,headers=headers,params=data,verify=False)
	LOG.error(r.url)

	if r.status_code == 200:
		return r.json()[0]

	else:
		return None


def get_subnet_list_v6(start_addr,sitename,subnetpool_name):
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip6_block6_subnet6_list')

	data['WHERE'] = "subnet_level='1' AND site_name='" + sitename +"' AND parent_subnet6_name='"+subnetpool_name+"'"

	if start_addr:
		start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
		data['WHERE'] += "AND start_ip6_addr='"+start_addr_hexa+"'"

	r = requests.get(url,headers=headers,params=data,verify=False)

	if r.status_code == 200:
		return r.json()[0]

	else:
		return None



def get_block_subnet_list_v4(start_addr,sitename,name):
	data=dict()
	start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
	url,headers = request_builder.requestBuilder.buildRequest('ip_block_subnet_list')
	data['WHERE'] = "subnet_level='0' AND site_name='" + sitename +"' AND start_ip_addr='"+ \
		start_addr_hexa+"' AND subnet_name='"+name+"'"


	r = requests.get(url,headers=headers,params=data,verify=False)

	if r.status_code == 200:
		r_json = r.json()
		block_id = r_json[0]['subnet_id']

	elif r.status_code == 204:
		# No content, which means the block does not exist
		block_id = None

	return block_id




def get_block_subnet_list_v6(start_addr,sitename,name):
	data=dict()
	start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
	url,headers = request_builder.requestBuilder.buildRequest('ip6_block6_subnet6_list')
	data['WHERE'] = "subnet_level='0' AND site_name='" + sitename +"' AND start_ip6_addr='"+\
		start_addr_hexa+"' AND subnet6_name='"+name+"'"

	r = requests.get(url,headers=headers,params=data,verify=False)
        if r.status_code == 200:
                r_json = r.json()
		block_id = r_json[0]['subnet6_id']	

	elif r.status_code == 204:
		# No content, which means the block does not exist
                block_id = None


	return block_id




def create_block_subnet_v4(start_addr,prefix,site_name,subnet_block_name):
	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip_subnet_add')
	data['subnet_addr'] = str(start_addr)
	data['subnet_prefix'] = prefix
 	data['subnet_level'] = 0
	data['subnet_name'] = subnet_block_name
	data['site_name'] = site_name

	r = requests.post(url,headers=headers,json=data,verify=False)

	if r.status_code == 201:
		r_json = r.json()
		return r_json[0]['ret_oid']
	else:
		return None



def create_block_subnet_v6(start_addr,prefix,site_name,subnet_block_name):
	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_add')
	data['subnet6_addr'] = start_addr
	data['subnet6_prefix'] = prefix
	data['subnet_level'] = 0
	data['subnet6_name'] = subnet_block_name
	data['site_name'] = site_name

	r = requests.post(url,headers=headers,json=data,verify=False)

	if r.status_code == 201:
		r_json = r.json()
		return r_json[0]['ret_oid']
	else:
		return None




def get_free_subnet_v4(block_id,prefixlen):
	# block_id : id returned by get_block_subnet_list_v4 or create_block_subnet_v4
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip_find_free_subnet')
	data['WHERE'] = "block_id='"+block_id+"'"
	data['prefix'] = prefixlen
	r = requests.get(url,headers=headers,params=data,verify=False)

	LOG.error(r.url)
	LOG.error(str(r.status_code))

	if r.status_code == 200:
		r_json = r.json()
		startAddr = netaddr.IPAddress('0x'+str(r_json[0]['start_ip_addr']))
		return netaddr.IPNetwork(str(startAddr)+'/'+str(prefixlen))

	else:
		return None


def get_free_subnet_v6(block_id,prefixlen):
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip6_find_free_subnet6')
	data['WHERE'] = "block6_id='"+block_id+"'"
	data['prefix'] = prefixlen
	r = requests.get(url,headers=headers,params=data,verify=False)

	if r.status_code == 200:
		r_json = r.json()
		startAddr = netaddr.IPAddress(add_columns(str(r_json[0]['start_ip6_addr'])))
		return netaddr.IPNetwork(str(startAddr)+'/'+str(prefixlen))

	else:
		return None
	

def create_subnet_v4(block_id,subnet_name=None,start_addr=None,prefix=0):
	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip_subnet_add')
	data['subnet_level']=1
	data['subnet_addr'] = str(netaddr.IPAddress(start_addr))
	data['subnet_prefix'] = prefix
	if subnet_name is not None:
		data['subnet_name'] = subnet_name
	data['parent_subnet_id'] = block_id

	r = requests.post(url,headers=headers,json=data,verify=False)
    	if r.status_code == 201:
		r_json = r.json()
		return r_json[0]['ret_oid']
	else:
		return None

def create_subnet_v6(block_id,subnet_name=None,start_addr=None,prefix=0):
        data=dict()
        url, headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_add')
        data['subnet_level']=1
	data['subnet6_addr'] = str(netaddr.IPAddress(start_addr))
	data['subnet6_prefix'] = prefix
	if subnet_name is not None:
		data['subnet6_name'] = subnet_name
	data['parent_subnet6_id'] = block_id
	r = requests.post(url,headers=headers,json=data,verify=False)
	LOG.error(r.url)
	LOG.error(str(data))
	if r.status_code == 201:
		r_json = r.json()
		return r_json[0]['ret_oid']
	else:
		return None


def delete_block_subnet_v4(sitename,subnet_addr,subnet_prefix):
	data=dict()
        url, headers = request_builder.requestBuilder.buildRequest('ip_subnet_delete')
        data['subnet_level']=0
        data['site_name'] = sitename
        data['subnet_addr'] = str(netaddr.IPAddress(subnet_addr))
        data['subnet_prefix'] = subnet_prefix

        r = requests.delete(url,headers=headers,json=data,verify=False)

        if r.status_code == 200:
                return 1
        else:
                return None

def delete_block_subnet_v6(sitename,subnet_addr,subnet_prefix):
        data=dict()
        url,headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_delete')
        data['subnet_level'] = 0
        data['site_name'] = sitename
        data['subnet6_addr'] = str(netaddr.IPAddress(subnet_addr))
        data['subnet6_prefix'] = subnet_prefix

        r = requests.delete(url,headers=headers,json=data,verify=False)

        if r.status_code == 200:
                return 1
        else:
                return None

	

def delete_subnet_v4(sitename,subnet_addr,subnet_prefix):
	data=dict()
        url,headers = request_builder.requestBuilder.buildRequest('ip_subnet_delete')
	data['subnet_level'] = 1
	data['site_name'] = sitename
	data['subnet_addr'] = str(netaddr.IPAddress(subnet_addr))
	data['subnet_prefix'] = subnet_prefix

	r = requests.delete(url,headers=headers,json=data,verify=False)

	if r.status_code == 200:
		return 1
	else:
		return None


def delete_subnet_v6(sitename,subnet_addr,subnet_prefix):
	data=dict()
        url,headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_delete')
	data['subnet_level'] = 1
	data['site_name'] = sitename
	data['subnet6_addr'] = str(netaddr.IPAddress(subnet_addr))
	data['subnet6_prefix'] = subnet_prefix

	r = requests.delete(url,headers=headers,json=data,verify=False)

	if r.status_code == 200:
		return 1
	else:
		return None


def rename_subnet_v4(subnet_id,subnet_new_name):
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip_subnet_add')
	data['subnet_id'] = subnet_id
	data['subnet_name'] = subnet_new_name

        r = requests.put(url,headers=headers,json=data,verify=False)

def rename_subnet_v6(subnet_id,subnet_new_name):
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_add')
	data['subnet6_id'] = subnet_id
	data['subnet6_name'] = subnet_new_name

        r = requests.put(url,headers=headers,json=data,verify=False)

def create_allocation_pool_v4(subnet_id,start_addr,end_addr):
	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip_pool_add')
	data['subnet_id'] = subnet_id
	data['start_addr'] = str(netaddr.IPAddress(start_addr))
	data['end_addr'] = str(netaddr.IPAddress(end_addr))
	r = requests.post(url,headers=headers,json=data,verify=False)

	if r.status_code == 201:
		return 1
	else:
		LOG.error(str(r.__dict__))
		return None


def create_allocation_pool_v6(subnet_id,start_addr,end_addr):
	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip6_pool6_add')
	data['subnet6_id'] = subnet_id
	data['start_addr'] = str(netaddr.IPAddress(start_addr))
	data['end_addr'] = str(netaddr.IPAddress(end_addr))
	r = requests.post(url,headers=headers,json=data,verify=False)

	if r.status_code == 201:
		return 1
	else:
		return None


def delete_allocation_pool_v4(subnet_id,start_addr,end_addr):
  	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip_pool_delete')
	data['subnet_id'] = str(subnet_id)
	data['start_addr'] = str(netaddr.IPAddress(start_addr))
	data['end_addr']   = str(netaddr.IPAddress(end_addr))
	r = requests.delete(url,headers=headers,json=data,verify=False)

	if r.status_code == 200:
		return 1
	else:
		LOG.error(str(r.__dict__))
		return None



def delete_allocation_pool_v6(subnet_id,start_addr,end_addr):
  	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip6_pool6_delete')
	data['subnet6_id'] = subnet_id
	data['start_addr'] = str(netaddr.IPAddress(start_addr))
	data['end_addr']   = str(netaddr.IPAddress(end_addr))
	r = requests.delete(url,headers=headers,json=data,verify=False)

	if r.status_code == 200:
		return 1
	else:
		return None


def get_allocation_pool_list_v4(subnet_id):
	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip_pool_list')
        data['WHERE'] = "subnet_id='"+subnet_id+"'"
        r = requests.get(url,headers=headers,params=data,verify=False)

	if r.status_code == 200:
		r_json = r.json()
	else:
		r_json = []
                ## NO pools associated

	return r_json


def get_allocation_pool_list_v6(subnet_id):
	data=dict()
	url, headers = request_builder.requestBuilder.buildRequest('ip6_pool6_list')
        data['WHERE'] = "subnet6_id='"+subnet_id+"'"
        r = requests.get(url,headers=headers,params=data,verify=False)

	if r.status_code == 200:
		r_json = r.json()
	else:
		r_json = []
                ## NO pools associated

	return r_json




def allocate_address_v4(sitename,address,name,mac):
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip_add')
	data['hostaddr'] = str(netaddr.IPAddress(address))
	data['site_name'] = sitename
	if name != '':
		data['name'] = name
	if mac != '':
		data['mac_addr'] = mac

	r = requests.post(url,headers=headers,json=data,verify=False)

	if r.status_code == 201:
		return 1
	else:
		return None

def allocate_address_v6(sitename,address,name,mac):
	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip6_address6_add')
	data['hostaddr'] = str(netaddr.IPAddress(address))
	data['site_name'] = sitename
	if name != '':
		data['ip6_name'] = name
	if mac != '':
		data['ip6_mac_addr'] = mac

	r = requests.post(url,headers=headers,json=data,verify=False)

	if r.status_code == 201:
		return 1
	else:
		return None


def get_free_address_v4(subnetId):
	# subnetId : returned from a previous call to get_subnet_list_v4

	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip_find_free_address')
	data['subnet_id'] = subnetId

	r = requests.get(url,headers=headers,params=data,verify=False)
        try:    
		return r.json()[0]['hostaddr']
	except: 
		return None


def get_free_address_v6(subnetId):
	# subnetId : returned from a previous call to get_subnet_list_v6

	data=dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip6_find_free_address6')
	data['subnet6_id'] = subnetId

	r = requests.get(url,headers=headers,params=data,verify=False)
        try:    
		return r.json()[0]['hostaddr6']
	except: 
		return None


def deallocate_address_v4(sitename,address):
	data = dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip_delete')
	data['site_name'] = sitename
	data['hostaddr']  = str(address)

	r = requests.delete(url,headers=headers,json=data,verify=False)
	if r.status_code == 200:
		return 1

	else:
		return None



def deallocate_address_v6(sitename,address):
	data = dict()
	url,headers = request_builder.requestBuilder.buildRequest('ip6_address6_delete')
	data['site_name'] = sitename
	data['hostaddr']  = str(address)

	r = requests.delete(url,headers=headers,json=data,verify=False)
	if r.status_code == 200:
		return 1

	else:
		return None

	




