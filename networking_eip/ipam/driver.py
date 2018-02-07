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

import netaddr
import sys
import json
import os


from oslo_log import log as logging
from oslo_config import cfg


import oslo_messaging

from neutron.ipam import driver
from neutron_lib import exceptions as neutron_lib_exc
from neutron.ipam import requests as neutron_ipam_req
from neutron.ipam import subnet_alloc as neutron_subnet_alloc
from neutron.ipam import exceptions as ipam_exc

from networking_eip.neutron_connector import connector
from networking_eip.subnet_factory import subnet_factory
from networking_eip.subnet_factory import address_factory

import networking_eip.request_builder.eip_rest as eip_rest

LOG = logging.getLogger(__name__)


class RequestNotSupported(neutron_lib_exc.NeutronException):
	message = _("IPAM error : '%(msg)s' ")


def retrieveContainersFromNeutron(function):
	""" Decorator to query Neutron server and retrieve its stored data """
	def wrap_function(*args,**kwargs):
		if isinstance(args[0],eipPool):
			if args[0]._subnetpool is not None:
				args[0].scope_json = connector.NeutronConnector().get_connector().list_address_scopes(id=args[0]._subnetpool['address_scope_id'])['address_scopes'][0]
			else: 
				subnet_id = args[1].subnet_id if hasattr(args[1],'subnet_id') else args[1]
				args[0].subnet_json = connector.NeutronConnector().get_connector().list_subnets(id=subnet_id)['subnets'][0]
				args[0].pool_json = connector.NeutronConnector().get_connector().list_subnetpools(id=args[0].subnet_json['subnetpool_id'])['subnetpools'][0] if args[0].subnet_json['subnetpool_id'] else None
				args[0].scope_json = connector.NeutronConnector().get_connector().list_address_scopes(id=args[0].pool_json['address_scope_id'])['address_scopes'][0] if args[0].pool_json and args[0].pool_json['address_scope_id'] else None


		elif isinstance(args[0],eipSubnet):
			args[0].subnet_json = connector.NeutronConnector().get_connector().list_subnets(id=args[0].subnet_id)['subnets'][0]
		        args[0].pool_json = connector.NeutronConnector().get_connector().list_subnetpools(id=args[0].subnet_json['subnetpool_id'])['subnetpools'][0]
		        args[0].scope_json = connector.NeutronConnector().get_connector().list_address_scopes(id=args[0].pool_json['address_scope_id'])['address_scopes'][0]

		if args[0].scope_json is None:
			# This subnet is not complient with our IPAM : it has no site
	                LOG.error("Failed : to retrieve "+subnet_id+" in IPAM")
        	        raise neutron_lib_exc.SubnetNotFound(subnet_id=subnet_id)

		args[0].sitename = args[0].scope_json['name']

		return function(*args,**kwargs)
	return wrap_function
			



#### neutron_subnet_alloc.SubnetAllocator is a derived class of driver.pool
class eipPool(neutron_subnet_alloc.SubnetAllocator):

    """Interface definition for an IPAM driver.

    There should be an instance of the driver for every subnet pool.
    """

    def __init__(self, subnetpool, context):
        """Initialize pool

        :param subnet_pool_id: SubnetPool ID of the address space to use.
        :type subnet_pool_id: str uuid
        """
        LOG.info("eip driver : Init")
        super(eipPool, self).__init__(subnetpool, context)

        LOG.info("eip driver : Init successful")

    @retrieveContainersFromNeutron
    def get_subnet(self, subnet_id):
        """Gets the matching subnet if it has been allocated

        :param subnet_id: the subnet identifier
        :type subnet_id: str uuid
        :returns: An instance of IPAM Subnet
        :raises: IPAMAllocationNotFound
        """

	subnet_request = neutron_ipam_req.SpecificSubnetRequest(self.subnet_json['tenant_id'],subnet_id,
			self.subnet_json['cidr'],None,[])

	subnetpool_name = self._subnetpool['name'] if self._subnetpool else self.pool_json['name']
	
	start_addr,_,__ = str(self.subnet_json['cidr']).partition('/')

	if self.subnet_json['ip_version'] == 4:
		s = eip_rest.get_subnet_list_v4(start_addr,self.sitename,subnetpool_name)
		
	elif self.subnet_json['ip_version'] == 6:
		s = eip_rest.get_subnet_list_v6(start_addr,self.sitename,subnetpool_name)

	if s is None:
		LOG.error("Failed : to retrieve "+subnet_id+" in IPAM")
		raise neutron_lib_exc.SubnetNotFound(subnet_id=subnet_id)


	ret = eipSubnet(subnet_request)
	return ret


    @retrieveContainersFromNeutron
    def allocate_subnet(self, request):
        """Allocates a subnet based on the subnet request

        :param request: Describes the allocation requested.
        :type request: An instance of a sub-class of SubnetRequest
        :returns: An instance of Subnet
        :raises: RequestNotSupported, IPAMAlreadyAllocated
        """

	LOG.info("eip driver : Entering allocate_subnet")

	subnet = eipSubnet(request)

	## Create the related space on solid-server. 
	## Even if we are listening to notifications for scope creations, it's quite useful to do it here
	## in case of migration


	siteFromIpam = eip_rest.get_site_list(site_name=self.sitename)

	if siteFromIpam is None:
		LOG.info("Creating site "+self.sitename)
		siteFromIpam = eip_rest.create_site(site_name=self.sitename)
	        if siteFromIpam is None:	
			raise RequestNotSupported(msg="Could not create site "+self.sitename)


	## TODO : obviously, if we've just created the site, the block does not exist
	
	if self._subnetpool['ip_version'] == 4:
		blockFromIpam = eip_rest.get_block_subnet_list_v4(self._subnetpool['prefixes'][0].ip,self.sitename, self._subnetpool['name'])

	elif self._subnetpool['ip_version'] == 6:
		blockFromIpam = eip_rest.get_block_subnet_list_v6(self._subnetpool['prefixes'][0].ip,self.sitename, self._subnetpool['name'])

	if blockFromIpam is None:
		LOG.info("Creating block "+self._subnetpool['name'])
		#TODO : handle multiple prefixes: for p in self._subnetpool['prefixes']:
		data = dict()
		if self._subnetpool['ip_version'] == 4:
			blockFromIpam = eip_rest.create_block_subnet_v4(
				self._subnetpool['prefixes'][0].ip,
				self._subnetpool['prefixes'][0].prefixlen,
				self.sitename,
				self._subnetpool['name'])
		elif self._subnetpool['ip_version'] == 6:
			blockFromIpam = eip_rest.create_block_subnet_v6(
                                self._subnetpool['prefixes'][0].ip,
                                self._subnetpool['prefixes'][0].prefixlen,
                                self.sitename,
                                self._subnetpool['name'])

		if blockFromIpam is None:
			LOG.error("Failed to create block "+self._subnetpool['name'])
			raise RequestNotSupported(msg="Could not create block "+self._subnetpool['name'])

		parent_subnet_id = blockFromIpam


		## Create the subnet. No extra checks needed, neutron handles duplicates and overlaps 


		### Case where neutron passes a request with just prefixlen (no cidr) : 
		##   - retrieve the block subnet
		##   - use rpc find free call to get a subnet
		##   - process normally and allocate it 

	if subnet.cidr is None:
		if self._subnetpool['ip_version'] == 4:
			freeSubnet =  eip_rest.get_free_subnet_v4(blockFromIpam,subnet.prefixlen)
			if freeSubnet is None:
				LOG.error("Could not find a free subnet")
				raise ipam_exc.InvalidAddressRequest(reason="Could not find a range for prefix "+str(subnet.prefixlen))

		elif self._subnetpool['ip_version'] == 6:
			freeSubnet =  eip_rest.get_free_subnet_v6(blockFromIpam,subnet.prefixlen)
                        if freeSubnet is None:
                                LOG.error("Could not find a free subnet")
                                raise ipam_exc.InvalidAddressRequest(reason="Could not find a range for prefix "+str(subnet.prefixlen))
		
		subnet.cidr = freeSubnet
				
	if self._subnetpool['ip_version'] == 4:
		subnet_name = request.subnet_name if hasattr(request,"subnet_name") else None
		start_addr,_,prefix = str(subnet.cidr).partition('/') 
		subnet_id = eip_rest.create_subnet_v4(blockFromIpam,subnet_name,start_addr,prefix)



	elif self._subnetpool['ip_version'] == 6:
		subnet_name = request.subnet_name if hasattr(request,"subnet_name") else None
		start_addr,_,prefix = str(subnet.cidr).partition('/') 
		subnet_id = eip_rest.create_subnet_v6(blockFromIpam,subnet_name,start_addr,prefix)


	if subnet_id is None:
		LOG.error("Subnet creation failed")
		raise RequestNotSupported(msg="Could not create subnet "+request.subnet_name if hasattr(request,"subnet_name") else "<No Name>")

	
	if self._subnetpool['ip_version'] == 4:
		for p in subnet.pools or []:
			start_addr,_,end_addr = str(p).partition('-')
			eip_rest.create_allocation_pool_v4(subnet_id,start_addr,end_addr)
	elif self._subnetpool['ip_version'] == 6:
		for p in subnet.pools or []:
			start_addr,_,end_addr = str(p).partition('-')
			eip_rest.create_allocation_pool_v6(subnet_id,start_addr,end_addr)


	return subnet


    @retrieveContainersFromNeutron
    def update_subnet(self, request):
        """Updates an already allocated subnet

        This is used to notify the external IPAM system of updates to a subnet.

        :param request: Update the subnet to match this request
        :type request: An instance of a sub-class of SpecificSubnetRequest
        :returns: An instance of IPAM Subnet
        :raises: RequestNotSupported, IPAMAllocationNotFound
        """

	LOG.info("eip driver : Entering update_subnet")

	subnet_from_request = eipSubnet(request)

	# NB : neutron raises exception in case the given pools are invalid (overlap or bad start/end)
	# NB2 : current_pools are sorted, which is nice

        if self.subnet_json['ip_version'] == 4:
	        start_addr,_,__ = str(self.subnet_json['cidr']).partition('/')
		subnetFromIpam = eip_rest.get_subnet_list_v4(start_addr,self.sitename,self.pool_json['name'])


		if subnetFromIpam is None:
			raise ipam_exc.InvalidSubnetRequest(reason="Subnet not found")


		if request.subnet_name and request.subnet_name != subnetFromIpam['subnet_name']:
			eip_rest.rename_subnet_v4(subnetFromIpam['subnet_id'],request.subnet_name)
			
			
		r_json = eip_rest.get_allocation_pool_list_v4(subnetFromIpam['subnet_id'])
	
		current_pools = set()
		new_pools = set()
		for p in r_json:
			a = netaddr.IPRange(long(p['start_ip_addr'],16),long(p['end_ip_addr'],16))
			LOG.info("Add to current_pools : "+str(a))
			current_pools.add(a)
		for p in subnet_from_request.pools:
			start_ip,_,end_ip = str(p).partition('-')
			a = netaddr.IPRange(start_ip,end_ip)
			LOG.info("Add to new_pools : "+str(a))
			new_pools.add(a)


## Pool edition may be faster as it requires only on operation but it's more complicated

		pools_to_create = new_pools.difference(current_pools) # pools in new_pools but not in current
		pools_to_remove = current_pools.difference(new_pools)

		for p in pools_to_remove:
			eip_rest.delete_allocation_pool_v4(subnetFromIpam['subnet_id'],p.first,p.last)

		for p in pools_to_create:
			eip_rest.create_allocation_pool_v4(subnetFromIpam['subnet_id'],p.first,p.last)


        elif self.subnet_json['ip_version'] == 6:
	        start_addr,_,__ = str(self.subnet_json['cidr']).partition('/')
                subnetFromIpam = eip_rest.get_subnet_list_v6(start_addr,self.sitename,self.pool_json['name'])

                if subnetFromIpam is None:
                        raise ipam_exc.InvalidSubnetRequest(reason="Subnet not found")


                if request.subnet_name and request.subnet_name != subnetFromIpam['subnet6_name']:
                        eip_rest.rename_subnet_v6(subnetFromIpam['subnet6_id'],request.subnet_name)
        
        
                r_json = eip_rest.get_allocation_pool_list_v6(subnetFromIpam['subnet6_id'])


                current_pools = set()
                new_pools = set()
                for p in r_json:
                        ipv6_addr_start = eip_rest.add_columns(p['start_ip6_addr'])
			ipv6_addr_end   =  eip_rest.add_columns(p['end_ip6_addr'])
			a = netaddr.IPRange(ipv6_addr_start,ipv6_addr_end)
                        LOG.info("Add to current_pools : "+str(a))
                        current_pools.add(a)

                for p in subnet_from_request.pools:
                        start_ip,_,end_ip = str(p).partition('-')
                        a = netaddr.IPRange(start_ip,end_ip)
                        LOG.info("Add to new_pools : "+str(a))
                        new_pools.add(a)


## Pool edition may be faster as it requires only on operation but it's more complicated

                pools_to_create = new_pools.difference(current_pools) # pools in new_pools but not in current
                pools_to_remove = current_pools.difference(new_pools)

                for p in pools_to_remove:
                        eip_rest.delete_allocation_pool_v6(subnetFromIpam['subnet6_id'],p.first,p.last)

                for p in pools_to_create:
                        eip_rest.create_allocation_pool_v6(subnetFromIpam['subnet6_id'],p.first,p.last)


	return subnet_from_request



    @retrieveContainersFromNeutron
    def remove_subnet(self, subnet_id):
        """Removes an allocation

        The initial reference implementation will probably do nothing.

        :param subnet_id: the subnet identifier
        :type subnet_id: str uuid
        :raises: IPAMAllocationNotFound
        """

        if self.subnet_json['ip_version'] == 4:
		subnet_addr,_,subnet_prefix = str(self.subnet_json['cidr']).partition('/')
		r = eip_rest.delete_subnet_v4(self.sitename,subnet_addr,subnet_prefix)

        elif self.subnet_json['ip_version'] == 6:
		subnet_addr,_,subnet_prefix = str(self.subnet_json['cidr']).partition('/')
		r = eip_rest.delete_subnet_v6(self.sitename,subnet_addr,subnet_prefix)

	if r is None:
                LOG.error("Failed : to retrieve "+subnet_id+" in IPAM")
                raise neutron_lib_exc.SubnetNotFound(subnet_id=subnet_id)


	return


    def get_subnet_request_factory(self):
	return subnet_factory.eipSubnetRequestFactory

    def get_address_request_factory(self):
	return address_factory.eipAddressRequestFactory
	

class eipSubnet(driver.Subnet):
    """Interface definition for an IPAM subnet

    A subnet would typically be associated with a network but may not be.  It
    could represent a dynamically routed IP address space in which case the
    normal network and broadcast addresses would be useable.  It should always
    be a routable block of addresses and representable in CIDR notation.
    """

    def __init__(self,request):
	LOG.info("Init an eip subnet")
	req_dict = request.__dict__
	self.gateway_ip = req_dict.get('_gateway_ip',None)
	self.cidr = req_dict.get('_subnet_cidr',None)
	self.prefixlen = req_dict.get('_prefixlen',None)
	self.tenant_id = req_dict['_tenant_id']
	self.subnet_id = req_dict['_subnet_id']
	pools = req_dict.get('_allocation_pools',[])
	self.pools = pools if pools is not None else []

    def __str__(self):
	ret = "eipSubnet obj : gw "+str(self.gateway_ip) + " id "+str(self.subnet_id)
	return ret


    @retrieveContainersFromNeutron
    def allocate(self,address_request):

        """Allocates an IP address based on the request passed in

        :param address_request: Specifies what to allocate.
        :type address_request: An instance of a subclass of AddressRequest
        :returns: A netaddr.IPAddress
        :raises: AddressNotAvailable, AddressOutsideAllocationPool,
            AddressOutsideSubnet
        """

	# warning : doc says it must return a netaddr.ip address but the calling code expects a string

	LOG.info("Allocate an eip address")
	addressToReturn = None

	if isinstance(address_request,neutron_ipam_req.SpecificAddressRequest) or isinstance(address_request,neutron_ipam_req.RouterGatewayAddressRequest):

		## SpecificAddressRequest or AutomaticAddressRequest(such as ipv6 slaac or custom randomizer)
		if self.subnet_json['ip_version'] == 4:
			res = eip_rest.allocate_address_v4(self.sitename,str(address_request.address),address_request.name,address_request.mac)
		elif self.subnet_json['ip_version'] == 6:
			res = eip_rest.allocate_address_v6(self.sitename,str(address_request.address),address_request.name,address_request.mac)
		
		if res is None:
			raise ipam_exc.IpAddressAlreadyAllocated(ip=str(address_request.address), subnet_id=self.subnet_id)
		addressToReturn = address_request.address

	elif isinstance(address_request,neutron_ipam_req.AnyAddressRequest):
		
		## AnyAddressRequest or PreferNextAddressRequest : give the first one available

		if self.subnet_json['ip_version'] == 4:
			start_addr,_,__ = str(self.subnet_json['cidr']).partition('/')
			subnetFromIpam = eip_rest.get_subnet_list_v4(start_addr,self.sitename,self.pool_json['name'])
			freeAddr = eip_rest.get_free_address_v4(subnetFromIpam['subnet_id'])
			
			if freeAddr is None:
				raise ipam_exc.IpAddressGenerationFailure(subnet_id=subnetFromIpam['subnet_id'])

			LOG.info("Address "+str(freeAddr)+" will be allocated")

		 	res = eip_rest.allocate_address_v4(self.sitename,freeAddr,address_request.name,address_request.mac)
			if res is None:
				LOG.error("Failed to allocate "+str(freeAddr))
				raise ipam_exc.IpAddressAlreadyAllocated(ip=str(freeAddr), subnet_id=subnetFromIpam['subnet_id'])

		if self.subnet_json['ip_version'] == 6:
			start_addr,_,__ = str(self.subnet_json['cidr']).partition('/')
                        subnetFromIpam = eip_rest.get_subnet_list_v6(start_addr,self.sitename,self.pool_json['name'])
			freeAddr = eip_rest.get_free_address_v6(subnetFromIpam['subnet6_id'])
			
			if freeAddr is None:
				raise ipam_exc.IpAddressGenerationFailure(subnet_id=subnetFromIpam['subnet6_id'])

			LOG.info("Address "+str(freeAddr)+" will be allocated")
			
		 	res = eip_rest.allocate_address_v6(self.sitename,freeAddr,address_request.name,address_request.mac)
			if res is None:
				LOG.error("Failed to allocate "+str(freeAddr))
				raise ipam_exc.IpAddressAlreadyAllocated(ip=str(freeAddr), subnet_id=subnetFromIpam['subnet6_id'])
		addressToReturn = freeAddr

	else:
		LOG.error("Address has no type " + str(type(address_request)))


	return str(netaddr.IPAddress(addressToReturn))


    @retrieveContainersFromNeutron
    def deallocate(self,address):
        """Returns a previously allocated address to the pool

        :param address: The address to give back.
        :type address: A netaddr.IPAddress or convertible to one.
        :returns: None
        :raises: IPAMAllocationNotFound
        """

	LOG.info("Trying to deallocate : "+str(address))
	
	if self.subnet_json['ip_version'] == 4:
		ret = eip_rest.deallocate_address_v4(self.sitename,address)
	elif self.subnet_json['ip_version'] == 6:
		ret = eip_rest.deallocate_address_v6(self.sitename,address)


	if ret is None:
		raise ipam_exc.IpAddressAllocationNotFound(ip_address=str(address),subnet_id=self.subnet_id)


    def get_details(self):
        """Return subnet detail as a SpecificSubnetRequest.

        :returns: An instance of SpecificSubnetRequest with the subnet detail.
        """
### TODO : Maybe building the req is not efficient, we could store it in class attributes
	return neutron_ipam_req.SpecificSubnetRequest(self.tenant_id,self.subnet_id,self.cidr,
					      self.gateway_ip,self.pools)



