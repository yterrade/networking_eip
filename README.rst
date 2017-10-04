==============
Networking EIP
==============
Neutron IPAM driver for EfficientIP SolidServer

===================
Package description
===================
    - ipam : the implementation of neutron driver interface
    - neutron_connector : an helper class to interact with neutron (access neutron info such as names, ids, …)
    - request_builder : an helper class to prepare requests from the driver to EIP solid server and high-level APIs to encapsulate REST calls to the SolidServer
    - service : a python script running as a service, to listen to openstack events (such as pools / address-scopes creation)
    - subnet_factory : a specialisation of subnet_factory generic class provided by Neutron. This class provides extra data (subnet name) in subnet requests, that will be inserted in IPAM records

=========================
Quick configuration guide
=========================

OpenStack
---------
In /etc/systemd/system/multi-user.target.wants/neutron-server.service, set PrivateTmp = false

Neutron
-------
In /etc/neutron/neutron.conf
    - In [oslo_messaging_notifications] section, set
       * driver=messagingv2
       * topics=notifications

    - In [DEFAULT] section, set ipam_driver = eip

    - Create a new [solidserver] section with the following keys/values:
       * address = <solid server ip>
       * username = <admin username, default : ipmadmin>
       * password = <admin password>

    - Create a new [eip_connector] section with the following keys/values:
       * username =  <username for this openstack deployment>
       * password =  <password for this user>
       * project_name = <the tenant name>
       * user_domain_id = <the domain used for users management, can be got from identity component config>
       * project_domain_id = <the domain used for projects management, can be got from identity component config>
       * auth_uri = <Identity component endpoint, default : http://<openstack_ip>:5000/v3 >

Keystone
--------
In /etc/keystone/keystone.conf
    - In [oslo_messaging_notifications] section, set
       * driver=messagingv2
       * topics=notifications

Nova
----
In /etc/nova/nova.conf
    - In [oslo_messaging_notifications] section, set
       * driver=messagingv2
       * topics=notifications


Restart the services
--------------------
    - Keystone : systemctl restart httpd
    - Neutron : systemctl restart neutron-server
    - Nova : systemctl restart nova-compute

Start eip_networking agent
--------------------------
The package includes a systemd service file that can be copied to /usr/lib/systemd/system. This allows eip_networking_agent to be run like a standard systemd service (systemctl enable eip_networking_agent, then systemctl start eip_networking_agent).
Alternatively, the agent can be launched manually via /usr/bin/eip_networking_agent.


==========
Data model
==========
1-1 mapping between neutron containers and SolidServer containers

================== ==================
Neutron            SolidServer  
================== ==================
address-scope      space         
subnetpool         block         
subnet             subnet
allocation-pool    pool       
port               address        
================== ==================

