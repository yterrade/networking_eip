from setuptools import setup,find_packages

with open('requirements.txt') as f:
      requirements = f.read().splitlines()

# See github.com/pypa/sampleproject/blob/master/setup.py
setup(name='networking_eip',
      version='0.1',
      packages=find_packages(),
      description='Neutron/OpenStack IPAM driver for Efficient IP SolidServer',
      url='http://www.efficientip.com',
      author='yoann terrade',
      author_email='yoannterrade@gmail.com',
      license='Apache',
      classifiers=[
              'Development Status :: 3 - Alpha',
              'License :: OSI Approved :: Apache Software License',
              'Programming Language :: Python :: 2.7',
              'Operating System :: POSIX :: Linux',
              'Environment :: OpenStack',
                  ],
      keywords='OpenStack, Neutron, IPAM',
      data_files = [('',['LICENSE.txt']),('',['eip_networking_agent.service'])],
      install_requires=requirements,
      entry_points={
	'console_scripts' :
		[ 'eip_networking_agent=networking_eip.service.eip_networking_agent:main'],
	'neutron.ipam_drivers':
                [ 'eip=networking_eip.ipam.driver:eipPool']
                   }
)
