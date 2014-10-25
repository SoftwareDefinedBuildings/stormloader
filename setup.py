from setuptools import setup
setup(
  name = 'stormloader',
  packages = ['stormloader'],
  version = '1.1',
  description = 'A utility for interacting with the Storm mote',
  author = 'Michael P Andersen',
  author_email = 'm.andersen@cs.berkeley.edu',
  url = 'https://github.com/SoftwareDefinedBuildings/stormloader',
  download_url = 'https://github.com/SoftwareDefinedBuildings/stormloader/tarball/1.1',
  entry_points={
     'console_scripts': [
        'sload = stormloader.main:entry'
     ]
  },
  install_requires=["pyelftools >= 0.22", "crcmod >= 1.7", "pylibftdi >= 0.14.2", "configobj >= 5.0.6", "six >= 1.8.0", "requests >= 2.4.3"],
  keywords = ['storm', 'mote', 'bootloader'],
  classifiers = [],
)
