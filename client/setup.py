from distutils.core import setup
setup(name='libinfoclient',
	version='1.0b1',
	author='Julian Frielinghaus',
	url='https://github.com/hansau22/infobook',

#	py_modules = [
#	'libinfo/ConnectionHandler', 
#	'libinfo/DatabaseHandler', 
#	'libinfo/EncryptionHandler', 
#	'libinfo/Pool'
#	],

	packages = ["libinfoclient"],
	package_dir = {"libinfoclient" : "libinfoclient"}, 

      )



