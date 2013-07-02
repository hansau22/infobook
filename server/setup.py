from distutils.core import setup
setup(name='libinfo',
	version='1.0b1',
	author='Julian Frielinghaus',
	url='https://github.com/hansau22/infobook',

#	py_modules = [
#	'libinfo/ConnectionHandler', 
#	'libinfo/DatabaseHandler', 
#	'libinfo/EncryptionHandler', 
#	'libinfo/Pool'
#	],

	packages = ["libinfo"],
	package_dir = {"libinfo" : "libinfo"}, 

      )



