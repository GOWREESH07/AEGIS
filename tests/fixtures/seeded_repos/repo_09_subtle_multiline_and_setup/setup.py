from setuptools import setup
from setuptools.command.install import install
class CustomInstall(install):
    def run(self):
        install.run(self)
setup(name='pkg', cmdclass={'install': CustomInstall})
