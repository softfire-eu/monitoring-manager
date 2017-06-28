import os

from setuptools import setup, find_packages


def read(fname):
    readme_file_path = os.path.join(os.path.dirname(__file__), fname)

    if os.path.exists(readme_file_path) and os.path.isfile(readme_file_path):
        readme_file = open(readme_file_path)
        return readme_file.read()
    else:
        return "The SoftFIRE Monitoring Manager"


setup(
    name="monitoring-manager",
    version="0.1.0",
    author="SoftFIRE",
    author_email="softfire@softfire.eu",
    description="The SoftFIRE Monitoring Manager",
    license="Apache 2",
    keywords="python vnfm nfvo sdk experiment manager softfire tosca openstack rest",
    url="http://softfire.eu/",
    packages=find_packages(),
    scripts=["monitoring-manager"],
    install_requires=[
        'bottle==0.12.13',
        'bottle-cork',
        'asyncio',
        'grpcio',
        'softfire-sdk',
        'tosca-parser', #probably not needed
        'pyyaml',
        'requests',
        'pbr==3.1.1',
        'oslo.utils==3.26.0',
        'oslo.i18n==3.15.3',
        'oslo.serialization==1.10.0',
        'keystoneauth1==2.21.0',
        'debtcollector==1.15.0',
        'stevedore==1.23.0',
        'python-novaclient',
    ],
    long_description=read('README.rst'),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",

    ],
)
