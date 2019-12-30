#!/usr/bin/env python

from setuptools import find_packages, setup

REPO_NAME = 'chickenzord/nginx-ldap-auth'
VERSION = '0.1.0'
ARCHIVE_URL = 'https://github.com/%s/archive/v%s.tar.gz' % (REPO_NAME, VERSION)


setup(
    # packaging
    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=[
        'Flask==1.1.1',
        'python-dotenv==0.10.3',
        'python-ldap==3.2.0',
        'prometheus_client==0.7.1',
    ],
    entry_points={
        "console_scripts": ['nginx_ldap_auth = nginx_ldap_auth.app']
    },
    zip_safe=False,

    # metadata
    name='nginx-ldap-auth',
    version=VERSION,
    author='Akhyar Amarullah',
    author_email='akhy@chickenzord.com',
    description='Re-implementation of Nginx basic auth backed by LDAP ',
    long_description=open('README.md').read(),
    download_url=ARCHIVE_URL,
    license='MIT',
    url='https://github.com/%s' % (REPO_NAME),
)
