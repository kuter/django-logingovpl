import os

from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))


setup(
    name='logingovpl',
    version='0.0.0',
    packages=find_packages(exclude=["*.swp"]),
    install_requires=[
        'Django >=2.1,<2.2',
        'django-appconf',
        'xmlsec',
        'defusedxml',
        'requests',
        'pycryptodome',
        'cryptography',
    ],
    include_package_data=True,
    license='MIT license',  # example license
    description='Django Login.gov.pl auth',
    url='https://www.example.com/',
    author='kuter',
    author_email='kuter@example.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 2.1',  # replace "X.Y" as appropriate
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT license',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
