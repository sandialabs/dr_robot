# -*- coding: utf-8 -*-

import codecs

from setuptools import setup, find_packages

setup(
    name="drrobot",
    version="1.1.2",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    url='https://github.com/sandialabs/dr_robot',
    author='Aleksandar Straumann',
    author_email='astraum@sandia.gov',
    description='This tool can be used to enumerate the subdomains associated'
    + 'with a company by aggregating the results of multiple OSINT'
    + '(Open Source Intelligence) tools.',
    keywords=[
        'environment variables',
        'settings',
        'env',
        'encryption',
        'dotenv',
        'configurations',
        'python'
        ],
    long_description=codecs.open('README.md', encoding="utf8").read(),
    include_package_data=True,
    entry_points={
        'console_scripts': ['drrobot=robot_api.cli:run']
        },
    install_requires=[
        'docker~=4.0',
        'requests~=2.0',
        'netaddr~=0.7.19',
        'mattermostdriver~=6.0',
        'shodan~=1.0',
        'certifi~=2019.9',
        'beautifulsoup4~=4.0',
        'argparse',
        'tqdm~=4.0',
        'dicttoxml~=1.0',
        'slackclient~=2.0',
        ],
    setup_requires=[
        'pytest-runner'
        ],
    tests_require=[
        'pytest',
        ]
)
