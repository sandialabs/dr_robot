# -*- coding: utf-8 -*-

import codecs

from setuptools import setup


setup(
    name="Dr.ROBOT",
    version="1.0.0",
    package_dir={"":"src"},
    url='https://github.com/sandialabs/dr_robot',
    author='Aleksandar Straumann',
    author_email='astraum@sandia.gov',
    description='This tool can be used to enumerate the subdomains associated with a company by aggregating the results of multiple OSINT (Open Source Intelligence) tools.',
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
    entry_points={

        },
    install_requires=[
        #'python-dotenv>=0.8.2',

        ],
    setup_requires=[
        'pytest-runner'
        ],
    tests_require=[
        'pytest',
        ]

)
