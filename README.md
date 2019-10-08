

```
.______  .______  .______  ._______  ._______ ._______  _____._
:_ _   \ : __   \ : __   \ : .___  \ : __   / : .___  \ \__ _:|
|   |   ||  \____||  \____|| :   |  ||  |>  \ | :   |  |  |  :|
| . |   ||   :  \ |   :  \ |     :  ||  |>   \|     :  |  |   |
|. ____/ |   |___\|   |___\ \_. ___/ |_______/ \_. ___/   |   |
 :/      |___|    |___|       :/                 :/       |___|
 :                            :                  :             
```

[![Dc27Badge](https://img.shields.io/badge/DEF%20CON-27-green)](https://defcon.org/html/defcon-27/dc-27-demolabs.html#Dr.%20ROBOT)[![License](http://img.shields.io/:license-mit-blue.svg)](https://github.com/sandialabs/dr_robot/blob/master/LICENSE)[![Build Status](https://travis-ci.org/sandialabs/dr_robot.svg?branch=master)](https://travis-ci.org/sandialabs/dr_robot)[![GitHub release (latest by date)](https://img.shields.io/github/v/release/sandialabs/dr_robot)](https://github.com/sandialabs/dr_robot/blob/master/CHANGELOG.md)[![GitHub Pipenv locked dependency version](https://img.shields.io/github/pipenv/locked/dependency-version/sandialabs/dr_robot/docker)]()[![GitHub Pipenv locked dependency version](https://img.shields.io/github/pipenv/locked/dependency-version/sandialabs/dr_robot/mattermostdriver)]() ![GitHub Pipenv locked dependency version](https://img.shields.io/github/pipenv/locked/dependency-version/sandialabs/dr_robot/slackclient)

Copyright 2019 National Technology & Engineering Solutions of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain rights in this software.

## Introduction

Dr.ROBOT is a tool for **Domain Reconnaissance and Enumeration**. By utilizing containers to reduce the overhead of dealing with dependencies, inconsistencies across operating systems, and different languages, Dr.ROBOT is built to be highly portable and configurable.

**Use Case**: Gather as many public facing servers that an organization possesses. Querying DNS resources enables us to quickly develop a large list of possible targets that you can run further analysis on.

**Note**: Dr.ROBOT is not just a one trick pony. You can easily customize the tools that are used to gather information, so that you can enjoy the benefits of using latest and greatest along with your battle tested favorites.

### List of current tools
* Altdns
* Amass
* Anubis
* Aquatone (Discover portion, when aquatone had multiple parts)
* CT-Exposer
* CTFR
* Eyewitness
* HTTPScreenshot
* Knock
* NMap Screenshot
* NMap 
* Reconng 
* Subbrute
* Subfinder
* Sublist3r
* Webscreenshot
* GoWitness

## Config Files

Dr.ROBOT adds config files, templates, logs, output files, and db files to your ```$HOME``` directory under ```.drrobot```

The directory structure will look like this:
```
-rw-r--r--   1       0 Sep 16 12:15 ansible_inventory
drwxr-xr-x   5     160 Sep 16 12:18 ansible_plays
-rw-r--r--   1   13576 Sep 16 12:41 config.json
drwxr-xr-x   4     128 Sep 17 10:48 dbs
drwxr-xr-x  21     672 Sep 16 13:51 docker_buildfiles
drwxr-xr-x   4     128 Sep 16 15:38 logs
drwxr-xr-x   3      96 Sep 16 12:46 output
```
If you ever break your config beyond saving, you can delete the config.json file in your ```$HOME``` directory and rerun Dr.ROBOT, which will generate a new config file for you.

## Installation (with pip)

```
git clone <URL>
cd gitrepo
pip install -r requirements.txt
pip install -e .
drrobot --help


usage: drrobot [-h] [--proxy PROXY] [--dns DNS] [--verbose] [--dbfile DBFILE]
               {gather,inspect,upload,rebuild,dumpdb,output,serve} ...

Docker DNS recon tool

positional arguments:
  {gather,inspect,upload,rebuild,dumpdb,output,serve}
    gather              Runs initial scanning phase where tools under the
                        webtools/scannerscategory will run and gather
                        information used in the following phases
    inspect             Run further tools against domain information gathered
                        from previous step.Note: you must either supply a file
                        which contains a list of IP/Hostnames orThe targeted
                        domain must have a db under the dbs folder
    upload              Upload recon data to Mattermost/Slack
    rebuild             Rebuild the database with additional files/all files
                        from previous runtime
    dumpdb              Dump contents of database (ip,hostname,banners) to a
                        text file with hostname for filename
    output              Generate output in specified format. Contains all
                        information from scans (images, headers, hostnames,
                        ips)
    serve               Serve database file in docker container using django

optional arguments:
  -h, --help            show this help message and exit
  --proxy PROXY         Proxy server URL to set DOCKER http_proxy too
  --dns DNS             DNS server to add to resolv.conf of DOCKER containers
  --verbose             Display verbose statements
  --dbfile DBFILE       Specify what db file to use for saving data too

```

## Installation (pipenv)

```
git clone <URL>
cd gitrepo
pipenv sync
pipenv shell
drrobot --help


usage: drrobot [-h] [--proxy PROXY] [--dns DNS] [--verbose] [--dbfile DBFILE]
               {gather,inspect,upload,rebuild,dumpdb,output,serve} ...

Docker DNS recon tool

positional arguments:
  {gather,inspect,upload,rebuild,dumpdb,output,serve}
    gather              Runs initial scanning phase where tools under the
                        webtools/scannerscategory will run and gather
                        information used in the following phases
    inspect             Run further tools against domain information gathered
                        from previous step.Note: you must either supply a file
                        which contains a list of IP/Hostnames orThe targeted
                        domain must have a db under the dbs folder
    upload              Upload recon data to Mattermost/Slack
    rebuild             Rebuild the database with additional files/all files
                        from previous runtime
    dumpdb              Dump contents of database (ip,hostname,banners) to a
                        text file with hostname for filename
    output              Generate output in specified format. Contains all
                        information from scans (images, headers, hostnames,
                        ips)
    serve               Serve database file in docker container using django

optional arguments:
  -h, --help            show this help message and exit
  --proxy PROXY         Proxy server URL to set DOCKER http_proxy too
  --dns DNS             DNS server to add to resolv.conf of DOCKER containers
  --verbose             Display verbose statements
  --dbfile DBFILE       Specify what db file to use for saving data too
```

## Certs

Running this behind a proxy was a pain. To make this less painful we create a certs directory under the ```$HOME/.drrobot/*``` where you can add your crt files. As part of the dockerfile build process we now generate tarfiles with the certificates so that applications, such as Amass, can run.

## Minio

Included with Dr.ROBOT is a docker-compose.yml file. This file contains a simple compose file to serve up Minio and the files gathered during runtime. 

To use:
```
cd /path/to/drrobot/
docker-compose up
```

## Docker

This tool relies heavily on Docker. 

See installation instructions here: 
* [Docker Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)
* [Docker MacOS](https://docs.docker.com/docker-for-mac/install/)
* [Docker Windows](https://docs.docker.com/docker-for-windows/install/)


## Ansible

You can make any module support Ansible. 

See [Installation](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#intro-installation-guide) guide for instructions.

* If using a mac you will need to install gnu-tar for Ansible to unpack compressed files: ```brew install gnu-tar```
* If you have an encrypted ssh key that requires a password to use and would not like to enter their password for every command ran remotely look into using an **ssh-agent**
```
eval $(ssh-agent)
ssh-add /path/to/keyfile
````


## Documentation

To add your own tool see the [Configuration](readmes/config.md) to get started.

For usage see [Usage](readmes/usage.md) to get started.
