

```
.______  .______  .______  ._______  ._______ ._______  _____._
:_ _   \ : __   \ : __   \ : .___  \ : __   / : .___  \ \__ _:|
|   |   ||  \____||  \____|| :   |  ||  |>  \ | :   |  |  |  :|
| . |   ||   :  \ |   :  \ |     :  ||  |>   \|     :  |  |   |
|. ____/ |   |___\|   |___\ \_. ___/ |_______/ \_. ___/   |   |
 :/      |___|    |___|       :/                 :/       |___|
 :                            :                  :             
```

[![Dc27Badge](https://img.shields.io/badge/DEF%20CON-27-green)](https://defcon.org/html/defcon-27/dc-27-demolabs.html#Dr.%20ROBOT)
[![License](http://img.shields.io/:license-mit-blue.svg)](https://github.com/sandialabs/dr_robot/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/sandialabs/dr_robot.svg?branch=master)](https://travis-ci.org/sandialabs/dr_robot)

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

## Config Files

DrROBOT adds config files, templates, logs, output files, and db files to your $HOME directory under ```.drrobot```

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
If you ever break your config beyond saving, you can delete the config.json file in your $HOME directory and rerun Dr.ROBOT, which will generate a new config file for you.

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
pipenv install -e .
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

## Configuration
Dr.ROBOT is built in a modular fashion, making it easy to add new tools. You have three options for adding a new tool to Dr.ROBOT:

#### Important: To make sure no issues come from adding your own tool, make sure the key used to identify a json item, the name, and docker_name are all unique. 

### 1. Docker container
Use the config file found at `$HOME/.drrobot/config.json`. Use the existing modules as a template. For this example I am using the Amass tool:
```
        "Amass": {
            "name": "Amass",
            "default" : false,
            "mode" : "DOCKER",
            "network_mode": "host",
            "docker_name" : "amass",
            "default_conf": "docker_buildfiles/Dockerfile.Amass.tmp",
            "active_conf": "docker_buildfiles/Dockerfile.Amass",
            "description": "The OWASP Amass tool suite obtains subdomain names by scraping data sources, recursive brute forcing, crawling web archives, permuting/altering names and reverse DNS sweeping.",
            "src": "https://github.com/OWASP/Amass",
            "output": "/root/amass",
            "output_folder": "amass"
        },
```

To add your own tool you can simply replace the above data as necessary with your tools information. 

Now add a Dockerfile to `$HOME/.drrobot/docker_buildfiles`. Simply follow the naming scheme for default and active conf when creating your file. 
```
FROM golang:1.12.6-alpine3.10 as build
RUN apk --no-cache add git
RUN go get github.com/OWASP/Amass; exit 0

ENV GO111MODULE on

WORKDIR /go/src/github.com/OWASP/Amass

RUN go install ./...

FROM alpine:latest
COPY --from=build /go/bin/amass /bin/amass
COPY --from=build /go/src/github.com/OWASP/Amass/wordlists/ /wordlists/

ENV http_proxy $proxy
ENV https_proxy $proxy
ENV DNS $dns
ENV HOME /

RUN mkdir -p $output

ENV TARGET $target
ENV OUTPUT $output/amass.txt
ENV INFILE  $infile

ENTRYPOINT amass enum --passive -d "$target" -o $$OUTPUT
```
As you can see there are some ENV variables that are passed in when running our tool. If you have any specific ones that you would like to pass into the docker container, you can add them to the above JSON using a name which you will then reference in the Dockerfile. For example you will notice `$output` is used. `$output` comes from the above json blob and is then replaced during the runtime of Dr.ROBOT.


### 2. Ansible Playbook
Similar to adding a Docker container we first add our tool to the configuration file. 
```
        "HTTPScreenshot": {
            "name" : "HTTPScreenshot",
            "short_name" : "http",
            "mode" : "ANSIBLE",
            "ansible_arguments" : {
                "config" : "$config/httpscreenshot_play.yml",
                "flags": "-e '$extra' -i configs/ansible_inventory",
                "extra_flags":{
                    "1" : "variable_host=localhost",
                    "2" : "variable_user=user", 
                    "3" : "infile=$infile",
                    "4" : "outfile=$outdir/httpscreenshots.tar",
                    "5" : "outfolder=$outdir/httpscreenshots"
                }
            },
            "description" : "Post enumeration tool for screen grabbing websites. All images will be downloaded to outfile: httpscreenshot.tar and unpacked httpscreenshots",
            "output" : "/tmp/output",
            "infile" : "/tmp/output/aggregated/aggregated_protocol_hostnames.txt",
        },
```

Take special note of the `ansible_arguments`. The two required items are `config` and `flags`. These two items tell Dr.ROBOT what file to use and what inventory and flags will be used. `extra flags` is a nested JSON block where you can specify any parameters that need to go into the ansible playbook.

Note: 

* `$infile` comes from the outermost **infile**, so that it is consistent for both docker and ansible. You can use a full path to a file for input if you desire.
* `$outdir` comes from Dr.ROBOT. It will generate a path that points to `$HOME/.drrobot/output/<domain>/`. Again, you can specify a custom path if you like. 

#### The Playbook
This will simply be a standard playbook with a few changes so that Dr.ROBOT can use the parameters we fed it. To make sure a parameter that we specified in the "extra_flags" JSON blob is available,  use Ansible syntax for variables: ```"{{ variable_name|quote }}"``` (Note the *quote* helps prevent issues with variable names)

```
---
- hosts: "{{ variable_host|quote }}"
  remote_user: "{{ variable_user|quote }}" 

  tasks:
      - name: Apt install git
        become: true
...
```

### 3. Web Module
Again we start with the `config.json` file. For web modules, you will be writing Python code that Dr.ROBOT can leverage for domain enumeration. As before, the names must be unique, however, for Web Modules the **class_name** must exactly match the class name inside web_resource.py.

```
        "Dumpster" :
        {
            "short_name" : "dump",
            "class_name" : "Dumpster",
            "default" : false,
            "description" : "Use the limited response of DNSDumpster. Requires API access for better results.",
            "output_file" : "dumpster.txt"
        },
```

#### The Module

Dr.ROBOT will use the JSON input to load classes at runtime which allows us to run your custom code! To add your custom code to the web_resource.py file there are some caveats:

1. It must extend the WebTool abstract base class. This allos DrROBOT to treat all imported classes as the same and run the only method we require: **do_query**.
2. If you want your output to be written to the correct folder you will store your results under the **self.results** list and call **_write_results** which will write to the output_file in your config.json.
