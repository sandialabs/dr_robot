# Configuration

Dr.ROBOT is built in a modular fashion, making it easy to add new tools. You have three options for adding a new tool to Dr.ROBOT:

#### Important: To make sure no issues come from adding your own tool, make sure the key used to identify a json item, the name, and docker_name are all unique. 

## 1. Docker container
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


## 2. Ansible Playbook
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
* `$outdir` comes from Dr.ROBOT. It will generate a path that points to ```$HOME/.drrobot/output/<domain>/ ``` Again, you can specify a custom path if you like. 

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

## 3. Web Module
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
