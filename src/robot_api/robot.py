# -*- coding: utf-8 -*-
"""Robot Module

This module kicks off all things Dr.ROBOT. o

Attributess:
    domain (str): target domain for Dr.ROBOT
    ROOT_DIR (str): path to config and template files
    dns (str): Custom DNS server for building images
    proxy (str): Proxy server to run commands against
    verbose (bool): More output Yes/No
    dbfile (str): Location of dbfile
    aggregation (Aggregation): Module for aggregation
"""
import importlib
import json
from os import makedirs, walk
from os.path import exists, isfile, getsize, isdir
import logging
import threading
from xml.dom.minidom import parseString
import requests
from tqdm import tqdm
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import dicttoxml
from robot_api.api import Ansible, Docker, Aggregation
from robot_api.parse import join_abs


LOG = logging.getLogger(__name__)

class Robot:
    def __init__(self, **kwargs):
        """Initialize Robot object.

        Args:
            dns (str): Added DNS for host configuration
            proxy (str): Proxy url of format "http://proxy.foo.bar:port
            domain (str): Target domain
            root_dir (str): Base directory containing config.json and template folders
            verbose (bool): verbose output on/off
            dbfile (str): Alternative database file to use

        Returns:
            None
        """
        self.domain = kwargs.get("domain", None)
        self.ROOT_DIR = kwargs.get("root_dir")
        if self.domain:
            self.OUTPUT_DIR = join_abs(self.ROOT_DIR, "output", self.domain)
        self.dns = kwargs.get("dns", None)
        self.proxy = kwargs.get("proxy", None)
        self.verbose = kwargs.get("verbose", False)
        self.dbfile = kwargs.get("dbfile")
        self.aggregation = Aggregation(
            kwargs.get("dbfile"), self.domain, self.OUTPUT_DIR)

        # Disable warnings for insecure requests
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _print(self, msg):
        """Helper method for verbose output

        Returns:
            None
        """
        if self.verbose:
            print("\t[D] " + msg)
        LOG.debug(msg)

    def _run_dockers(self, dockers):
        """Build Docker containers provided dictionary of arguments for building

        Dockerize is a wrapper around the docker module. 
        This module allows Dr.ROBOT to specify
        required arguments for building its containers

        Args:
            dockers (Dict): dictionary with all docker objects to build

                Example:
                {
                "Aquatone" : {
                    "name": "Aquatone",
                    "docker_name": "aqua",
                    "default_conf": "docker_buildfiles/Dockerfile.Aquatone.tmp",
                    "active_conf": "docker_buildfiles/Dockerfile.Aquatone",
                    "description": "AQUATONE is a set of tools for performing
                                    reconnaissance on domain names",
                    "src": "https://github.com/michenriksen/aquatone",
                    "output": "/aqua",
                    "output_dir" : "aquatone"
                  }
                }

        Returns:
            A tuple containing the threads and the scanners being ran

        """
        scanners = []
        self._print(f"Creating scanners{dockers.keys()}")
        for scan, scan_dict in dockers.items():
            options = scan_dict
            options.update({"proxy": self.proxy or None})
            options.update({"dns": self.dns or None})
            options.update({"target": self.domain})
            options.update({"verbose": self.verbose})
            output_dir = self.OUTPUT_DIR
            if options.get("output_folder", None):
                output_dir = join_abs(
                    self.OUTPUT_DIR, options.get("output_folder"))

            self._print(f"Creating scanner for {scan} with options: " +
                        "{json.dumps(options, indent=4)}")

            scanners += [
                Docker(
                    active_config_path=join_abs(
                        self.ROOT_DIR,
                        scan_dict['active_conf']),
                    default_config_path=join_abs(
                        self.ROOT_DIR,
                        scan_dict['default_conf']),
                    docker_options=options,
                    output_dir=output_dir)]

        self._print("Threading builds")
        build_threads = [threading.Thread(target=scanner.build, daemon=True) for scanner in scanners]
        for build in build_threads:
            build.start()

        build_monitor_threads = [threading.Thread(target=scanner.monitor_build, daemon=True) for scanner in scanners]
        for thread in build_monitor_threads:
            thread.start()

        for build in build_monitor_threads:
            build.join()

        for scanner in scanners:
            if scanner.error or scanner.image is None:
                print(f"[!] Error building {scanner.name}. Check logs")

        self._print("Images built, running containers")
        for scanner in scanners:
            scanner.run()

        status_threads = [threading.Thread(target=scanner.update_status, daemon=True) for scanner in scanners]
        for stat in status_threads:
            stat.start()

        return (status_threads, scanners)

    def _run_ansible(self, ansible_mods, infile):
        """Create ansible objects from dictionary containing the configurations.

        Args:
            ansible_mods (Dict): Dictionary of ansible modules to build and run
            infile (Strings): Path to file for upload to ansible server

            Example:
                {
                    "Eyewitness": {
                        "name" : "Eyewitness",
                        "short_name" : "eye",
                        "default" : 2,
                        "ansible_arguments" : {
                            "config" : "$config/ansible_plays/eyewitness_play.yml",
                            "flags": "-e '$extra'",
                            "extra_flags":{
                                "1" : "variable_host=localhost",
                                "2" : "infile=$infile/aggregated_ips.txt",
                                "3" : "outfile=$outfile/Eyewitness.tar",
                                "4" : "outfolder=$outfile/Eyewitness"
                            }
                        },
                        "output" : "/tmp/output",
                        "enabled" : false
                    }
                }

        Returns:

        """
        for ansible, ansible_json in ansible_mods.items():
            try:
                attr = {}
                print("[*] Running {ansible} as ansible Module")
                attr['infile'] = infile
                attr['domain'] = self.domain
                attr['ansible_file_location'] = join_abs(
                    self.ROOT_DIR, "ansible_plays")
                attr['output_dir'] = self.OUTPUT_DIR
                attr['ansible_arguments'] = ansible_json.get(
                    "ansible_arguments")
                attr['verbose'] = self.verbose

                self._print(
                    f"Creating ansible {ansible} with attributes\n\t {attr}")
                ansible_mod = Ansible(**attr)

                ansible_mod.run()

            except OSError:
                print(f"[!] Something went wrong. Check error log for details")
                LOG.exception("Error in ansible method")
            except TypeError:
                print(f"[!] Something went wrong. Check error log for details")
                LOG.exception("Error in ansible method")

    def _run_webtools(self, webtools):
        """Create custom WebTool object from dictionary containing WebTools

        Args:
            webtools (Dict): WebTool modules to build and run
                Example:
                {
                    "Shodan" :
                    {
                      "short_name": "shodan",
                      "class_name": "Shodan",
                      "output_file" : "shodan.txt",
                      "api_key" : null,
                      "endpoint" : null,
                      "username" : null,
                      "password" : null
                    },
                }

        Returns:
            (List) Threads of WebTool objects that are running

        """
        threads = []
        for tool, tool_dict in webtools.items():
            try:
                output_file_loc = join_abs(
                    self.ROOT_DIR, "output", self.domain, tool_dict.get(
                        'output_file', tool))
                attr = {
                    "proxies": {'http': self.proxy, 'https': self.proxy},
                    "api_key": tool_dict.get('api_key', None),
                    "domain": self.domain,
                    "output_file": output_file_loc,
                    "username": tool_dict.get('username', None),
                    "password": tool_dict.get('password', None),
                    "endpoint": tool_dict.get('endpoint', None),
                    "verbose": self.verbose,
                }
                self._print(f"Building webtool {tool} with options \n\t{attr}")
                """
                module contains the modules loaded in from web_resources
                    relative to __main__
                tool_class contains the class object with the name
                    specified in the default/user config file.
                tool_class_obj contains the instantiated object
                    using the tool_class init method.
                """
                module = importlib.import_module('robot_api.api.web_resources', __name__)
                tool_class = getattr(module, tool_dict.get('class_name'))
                tool_class_obj = tool_class(**attr)
                threads += [
                    multiprocessing.Process(
                        target=tool_class_obj.do_query,
                        daemon=True)]

            except KeyError:
                print("[!] Error locating key for tool. " +
                      "Check error log for details")
                LOG.exception("Key Error in run_webtools method")
            except json.JSONDecodeError:
                print("[!] Failure authenticating to service. " +
                      "Check error log for details")
                LOG.exception("Failure authenticating to service.")
            except ValueError:
                print("[!] Value Error thrown. Check error log for details")
                LOG.exception("Value error on init")

        for thread in threads:
            thread.start()

        return threads

    def _run_upload(self, upload_dest, filepath):
        """
        Create Forum object for uploading of recon results

        Args:
            filepath (String): Filepath of files to upload
            boards (Dict): dictionary of given upload destination
                Example:
                        {
                        "Mattermost":
                            {
                              "class_name" : "Mattermost",
                              "short_name" : "matter",
                              "api_key": "",
                              "token_id" : "",
                              "port" : null,
                              "username" : "",
                              "url" : "",
                              "team_name" : "",
                              "channel_name" : "",
                              "description" : "Mattermost server"
                            }
                        }

        Returns:
            (List) Threads of upload operations running
        """
        threads = []
        for dest, dest_json in upload_dest.items():
            try:
                attr = {
                    "api_key": dest_json.get('api_key'),
                    "username": dest_json.get('username'),
                    "domain": self.domain,
                    "url": dest_json.get('url'),
                    "port": dest_json.get('port'),
                    "team_name": dest_json.get('team_name'),
                    "channel_name": dest_json.get('channel_name'),
                    "filepath": filepath,
                }

                self._print(f"Uploading to {dest} with options \n\t{attr}")

                module = importlib.import_module('..upload', __name__)
                board_class = getattr(module, dest_json.get('class_name'))
                obj = board_class(**attr)

                threads += [multiprocessing.Process(target=obj.upload, daemon=True)]
            except KeyError:
                print("[!] Key error: check your config. " +
                      "See error log for details")
                LOG.exception("Key error in upload method")
            except TypeError:
                print(f"[!] Error in initializing {dest}. Check error logs")
                LOG.exception("Type error in upload method")
            except ConnectionError:
                print("[!] ConnectionError, check URL for upload destination")
                LOG.exception("Connection error in upload method")
            except OSError:
                print("[!] OSError. See error log for details")
                LOG.exception("OSError in upload method")
            except json.JSONDecodeError:
                print("[!] Json error. See error log for details")
                LOG.exception("Json error in upload method")

        for thread in threads:
            thread.start()

        return threads


    def gather(self, **kwargs):
        """Starts domain reconnaisance of target domain using the supplied tools

        Args:
            webtools (Dict): webtool dict
            scanners_dockers (Dict): scanners that use docker as their base
            scanners_ansible (Dict): scanners that use ansible as their base.
            headers (Boolean): if headers should be gathered

        Returns:

        """
        _threads = []

        output_folders = []
        output_files = []

        webtools = kwargs.get('webtools', {})

        output_files += [v['output_file'] for _, v in webtools.items()]

        if webtools:
            _threads += self._run_webtools(webtools)

        scanners_dockers = kwargs.get('scanners_dockers', {})

        output_folders += [v.get('output_folder') for _,
                           v in scanners_dockers.items()
                           if v.get("output_folder")]
        output_files += [v.get('output_file') for _,
                         v in scanners_dockers.items()
                         if v.get('output_file')]

        scanners_ansible = kwargs.get('scanners_ansible', {})

        output_folders += [v.get('output_folder', None)
                           for _, v in scanners_ansible.items()
                           if v.get("output_folder")]
        output_files += [v.get('output_file', None)
                         for _, v in scanners_ansible.items()
                         if v.get("output_file")]

        for folder in output_folders:
            if not exists(join_abs(self.OUTPUT_DIR, folder)):
                makedirs(join_abs(self.OUTPUT_DIR, folder))

        if scanners_dockers:
            scanner_threads, scanners = self._run_dockers(scanners_dockers)
            _threads += scanner_threads

        if scanners_ansible:
            _threads += self._run_ansible(scanners_ansible, None)

        if _threads:
            try:
                [thread.join() for thread in _threads if thread]
            except KeyboardInterrupt:
                self._print("Keyboard Interrupt sending kill signal to docker")
                try:
                    _ = [scanner.kill() for scanner in scanners]
                except:
                    pass
                raise KeyboardInterrupt

        verify = kwargs.get('verify', None)

        if verify and webtools:
            for k in webtools:
                if verify.lower() in k.lower():
                    verify = webtools[k].get('output_folder', None)
                    if not verify:
                        verify = webtools[k].get('output_file', None)
                    break
        if verify:
            print(f"[*] Omit addresses gathered from web tool: {verify}")

        self.aggregation.aggregate(
            output_folders=output_folders,
            output_files=output_files)

        self.aggregation.dump_to_file()

        if kwargs.get("headers", False):
            self.aggregation.headers()
        print("[*] Gather complete")

    def inspection(self, **kwargs):
        """Starts inspection of target domain

        Args:
            post_enum_dockers (Dict): Tools to use docker as their base
            post_enum_ansible (Dict): Tools to use ansible as their base.
            infile (str): Path to file to use as alternative to infile

        Returns:

        """
        _threads = []

        infile = kwargs.get('file', None)

        if infile is None:
            print("[*] No file provided, dumping db for input")
            if getsize(self.dbfile) > 0:
                self.aggregation.dump_to_file()
            else:
                print("[!] \tDatabase file is empty. Have you ran gather?")
        elif not isfile(infile):
            print("[!] file provided does not exist, terminating")
            return

        print("[*] Inspection beginning")
        post_enum_dockers = kwargs.get("post_enum_dockers")

        if post_enum_dockers:
            post_threads, post_doc = self._run_dockers(post_enum_dockers)
            _threads += post_threads

        post_enum_ansible = kwargs.get("post_enum_ansible")

        if post_enum_ansible:
            print("[*] Custom modules will be run on main thread due " +
                  "to possibility of user input")
            self._run_ansible(post_enum_ansible, infile)

        print("[*] Inspection Done")
        if _threads:
            try:
                [thread.join() for thread in _threads if thread]
            except KeyboardInterrupt:
                self._print("Keyboard Interrupt sending kill signal to docker")
                _ = [doc.kill() for doc in post_doc]
                raise KeyboardInterrupt

    def upload(self, **kwargs):
        """Uploads files under filepath to upload destination

        Args:
            upload_dest (str): module name for upload destination.
            filepath (str): path to file(s) to upload

        Returns:

        """
        _threads = []
        print(f"[*] Upload beginning")
        upload_dest = kwargs.get('upload_dest')
        if upload_dest:
            _threads += self._run_upload(upload_dest, kwargs.get('filepath'))
        if _threads:
            [thread.join() for thread in _threads if thread]

        print(f"[*] Upload Done")

    def rebuild(self, **kwargs):
        """Rebuilds sqlite3 database by parsing output files found under HOME directory

        Args:
            files (List): list of files to include in this rebuild.

        Returns:

        """
        print("[*] Rebuilding DB")
        filenames = kwargs.get("files", None)
        output_files = []
        output_files += [f for f in filenames if isfile(f)]
        for root, dirs, files in walk(self.OUTPUT_DIR, topdown=True):
            dirs = [d for d in filenames if isdir(d)]
            for _file in files:
                output_files += [join_abs(root, _file)]
        self.aggregation.aggregate(output_files=output_files)
        if kwargs.get("headers", False):
            self.aggregation.headers()
        print("[*] Rebuilding complete")

    def generate_output(self, _format, output_file):
        """Dumps contents of sqlite3 file into an alternative text format

        Args:
            _format:        format of output file [xml, json]
            output_file:    (Optional) filename to dump contents too

        Returns:
            (None)
        """
        if not output_file:
            output_file = join_abs(self.OUTPUT_DIR, f"output.{_format}")
        file_index = self.aggregation.gen_output()
        if 'json' in _format:
            print("Generating JSON")
            try:
                """
                need to dump json file here, error checking as well
                """
                with open(output_file, 'w') as _file:
                    json.dump(file_index, _file, indent="\t")
            except json.JSONDecodeError as error:
                self._print(str(error))
        elif "xml" in _format:
            try:
                with open(output_file, 'w') as _file:
                    xmlout = dicttoxml.dicttoxml(file_index)
                    dom = parseString(xmlout)
                    _file.write(dom.toprettyxml())
            except TypeError:
                self._print("Error in generate_output check logs")
                LOG.exception("Error in generate output")
            except AttributeError:
                self._print("Error in generate_output check logs")
                LOG.exception("Error in generate output")

    def dumpdb(self):
        """Dumps the contents of the db file.
        """
        print(f"[*] Dumping sqllite3 file for {self.domain.replace('.', '_')}")
        self.aggregation.dump_to_file(dump_headers=True)
        print("[*] Headers will be found in output folder")
