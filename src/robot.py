import importlib
import json
import dicttoxml
import logging
import re
import socket
import threading
import requests
import mmap
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
import sqlite3
from os.path import dirname, getsize, isfile, exists, isdir
from os import walk, makedirs, getcwd

from docker.errors import APIError, BuildError, ContainerError, ImageNotFound
from tqdm import tqdm

from . import join_abs
from .ansible import Ansible
from .dockerize import Docker
from .aggregation import Aggregation


logger = logging.getLogger(__name__)


class Robot:
    def __init__(self, **kwargs):
        """
        Initialize Robot object.

        Args:
            scanners (Dict): dictionary of scanners and their options
            webtools (Dict): dictionary of webtools and their options
            enumeration (Dict): dictionary of enumerations and their options
            boards (Dict): dictionary of boards and their options
            dns (str): Added DNS for host configuration
            proxy (str): Proxy url of format "http://proxy.foo.bar:port
            domain (str): Target domain
            root_dir (str): Path to directory of drrobot.py

        Returns:

        """
        self.domain = kwargs.get("domain", None)
        self.ROOT_DIR = kwargs.get("root_dir")
        if self.domain:
            self.OUTPUT_DIR = join_abs(self.ROOT_DIR, "output", self.domain)
        self.scanners = kwargs.get("scanners", {})
        self.webtools = kwargs.get("webtools", {})
        self.enumeration = kwargs.get("enumeration", {})
        self.boards = kwargs.get("boards", {})
        self.dns = kwargs.get("dns", None)
        self.proxy = kwargs.get("proxy", None)
        self.verbose = kwargs.get("verbose", False)
        self.dbfile = kwargs.get("dbfile")
        self.aggregation = Aggregation(
            kwargs.get("dbfile"), self.domain, self.OUTPUT_DIR)

        # Disable warnings for insecure requests
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _print(self, msg):
        if self.verbose:
            print("\t[D] " + msg)
        logger.debug(msg)

    def _run_dockers(self, dockers):
        """
        Build Docker objects composed of dictionary of arguments.
        These Docker objects are a wrapper around the Docker module.

        Args:
            dockers (Dict): dictionary with all docker objects to build

                Example:
                {
                "Aquatone" : {
                    "name": "Aquatone",
                    "default" : 1,
                    "docker_name": "aqua",
                    "default_conf": "docker_buildfiles/Dockerfile.Aquatone.tmp",
                    "active_conf": "docker_buildfiles/Dockerfile.Aquatone",
                    "description": "AQUATONE is a set of tools for performing reconnaissance on domain names",
                    "src": "https://github.com/michenriksen/aquatone",
                    "output": "/aqua",
                    "output_file": "aquatone.txt" #OPTIONAL
                    "output_dir" : "aquatone"
                  }
                }

        Returns:
            (List) Threads of Docker objects

        Currently error handling is done outside of the docker module. This may be subject to change.
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

            self._print(
                f"Creating scanner for {scan} with options: {json.dumps(options, indent=4)}")

            scanners += [
                Docker(
                    active_config_path=join_abs(
                        dirname(__file__),
                        '..',
                        scan_dict['active_conf']),
                    default_config_path=join_abs(
                        dirname(__file__),
                        '..',
                        scan_dict['default_conf']),
                    docker_options=options,
                    output_dir=output_dir)]

        for scanner in scanners:
            try:
                scanner.build()
                print(
                    f"[*] Running the following docker containers: {[scanner.name for scanner in scanners]}")
                scanner.run()
            except BuildError as er:
                print(f"[!] Build Error encountered {er}")
                if "net/http" in str(er):
                    print(
                        "[!] This could be a proxy issue, see https://docs.docker.com/config/daemon/systemd/#httphttps-proxy for help")
                if not self.dns:
                    print(f"\t[!] No DNS set. This could be an issue")
                    self._print("No DNS set. This could be an issue")
                if not self.proxy:
                    print(f"\t[!] No PROXY set. This could be an issue")
                    self._print("No PROXY set. This could be an issue")

            except ContainerError:
                print(f"[!] Container Error: {scanner.name}")
                logger.exception(f"[!] Container Error: {scanner.name}")

            except ImageNotFound:
                print(f"[!] ImageNotFound: {scanner.name}")
                logger.exception(f"[!] ImageNotFound: {scanner.name}")

            except APIError:
                print(f"[!] APIError: {scanner.name}")
                logger.exception(f"[!] APIError: {scanner.name}")

            except KeyError:
                print(
                    f"[!] KeyError Output or Docker Name is not defined!!: {scanner.name}")
                logger.exception(
                    f"[!] KeyError Output or Docker Name is not defined!!: {scanner.name}")

            except OSError:
                print(
                    f"[!] Output directory could not be created, please verify permissions")
                logger.exception(
                    f"[!] Output directory could not be created, please verify permissions")

        threads = list()
        self._print("Threading scanners")
        for scanner in scanners:
            threads += [
                threading.Thread(
                    target=scanner.update_status,
                    daemon=True)]

        for thread in threads:
            thread.start()

        return (threads, scanners)

    def _run_ansible(self, ansible_mods, infile):
        """
        Create ansible object generated from dictionary containing the ansible objects to be built.

        Args:
            ansible_mods (Dict): Dictionary of ansible modules to build and run.
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
                        "description" : "Post enumeration tool for screen grabbing websites. All images will be downloaded to outfile: Eyewitness.tar and unpacked in Eyewitness",
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
                print("[*)\t Executing Ansible on main thread")
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
                logger.exception("Error in ansible method")
            except TypeError:
                print(f"[!] Something went wrong. Check error log for details")
                logger.exception("Error in ansible method")

    def _run_webtools(self, webtools):
        """
        Create custom WebTool object from dictionary containing WebTool objects to be build.

        Args:
            webtools (Dict): WebTool modules to build and run
                Example:
                {
                    "Shodan" :
                    {
                      "short_name": "shodan",
                      "class_name": "Shodan",
                      "description" : "Query SHODAN for publicly facing sites of given domain",
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
                module contains the modules loaded in from web_resources relative to __main__
                tool_class contains the class object with the name specified in the default/user config file.
                tool_class_obj contains the instantiated object using the tool_class init method.
                """
                module = importlib.import_module('..web_resources', __name__)
                tool_class = getattr(module, tool_dict.get('class_name'))
                tool_class_obj = tool_class(**attr)
                threads += [
                    threading.Thread(
                        target=tool_class_obj.do_query,
                        daemon=True)]

            except KeyError:
                print(
                    f"[!] Error locating key for tool. Check error log for details")
                logger.exception("Key Error in run_webtools method")
            except json.JSONDecodeError:
                print(
                    f"[!] Failure authenticating to service. Check error log for details")
                logger.exception(f"Failure authenticating to service.")
            except ValueError:
                print("[!] Value Error thrown. Check error log for details")
                logger.exception("Value error on init")

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

                threads += [threading.Thread(target=obj.upload, daemon=True)]
            except KeyError:
                print(f"[!] Key error: check your config. See error log for details")
                logger.exception("Key error in upload method")
            except TypeError as er:
                print(f"[!] Error in initialization of {dest}: {er}")
                logger.exception("Type error in upload method")
            except OSError as er:
                print(f"[!] {er}. See error log for details")
                logger.exception("OSError in upload method")
            except json.JSONDecodeError as er:
                print(f"[!] Json error {er}. See error log for details")
                logger.exception("Json error in upload method")
            except ConnectionError:
                print(f"[!] ConnectionError, check URL for upload destination")
                logger.exception("Connection error in upload method")

        for thread in threads:
            thread.start()

        return threads

    def gather(self, **kwargs):
        """
        This begins our gather process. Starts by looking at webtools and scanners for initial ip and hostname gathering.

        Args:
            webtools (Dict): webtool dict
            scanners_dockers (Dict): scanners that use docker as their base
            scanners_ansible (Dict): scanners that use ansible as their base.
            headers (Boolean): if headers should be gathered
            verify (str): file/resource to run scans against. Not implemented yet.

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
                           v in scanners_dockers.items() if v.get("output_folder")]
        output_files += [v.get('output_file') for _,
                         v in scanners_dockers.items() if v.get('output_file')]

        scanners_ansible = kwargs.get('scanners_ansible', {})

        output_folders += [v.get('output_folder', None)
                           for _, v in scanners_ansible.items() if v.get("output_folder")]
        output_files += [v.get('output_file', None)
                         for _, v in scanners_ansible.items() if v.get("output_file")]

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
                [scanner.kill() for scanner in scanners]
                raise KeyboardInterrupt

        verify = kwargs.get('verify', None)

        if verify and webtools:
            for k in webtools:
                if verify.lower() in k.lower():
                    verify = self.webtools[k].get('output_folder', None)
                    if not verify:
                        verify = self.webtools[k].get('output_file', None)
                    break
        if verify:
            print(f"[*] Omit addresses gathered from web tool: {verify}")

        self.aggregation.aggregate(
            verify=verify,
            output_folders=output_folders,
            output_files=output_files)
        self.aggregation.dump_to_file()
        if kwargs.get("headers", False):
            self.aggregation.headers()
        print("[*] Gather complete")

    def inspection(self, **kwargs):
        """
        Inspection function to being the post enumeration step. This will use enumeration tools to gather further information
        from the targets found in gather.

        Args:
            post_enum_dockers (Dict): enumeration tools that use docker as their base
            post_enum_ansible (Dict): enumeration tools that use ansible as their base.

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
            print(
                "[*] Custom modules will be run on main thread due to possibility of user input")
            self._run_ansible(post_enum_ansible, infile)

        print("[*] Inspection Done")
        if _threads:
            try:
                [thread.join() for thread in _threads if thread]
            except KeyboardInterrupt:
                self._print("Keyboard Interrupt sending kill signal to docker")
                [doc.kill() for doc in post_doc]
                raise KeyboardInterrupt

    def upload(self, **kwargs):
        """
        Upload function to access modules with respect to their given forum/chat/service api.

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
        """
        Function to allow rebuilding of the sqlite3 database.

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
            for f in files:
                output_files += [join_abs(root, f)]
        self.aggregation.aggregate(False, output_files=output_files)
        self.aggregation.headers()
        print("[*] Rebuilding complete")

    def generate_output(self, _format, output_file):
        """
        Function to translate contents of sqlite3 file into an alternative text format (Json, XML, etc.)

        Args:
            _format:        format of output file [xml, json]
            output_file:    (Optional) filename to dump contents too

        Returns:
            (None)
        """
        if not output_file:
            output_file = join_abs(self.OUTPUT_DIR, f"output.{_format}")
        file_index = self._gen_output()
        if 'json' in _format:
            print("Generating JSON")
            try:
                """
                need to dump json file here, error checking as well
                """
                with open(output_file, 'w') as f:
                    json.dump(file_index, f, indent="\t")
            except Exception as er:
                self._print(str(er))
        elif "xml":
            try:
                with open(output_file, 'w') as f:
                    xmlout = dicttoxml.dicttoxml(file_index)
                    dom = parseString(xmlout)
                    f.write(dom.toprettyxml())
            except Exception as er:
                self._print(str(er))

    def dumpdb(self, **kwargs):
        """
        Function to dump the contents of the db file.

        Args:
            **kwargs
        """
        print(f"[*] Dumping sqllite3 file for {self.domain.replace('.', '_')}")
        self.aggregation.dump_to_file(dump_headers=True)
        print(f"[*] Headers will be found under header folder in your domains output")

    def serve(self, **kwargs):
        """
        Function to serve the contents of a database using django

        Args:
            **kwargs
        """
        #print(f"[*] Check if already serving a container")
        options = kwargs.get("server", None)
        if options is None:
            self._print("Server configuration is missing in config.json")
        options.update({"proxy": self.proxy or None})
        options.update({"dns": self.dns or None})
        options.update({"verbose": self.verbose})
        options.update({"volumes": {
            join_abs(self.ROOT_DIR, "dbs"): {
                'bind': "/root/dr_robot/dbs",
                        'mode': 'rw'
            },
            join_abs(self.ROOT_DIR, "serve_api", "drrobot"): {
                'bind': "/root/dr_robot",
                'mode': 'rw'
            }
        }
        })
        output_dir = join_abs(self.ROOT_DIR, "dbs")

        self._print(
            f"Building django container with options: {json.dumps(options, indent=4)}")

        server = Docker(
            active_config_path=join_abs(
                dirname(__file__),
                '..',
                options['active_conf']),
            default_config_path=join_abs(
                dirname(__file__),
                '..',
                options['default_conf']),
            docker_options=options,
            output_dir=output_dir)

        try:
            server.build()
            server.run()
        except BuildError as er:
            print(f"Build Error encountered {er}")
            if "net/http" in str(er):
                print(
                    "This could be a proxy issue, see https://docs.docker.com/config/daemon/systemd/#httphttps-proxy for help")
            if not self.dns:
                print(f"\t[!] No DNS set. This could be an issue")
                self._print("No DNS set. This could be an issue")
            if not self.proxy:
                print(f"\t[!] No PROXY set. This could be an issue")
                self._print("No PROXY set. This could be an issue")

        except ContainerError:
            print(f"[!] Container Error: {options.name}")
            logger.exception(f"[!] Container Error: {options.name}")

        except ImageNotFound:
            print(f"[!] ImageNotFound: {options.name}")
            logger.exception(f"[!] ImageNotFound: {options.name}")

        except APIError:
            print(f"[!] APIError: {options.name}")
            logger.exception(f"[!] APIError: {options.name}")
