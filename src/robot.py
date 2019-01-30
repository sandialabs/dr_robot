import importlib
import json
import logging
import re
import socket
import threading
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
import sqlite3
from os.path import dirname, getsize, isfile, exists
from os import walk, makedirs

from docker.errors import APIError, BuildError, ContainerError, ImageNotFound
from tqdm import tqdm

from . import join_abs
from .ansible import Ansible
from .dockerize import Docker


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
        self.scanners = kwargs.get("scanners", {})
        self.webtools = kwargs.get("webtools", {})
        self.enumeration = kwargs.get("enumeration", {})
        self.boards = kwargs.get("boards", {})
        self.dns = kwargs.get("dns", None)
        self.proxy = kwargs.get("proxy", None)
        self.domain = kwargs.get("domain", None)
        self.verbose = kwargs.get("verbose", False)

        self.ROOT_DIR = kwargs.get("root_dir")
        self.OUTPUT_DIR = join_abs(self.ROOT_DIR, "output", self.domain)

        #Disable warnings for insecure requests
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _print(self, msg):
        if self.verbose:
            print(msg)
        else:
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
            output_dir = self.OUTPUT_DIR
            if options.get("output_folder", None):
                output_dir = join_abs(self.OUTPUT_DIR, options.get("output_folder"))

            self._print(f"Creating scanner for {scan} with options: \n\t{options}")

            scanners += [Docker(active_config_path=join_abs(dirname(__file__), '..', scan_dict['active_conf']),
                         default_config_path=join_abs(dirname(__file__), '..', scan_dict['default_conf']),
                         docker_options=options,
                         output_dir=output_dir)]

        for scanner in scanners:
            try:
                scanner.build()
                scanner.run()
            except BuildError as er:
                print(f"Build Error encountered {er}")
                if "net/http" in str(er):
                    print("This could be a proxy issue, see https://docs.docker.com/config/daemon/systemd/#httphttps-proxy for help")
                logger.exception(f"Build Error encountered")
                if not self.dns:
                    print(f"\t[!] No DNS set. This could be an issue")
                    logger.info("No DNS set. This could be an issue")
                if not self.proxy:
                    print(f"\t[!] No PROXY set. This could be an issue")
                    logger.info("No PROXY set. This could be an issue")

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
                print(f"[!] KeyError Output or Docker Name is not defined!!: {scanner.name}")
                logger.exception(f"[!] KeyError Output or Docker Name is not defined!!: {scanner.name}")

            except OSError:
                print(f"[!] Output directory could not be created, please verify permissions")
                logger.exception(f"[!] Output directory could not be created, please verify permissions")

        threads = list()
        self._print("Threading scanners")
        for scanner in scanners:
            threads += [threading.Thread(target=scanner.update_status, daemon=True)]

        for thread in threads:
            thread.start()

        return threads

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
                print(f"[*] Running {ansible} as ansible Module")
                attr['infile'] = infile
                attr['domain'] = self.domain
                attr['ansible_file_location'] = join_abs(self.ROOT_DIR, "ansible_plays")
                attr['output_dir'] = self.OUTPUT_DIR
                attr['ansible_arguments'] = ansible_json.get("ansible_arguments")

                self._print(f"Creating ansible {ansible} with attributes\n\t {attr}")
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
                output_file_loc = join_abs(self.ROOT_DIR, "output", self.domain, tool_dict.get('output_file', tool))
                attr = {
                        "proxies": {'http': self.proxy, 'https': self.proxy},
                        "api_key": tool_dict.get('api_key', None),
                        "domain": self.domain,
                        "output_file": output_file_loc,
                        "username": tool_dict.get('username', None),
                        "password": tool_dict.get('password', None),
                        "endpoint": tool_dict.get('endpoint', None),
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
                threads += [threading.Thread(target=tool_class_obj.do_query, daemon=True)]

            except KeyError:
                print(f"[!] Error locating key for tool. Check error log for details")
                logger.exception("Key Error in run_webtools method")
            except json.JSONDecodeError:
                print(f"[!] Failure authenticating to service. Check error log for details")
                logger.exception(f"Failure authenticating to service.")

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
                        "output_dir": self.OUTPUT_DIR
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

    def _dump_db_to_file(self, dump_ips=True, dump_hostnames=True, dump_headers=False):
        """
        Dump the contents of ips and hostnames columns from the database into two files that can be used for further enumeration

        Args:
            dump_ips (Bool): if ips should be dumped
            dump_hostnames (Bool): if hostnames should be dumped
            dump_headers (Bool): if headers should be dumped

        Return:

        """
        try:
            dbconn = sqlite3.connect(join_abs(self.ROOT_DIR, "dbs", f"{self.domain}.db"))
            dbcurs = dbconn.cursor()
            
            self._print(f"Creating sqlite file {self.domain}.db")

            ips = dbcurs.execute("SELECT ip FROM drrobot WHERE ip IS NOT NULL").fetchall()
            hostnames = dbcurs.execute("SELECT hostname FROM drrobot WHERE hostname IS NOT NULL").fetchall()

            self._print(f"Fetching all ips with command 'SELECT ip FROM drrobot WHERE ip IS NOT NULL'")
            self._print(f"Fetching all hostnames with command 'SELECT hostname FROM drrobot WHERE hostname IS NOT NULL'")
            """
                Header options require there to have been a scan otherwise there will be no output but that should be expected.
                Might change db to a dataframe later... possible
            """
            headers = dbcurs.execute("SELECT ip, hostname, http_headers, https_headers FROM drrobot WHERE http_headers IS NOT NULL AND https_headers IS NOT NULL").fetchall()
            if dump_ips:
                self._print("Dumping to aggregated_ips.txt")
                with open(join_abs(self.OUTPUT_DIR, 'aggregated', 'aggregated_ips.txt'), 'w') as f:
                    f.writelines("\n".join(list(ip[0] for ip in ips)))

            if dump_hostnames:
                self._print("Dumping to aggregated_hostnames.txt")
                with open(join_abs(self.OUTPUT_DIR, 'aggregated', 'aggregated_hostnames.txt'), 'w') as f:
                    f.writelines("\n".join(list(f"{host[0]}" for host in hostnames)))

                self._print("Dumping to aggregated_protocol_hostnames.txt")
                with open(join_abs(self.OUTPUT_DIR, 'aggregated', 'aggregated_protocol_hostnames.txt'), 'w') as f:
                    f.writelines("\n".join(list(f"https://{host[0]}\nhttp://{host[0]}" for host in hostnames)))

            if dump_headers:
                KEYS = ["Ip", "Hostname", "Http", "Https"]
                for row in headers:
                    r = dict(zip(KEYS, row))
                    with open(join_abs(self.OUTPUT_DIR, "headers", f"{r['Hostname']}_headers.txt"), 'w') as f:
                        f.write(json.dumps(r, indent=2))
        finally:
            dbconn.close()

    def _hostname_aggregation(self, verify=None, output_files=[], output_folders=[]):
        """
        Create an aggregated dictionary of all tool outputs that we can use to run further host enumeration on.
        This dictionary will be uploaded to a small sqlite3 database under the name "domain.db"

        Args:
            verify (String): Filename to be used as baseline for IP/Hostnames already known and scanned. Due to changes in the code base this is not enabled at the moment.
            output_files (List): filenames that we should be looking for when reading in files.
            output_folders (List): folder names that contain the output of specific tools

        Returns:

        """
        def build_db(ips, cursor):
            """
            Clojue that takes in a list of ips and creates a large transaction for inserts.

            Args:
                ips (Dict): ips, hostnames to insert
                cursor (sqlite3.connection.cursor): to execute in our sqlite instance

            Returns:

            """
            cursor.execute('BEGIN TRANSACTION')
            for host, ip in ips.items():
                cursor.execute("""INSERT OR IGNORE INTO drrobot (ip, hostname, http_headers, https_headers) VALUES (?,?, NULL, NULL);""", (ip, host))

            cursor.execute('COMMIT')

        def read_file(filename):
            """
            Generator for large file reading. Reads file in chunks for insert into database.

            Args:
                filename (str): filename to open and read from

            Returns:

            """
            with open(join_abs(self.OUTPUT_DIR, filename), 'r') as f:
                chunks = []
                chunk_size = 10000
                for line in f:
                    chunks += [line]
                    if len(chunks) >= chunk_size:
                        yield chunks
                        chunks = []
                yield chunks
        try:
            ip_regex = re.compile(
                    r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)")
            hostname_reg = re.compile(r"([A-Za-z0-9\-]*\.?)*\." + self.domain)

            dbconn = sqlite3.connect(join_abs(self.ROOT_DIR, "dbs", f"{self.domain}.db"))
            dbcurs = dbconn.cursor()
            dbcurs.execute('CREATE TABLE IF NOT EXISTS drrobot (ip VARCHAR, hostname VARCHAR, http_headers VARCHAR, https_headers VARCHAR)')

            all_files = []
            for name in output_files:
                if isfile(join_abs(self.OUTPUT_DIR, name)):
                    all_files += [join_abs(self.OUTPUT_DIR, name)]
                elif isfile(name):
                    all_files += [name]
                else:
                    print(f"[!] File {name} does not exist, verify scan results")

            for folder in output_folders:
                for root, dirs, files in walk(join_abs(self.OUTPUT_DIR, folder)):
                    for f in files:
                        if isfile(join_abs(root, f)):
                            all_files += [join_abs(root,f)]

            self._print(f"Parsing all files {all_files}")
            for filename in all_files:
                print(f"[*] Parsing file: {filename}")
                for ips in read_file(join_abs(filename)):
                    with ThreadPoolExecutor(max_workers=40) as pool:
                        tool_ips = dict(tqdm(pool.map(Robot._reverse_ip_lookup,
                                                      ips,
                                                      repeat(hostname_reg, len(ips)),
                                                      repeat(ip_regex, len(ips))),
                                        total=len(ips)))
                        build_db(tool_ips, dbcurs)
            dbconn.commit()
        finally:
            dbconn.close()

    @staticmethod
    def _reverse_ip_lookup(data, hostname_reg, ip_regex):
        """
        Static method to do a reverse lookup of ip to hostname and vice versa if need be.

        Args:
            data (str): ambiguous string, either ip or hostname.
            hostname_reg (re): compiled regex for hostname grouping
            ip_regex (re): compiled regex for ip grouping

        Returns:
            (Tuple) hostname, ip
        """
        hostname = hostname_reg.search(data.strip())
        ip = ip_regex.search(data.strip())
        hostname = hostname.group() if hostname else None
        ip = ip.group() if ip else None

        try:
            if not hostname and ip:
                hostname = socket.gethostbyaddr(ip)[0]
            if not ip and hostname:
                ip = socket.gethostbyname(hostname)

        except socket.herror as er:
            logger.debug(f"{ip}{hostname}: Host cannot be resolved, not adding")
        finally:
            return hostname, ip

    @staticmethod
    def grab_header(ip):
        """
        Grabs the headers of a given ip.
        Args:
            ip (str) ip address

        Returns:
            (Dict) ip : (http, https)  tuple of http, https headers
        """
        http = None
        https = None
        # May add option later to set UserAgent
        headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0"
                }
        try:
            http = requests.get(f"http://{ip}", headers=headers, timeout=0.5, verify=False).headers
            http = str(http)
        except:
            pass
        try:
            https = requests.get(f"https://{ip}", headers=headers, timeout=0.5, verify=False).headers
            https = str(https)
        except:
            pass
        return ip , (http, https)

    def _grab_headers(self):
        """
        Function to do mass header grabbing.
        Commits all headers to the sqlite3 database given the ip.

        Args:

        Returns:

        """

        dbconn = sqlite3.connect(join_abs(self.ROOT_DIR, "dbs", f"{self.domain}.db"))
        dbcurs = dbconn.cursor()

        ips = dbcurs.execute("SELECT ip FROM drrobot WHERE ip IS NOT NULL").fetchall()
        ips = [item[0] for item in ips]
        # Threading is done against the staticmethod. Feel free to change the max_workers if your system allows.
        # May add option to specify threaded workers.
        with ThreadPoolExecutor(max_workers=40) as pool:
            ip_headers = dict(tqdm(pool.map(Robot.grab_header,
                                            ips),
                                   total=len(ips)))
            dbcurs.execute('BEGIN TRANSACTION')
        for ip, (http, https) in ip_headers.items():
            dbcurs.execute("""UPDATE drrobot SET http_headers=?, https_headers=? WHERE ip = ? LIMIT 1;""", (http, https, ip))
            dbcurs.execute("COMMIT")
        dbconn.close()

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

        output_folders += [v.get('output_folder') for _, v in scanners_dockers.items() if v.get("output_folder")]
        output_files += [v.get('output_file') for _, v in scanners_dockers.items() if v.get('output_file')]

        scanners_ansible = kwargs.get('scanners_ansible', {})

        output_folders += [v.get('output_folder', None) for _, v in scanners_ansible.items() if v.get("output_folder")]
        output_files += [v.get('output_file', None) for _, v in scanners_ansible.items() if v.get("output_file")]

        for folder in output_folders:
            if not exists(join_abs(self.OUTPUT_DIR, folder)):
                makedirs(join_abs(self.OUTPUT_DIR, folder))

        if scanners_dockers:
            _threads += self._run_dockers(scanners_dockers)

        if scanners_ansible:
            _threads += self._run_ansible(scanners_ansible, None)

        if _threads:
            [thread.join() for thread in _threads if thread]

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

        self._hostname_aggregation(verify=verify, output_folders=output_folders, output_files=output_files)
        self._dump_db_to_file()
        if kwargs.get("headers", False):
            self._grab_headers()
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
            db_file_loc = join_abs(self.ROOT_DIR, "dbs", f"{self.domain}.db")
            if getsize(db_file_loc) > 0:
                self._dump_db_to_file()
            else:
                print("[!] \tDatabase file is empty. Have you ran gather?")
        elif not isfile(infile):
            print("[!] file provided does not exist, terminating")
            return

        print("[*] Inspection beginning")
        post_enum_dockers = kwargs.get("post_enum_dockers")

        if post_enum_dockers:
            _threads += self._run_dockers(post_enum_dockers)

        post_enum_ansible = kwargs.get("post_enum_ansible")

        if post_enum_ansible:
            print("[*] Custom modules will be run on main thread due to possibility of user input")
            self._run_ansible(post_enum_ansible, infile)

        print("[*] Inspection Done")
        if _threads:
            [thread.join() for thread in _threads if thread]

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
        output_files = kwargs.get("files", None)
        self._hostname_aggregation(False, output_files=output_files)
        self._grab_headers()
        print("[*] Rebuilding complete")

    def dumpdb(self, **kwargs):
        """
        Quick function to dump the contents of the db file.

        Args:
            **kwargs
        """
        print(f"[*] Dumping sqllite3 file for {self.domain}")
        self._dump_db_to_file(dump_headers=True)
        print(f"[*] Headers will be found under header folder in your domains output")
