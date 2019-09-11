import importlib
import json
from xml.dom.minidom import parseString
import dicttoxml
import logging
import re
import socket
import threading
import requests
import glob
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
        self.dbfile = kwargs.get("dbfile")

        self.ROOT_DIR = kwargs.get("root_dir")
        if self.domain:
            self.OUTPUT_DIR = join_abs(self.ROOT_DIR, "output", self.domain)

        #Disable warnings for insecure requests
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
                output_dir = join_abs(self.OUTPUT_DIR, options.get("output_folder"))

            self._print(f"Creating scanner for {scan} with options: {json.dumps(options, indent=4)}")

            scanners += [Docker(active_config_path=join_abs(dirname(__file__), '..', scan_dict['active_conf']),
                         default_config_path=join_abs(dirname(__file__), '..', scan_dict['default_conf']),
                         docker_options=options,
                         output_dir=output_dir)]

        for scanner in scanners:
            try:
                scanner.build()
                print(f"[*] Running the following docker containers: {[scanner.name for scanner in scanners]}")
                scanner.run()
            except BuildError as er:
                print(f"[!] Build Error encountered {er}")
                if "net/http" in str(er):
                    print("[!] This could be a proxy issue, see https://docs.docker.com/config/daemon/systemd/#httphttps-proxy for help")
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
                attr['ansible_file_location'] = join_abs(self.ROOT_DIR, "ansible_plays")
                attr['output_dir'] = self.OUTPUT_DIR
                attr['ansible_arguments'] = ansible_json.get("ansible_arguments")
                attr['verbose'] = self.verbose

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
                threads += [threading.Thread(target=tool_class_obj.do_query, daemon=True)]

            except KeyError:
                print(f"[!] Error locating key for tool. Check error log for details")
                logger.exception("Key Error in run_webtools method")
            except json.JSONDecodeError:
                print(f"[!] Failure authenticating to service. Check error log for details")
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

    def _dump_db_to_file(self, dump_ips=True, dump_hostnames=True, dump_headers=False):
        """
        Dump the contents of ips and hostnames columns from the database into two files that can be used for further enumeration

        Args:
            dump_ips (Bool): if ips should be dumped
            dump_hostnames (Bool): if hostnames should be dumped
            dump_headers (Bool): if headers should be dumped

        Returns:

        """
        try:
            dbconn = sqlite3.connect(self.dbfile)
            dbcurs = dbconn.cursor()
            
            self._print(f"Creating sqlite file {self.dbfile}")

            ips = dbcurs.execute(f"""SELECT DISTINCT ip 
                                    FROM data 
                                    WHERE domain='{self.domain.replace('.', '_')}' 
                                    AND ip IS NOT NULL"""
                                    ).fetchall()
            hostnames = dbcurs.execute(f"""SELECT DISTINCT hostname 
                                            FROM data 
                                            WHERE domain='{self.domain.replace('.', '_')}'
                                            AND hostname IS NOT NULL"""
                                        ).fetchall()

            self._print(f"Fetching all ips with command 'SELECT DISTINCT ip FROM data WHERE domain={self.domain.replace('.', '_')} AND ip IS NOT NULL'")
            self._print(f"Fetching all hostnames with command 'SELECT DISTINCT hostname FROM data WHERE domain={self.domain.replace('.', '_')} AND hostname IS NOT NULL'")
            """
                Header options require there to have been a scan otherwise there will be no output but that should be expected.
                Might change db to a dataframe later... possible
            """
            headers = dbcurs.execute(f"""SELECT DISTINCT ip, hostname, http_headers, https_headers 
                                        FROM data 
                                        WHERE domain='{self.domain.replace('.', '_')}' 
                                        AND (http_headers IS NOT NULL 
                                        AND https_headers IS NOT NULL)"""
                                        ).fetchall()

            self._print(f"SELECT DISTINCT ip, hostname, http_headers, https_headers FROM data WHERE domain={self.domain.replace('.', '_')} AND (http_headers IS NOT NULL AND https_headers IS NOT NULL)")

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
        This dictionary will be uploaded to a small sqlite3 database under the name "drrobot.db"

        Args:
            verify (String): Filename to be used as baseline for IP/Hostnames already known and scanned. Due to changes in the code base this is not enabled at the moment.
            output_files (List): filenames that we should be looking for when reading in files.
            output_folders (List): folder names that contain the output of specific tools

        Returns:

        """
        def build_db(ips, cursor):
            """
            Closure that takes in a list of ips and creates a large transaction for inserts.

            Args:
                ips (Dict): ips, hostnames to insert
                cursor (sqlite3.connection.cursor): to execute in our sqlite instance

            Returns:

            """
            cursor.execute('BEGIN TRANSACTION')
            domain = self.domain.replace(".","_")
            try:
                for host, ip in ips:
                    cursor.execute("""INSERT INTO data 
                                        (ip, hostname, http_headers, https_headers, domain) 
                                        VALUES (?,?, NULL, NULL, ?);""", 
                                        (ip, host, domain))
            except:
                print(f"Issue with the following data: {ip} {host} {domain}")

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

            dbconn = sqlite3.connect(self.dbfile)
            dbcurs = dbconn.cursor()
            dbcurs.execute("PRAGMA foreign_keys=1") # Enable foreign key support
            # Simple database that contains list of domains to run against
            dbcurs.execute("""
                            CREATE TABLE IF NOT EXISTS domains (
                                domain VARCHAR PRIMARY KEY,
                                UNIQUE(domain)
                            )
                            """)
            # Setup database to keep all data from all targets. This allows us to use a single model for hosting with Django
            dbcurs.execute("""
                            CREATE TABLE IF NOT EXISTS data (
                                domainid INTEGER PRIMARY KEY,
                                ip VARCHAR,
                                hostname VARCHAR,
                                http_headers TEXT,
                                https_headers TEXT,
                                domain VARCHAR,
                                FOREIGN KEY(domain) REFERENCES domains(domain),
                                UNIQUE(ip, hostname)
                            )
                            """)
            # Quickly create entry in domains table. 
            dbcurs.execute(f"INSERT OR IGNORE INTO domains(domain) VALUES ('{self.domain.replace('.', '_')}')")
            dbconn.commit()

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
            all_ips =[]
            for filename in all_files:
                print(f"[*] Parsing file: {filename}")
                all_ips += self._reverse_ip_lookup(filename)
                # for data in read_file(join_abs(filename)):
                #     all_ips += self._reverse_ip_lookup(data)
            build_db(all_ips, dbcurs)
            dbconn.commit()
        finally:
            dbconn.close()

    def _reverse_ip_lookup(self, filename):
        """

        Args:
            data (str): ambiguous string, either ip or hostname.
            hostname_reg (re): compiled regex for hostname grouping
            ip_regex (re): compiled regex for ip grouping

        Returns:
            (List) of Tuples (hostname, ip)
        """
        print("Extracting ips and hostnames from text")
        ip_reg = re.compile(r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)")
        #hostname_reg = re.compile(r"([A-Za-z0-9\-]*\.?)*\." + self.domain)
        hostname_reg = re.compile(r"([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*?\."+self.domain)
        results = []
        with open(filename, "r") as f:
            for line in tqdm(f.readlines()):
                host = hostname_reg.match(line) 
                if host:
                    host = host.group()
                ip = ip_reg.match(line)
                if ip:
                    ip = ip.group()
                try:
                    if host is not None and ip is None:
                        ip = socket.gethostbyname(host)
                    if ip is not None and host is None:
                        host = socket.gethostbyaddr(ip)
                except:
                    pass
                if host or ip:
                    results += [(host, ip)]

            # print("Extracting ips")
            # for ip in tqdm(ips):
            #     hostname = None
            #     try:
            #         hostname = socket.gethostbyaddr(ip)
            #         hostname = hostname[0]
            #     except:
            #         results += [(hostname, ip)]

        return results

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
            http = requests.get(f"http://{ip}", headers=headers, timeout=1, verify=False).headers
            http = str(http)
        except Exception as er:
            logger.exception(f"Could not retrieve http header for ip: {ip}")
            pass
        try:
            https = requests.get(f"https://{ip}", headers=headers, timeout=1, verify=False).headers
            https = str(https)
        except:
            logger.exception(f"Could not retrieve https header for ip: {ip}")
            pass
        return ip , (http, https)

    def _grab_headers(self):
        """
        Function to do mass header grabbing.
        Commits all headers to the sqlite3 database given the ip.

        Args:

        Returns:

        """

        dbconn = sqlite3.connect(self.dbfile)
        dbcurs = dbconn.cursor()

        print("[*] Grabbing headers from ips and hostnames")
        ips = dbcurs.execute(f"""SELECT ip 
                                    FROM data 
                                    WHERE ip IS NOT NULL 
                                    AND domain='{self.domain.replace('.','_')}'"""
                                ).fetchall()
        ips = [item[0] for item in ips]
        # Threading is done against the staticmethod. Feel free to change the max_workers if your system allows.
        # May add option to specify threaded workers.
        with ThreadPoolExecutor(max_workers=40) as pool:
            ip_headers = dict(tqdm(pool.map(Robot.grab_header,
                                            ips),
                                   total=len(ips)))
        dbcurs.execute('BEGIN TRANSACTION')
        domain_rep = self.domain.replace(".", "_")
        for ip, (http, https) in ip_headers.items():
            dbcurs.execute(f"""UPDATE data 
                                SET http_headers=?, https_headers=? 
                                WHERE ip = ? 
                                AND domain= ? 
                                LIMIT 1;""", 
                                (http, https, ip, domain_rep))
        dbcurs.execute("COMMIT")

        hostnames = dbcurs.execute(f"""SELECT ip 
                                    FROM data 
                                    WHERE ip IS NOT NULL 
                                    AND domain='{self.domain.replace('.','_')}'"""
                                ).fetchall()
        hostnames = [item[0] for item in hostnames]
        with ThreadPoolExecutor(max_workers=40) as pool:
            hostname_headers = dict(tqdm(pool.map(Robot.grab_header,
                                            hostnames),
                                   total=len(hostnames)))
        dbcurs.execute('BEGIN TRANSACTION')
        domain_rep = self.domain.replace(".", "_")
        for hostname, (http, https) in hostname_headers.items():
            dbcurs.execute(f"""UPDATE data 
                                SET http_headers=?, https_headers=? 
                                WHERE hostname = ? 
                                AND domain= ? 
                                LIMIT 1;""", 
                                (http, https, hostname, domain_rep))
        dbcurs.execute("COMMIT")

        dbconn.close()

    def _gen_output(self):
        """
        Generate output file from target information in sqlite3 database

        Args:
            (None)

        Returns:
            (Dict) file_index: Dictionary of dictionaries containing ip, hostname information from various phases of Dr. ROBOT 
        """
        if not exists(self.dbfile):
            self._print("No database file found. Exiting")
            return

        dbconn = sqlite3.connect(self.dbfile)
        dbcurs = dbconn.cursor()

        db_headers = dbcurs.execute(f"""SELECT * 
                                        FROM data 
                                        WHERE domain='{self.domain.replace('.','_')}' 
                                        AND (http_headers IS NOT NULL OR https_headers IS NOT NULL)"""
                                        ).fetchall()
        db_ips = dbcurs.execute(f"""SELECT DISTINCT ip, hostname 
                                    FROM data 
                                    WHERE domain='{self.domain.replace('.', '_')}'"""
                                    ).fetchall()

        """
        (IP, HOSTNAME, HTTP, HTTPS)
        """
        file_index = {}
        """
            Need to be smarter about this:

            Multiple different sql queries
                1. Grabs all those with headers:
                    most likely that if they have headers they have a screenshot
                    glob can run and take it's time.
                2. Grab all unique ips
                2a. Grab all unique hostnames

                3. Update json with all documents
        """
        self._print(f"How many ip/hostnames with header information found {len(db_headers)}")
        for _, ip, hostname, http, https, domainname in db_headers:
            ip_screenshots = glob.glob("**/*{}*".format(ip), recursive=True)
            hostname_screeshots = glob.glob("**/*{}*".format(hostname), recursive=True)
        
            image_files = []
            for _file in ip_screenshots:
                image_files += [join_abs(getcwd(), _file)]
            for _file in hostname_screeshots:
                image_files += [join_abs(getcwd(), _file)]
            file_index[ip] = {
                        "hostnames" : [hostname],
                        "http_header" : http,
                        "https_header" : https,
                        "images" : image_files
                    }

        self._print(f"How many ip/hostnames {len(db_ips)}")

        for ip, hostname in db_ips:
            if ip not in file_index:
                file_index[ip] = {
                            "hostnames" : [hostname],
                            "http_header" : "",
                            "https_header" : "",
                            "images" : [] 
                        }
            elif hostname not in file_index[ip]['hostnames']:
                    file_index[ip]['hostnames'] += [hostname]
        return file_index
        


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
            db_file_loc = self.dbfile
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
            post_threads, post_doc = self._run_dockers(post_enum_dockers)
            _threads += post_threads

        post_enum_ansible = kwargs.get("post_enum_ansible")

        if post_enum_ansible:
            print("[*] Custom modules will be run on main thread due to possibility of user input")
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
        self._hostname_aggregation(False, output_files=output_files)
        self._grab_headers()
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
        self._dump_db_to_file(dump_headers=True)
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
                join_abs(self.ROOT_DIR, "dbs") : {
                        'bind': "/root/dr_robot/dbs",
                        'mode': 'rw'
                    },
                join_abs(self.ROOT_DIR ,"serve_api", "drrobot") : {
                        'bind': "/root/dr_robot",
                        'mode': 'rw'
                    }
                }
            })
        output_dir = join_abs(self.ROOT_DIR, "dbs")

        self._print(f"Building django container with options: {json.dumps(options, indent=4)}")

        server = Docker(active_config_path=join_abs(dirname(__file__), '..', options['active_conf']),
                     default_config_path=join_abs(dirname(__file__), '..', options['default_conf']),
                     docker_options=options,
                     output_dir=output_dir)
        
        try:
            server.build()
            server.run()
        except BuildError as er:
            print(f"Build Error encountered {er}")
            if "net/http" in str(er):
                print("This could be a proxy issue, see https://docs.docker.com/config/daemon/systemd/#httphttps-proxy for help")
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
