# -*- coding: utf-8 -*-
"""Aggregation Module

This module handles all database interaction when aggregating data source.

Attributes:
    dbfile (str): location of database file to load
    domain (str): target domain
    output_dir (str): Where to dump files
    logger (Logger): Module based logger

"""
import json
import socket
import sqlite3
from os import path, getcwd, walk
import glob
import re
import logging
import multiprocessing
from functools import partial
from tqdm import tqdm
import requests

from robot_api.parse import join_abs


class Aggregation:
    """Aggregation module
    """
    def __init__(self, db_filename, domain, output_dir):
        """Initialize aggregation object

        Args:
            dbfile (str): location of database file to load
            domain (str): target domain
            output_dir (str): Where to dump files
            logger (Logger): Module based logger


        Returns:

        """
        self.dbfile = db_filename
        self.domain = domain
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)

    def dump_to_file(
            self,
            dump_ips=True,
            dump_hostnames=True,
            dump_headers=False):
        """Dump database to file

        Dumps contents of database to three seperate files:
            1. File with protocol (http/https)
            2. File with hostname only
            3. File with ip only

        Args:
            dump_ips (bool): dump ips
            dump_hostnames (bool): dump hostnames to file
            dump_headers (bool): dump headers to output firectory under headers


        Returns:
        """
        dbconn = sqlite3.connect(self.dbfile)
        try:
            dbcurs = dbconn.cursor()

            ips = dbcurs.execute(
                f"""SELECT DISTINCT ip
                FROM data
                WHERE domain='{self.domain.replace('.', '_')}'
                AND ip IS NOT NULL""").fetchall()
            hostnames = dbcurs.execute(
                f"""SELECT DISTINCT hostname
                    FROM data
                    WHERE domain='{self.domain.replace('.', '_')}'
                    AND hostname IS NOT NULL""").fetchall()

            """
                Header options require there to have been a scan otherwise
                there will be no output but that should be expected.
                Might change db to a dataframe later... possible
            """
            headers = dbcurs.execute(
                f"""SELECT DISTINCT ip, hostname, http_headers, https_headers
                        FROM data
                        WHERE domain='{self.domain.replace('.', '_')}'
                        AND (http_headers IS NOT NULL
                        AND https_headers IS NOT NULL)""").fetchall()

            if dump_ips:
                with open(join_abs(self.output_dir,
                                   'aggregated',
                                   'aggregated_ips.txt'),
                          'w') as _file:
                    _file.writelines("\n".join(list(ip[0] for ip in ips)))

            if dump_hostnames:
                with open(join_abs(self.output_dir,
                                   'aggregated',
                                   'aggregated_hostnames.txt'),
                          'w') as _file:
                    _file.writelines(
                        "\n".join(
                            list(
                                f"{host[0]}" for host in hostnames)))

                with open(join_abs(self.output_dir,
                                   'aggregated',
                                   'aggregated_protocol_hostnames.txt'),
                          'w') as _file:
                    _file.writelines(
                        "\n".join(
                            list(f"https://{host[0]}\nhttp://{host[0]}"
                                 for host in hostnames)))

            if dump_headers:
                keys = ["Ip", "Hostname", "Http", "Https"]
                for row in headers:
                    _rows = dict(zip(keys, row))
                    with open(join_abs(self.output_dir,
                                       "headers",
                                       f"{_rows['Hostname']}_headers.txt"),
                              'w') as _file:
                        _file.write(json.dumps(_rows, indent=2))
        except sqlite3.Error:
            print("Failed to write to files in aggregated directory, exiting")
            self.logger.exception("Error in dump to file")
            return
        except OSError:
            print("Failed to write to files in aggregated directory, exiting")
            self.logger.exception("Error in dump to file")
            return
        finally:
            dbconn.close()

    def _build_db(self, queue, cursor):
        """Takes in ip/hostname data and inserts them into the database

        Args:
            queue (multiprocessing.Queue): list of tupes (host, ip)
            cursor (sqlite3.cursor): database cursor object

        Returns:
        """
        cursor.execute('BEGIN TRANSACTION')
        domain = self.domain.replace(".", "_")
        while not queue.empty():
            host, ipv4 = queue.get()
            if host is not None and type(host) is not str:
                host = host[0]
            try:
                cursor.execute("""INSERT OR IGNORE INTO data
                        (ip, hostname, http_headers, https_headers, domain)
                        VALUES (?,?, NULL, NULL, ?);""", (ipv4, host, domain))
            except sqlite3.Error:
                print(f"Issue with the following data: {ipv4} {host} {domain}")
                self.logger.exception("Error in _build_db")

        cursor.execute('COMMIT')

    def aggregate(self, output_files=[], output_folders=[]):
        """Aggregates all output from scanners into the database

        Args:
            output_files: list of output files referenced in config.json
            output_folders: list of folders to for aggregation

        Returns:
        """
        try:

            dbconn = sqlite3.connect(self.dbfile)
            dbcurs = dbconn.cursor()
            # Enable foreign key support
            dbcurs.execute("PRAGMA foreign_keys=1")
            # Simple database that contains list of domains to run against
            dbcurs.execute("""
                            CREATE TABLE IF NOT EXISTS domains (
                                domain VARCHAR PRIMARY KEY,
                                UNIQUE(domain)
                            )
                            """)
            # Setup database to keep all data from all targets. This allows us
            # to use a single model for hosting with Django
            dbcurs.execute("""
                            CREATE TABLE IF NOT EXISTS data (
                                domainid INTEGER PRIMARY KEY,
                                ip VARCHAR,
                                hostname VARCHAR,
                                http_headers TEXT,
                                https_headers TEXT,
                                domain VARCHAR,
                                found TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                                FOREIGN KEY(domain) REFERENCES domains(domain),
                                UNIQUE(hostname)
                            )
                            """)
            # Quickly create entry in domains table.
            dbcurs.execute(f"INSERT OR IGNORE INTO domains(domain) VALUES ('{self.domain.replace('.', '_')}')")
            dbconn.commit()

            all_files = []
            for name in output_files:
                if path.isfile(join_abs(self.output_dir, name)):
                    all_files += [join_abs(self.output_dir, name)]
                elif path.isfile(name):
                    all_files += [name]
                else:
                    print(
                        f"[!] File {name} does not exist, verify scan results")

            for folder in output_folders:
                for root, _, files in walk(
                        join_abs(self.output_dir, folder)):
                    for _file in files:
                        if path.isfile(join_abs(root, _file)):
                            all_files += [join_abs(root, _file)]
            # multi_queue = multiprocessing.Queue()
            qu_manager = multiprocessing.Manager()
            pool = multiprocessing.Pool(5) 
            queue = qu_manager.Queue()
            reverse_partial = partial(self._reverse_ip_lookup, queue)
            pool.map(reverse_partial, all_files)
            pool.close()
            self._build_db(queue, dbcurs)
            dbconn.commit()
        except sqlite3.Error:
            self.logger.exception("Error in aggregation")
        finally:
            dbconn.close()

    def _reverse_ip_lookup(self, queue, filename):
        """Read in filesnames and use regex to extract all ips and hostnames.

        Args:
            filename: string to filename to parse

        Returns:
            A list of tuples containing the extracted host and ip
        """
        ip_reg = re.compile(
            r"(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)")
        # hostname_reg = re.compile(r"([A-Za-z0-9\-]*\.?)*\." + self.domain)
        hostname_reg = re.compile(
            r"([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*?\." 
            + self.domain
            + r"(\:?[0-9]{1,5})?")
        results = []
        try:
            with open(filename, "r", encoding='utf-8') as _file:
                for line in tqdm(_file.readlines(), desc=f"{filename} parsing..."):
                    _host = hostname_reg.search(line)
                    if _host is not None:
                        _host = _host.group(0)
                    _ip = ip_reg.search(line)
                    if _ip is not None:
                        _ip = _ip.group(0)
                    try:
                        if _host is not None and _ip is None:
                            _ip = socket.gethostbyname(_host)
                        if _ip is not None and _host is None:
                            _host = socket.gethostbyaddr(_ip)
                    except Exception:
                        pass
                    if _host or _ip:
                        queue.put((_host, _ip))
        except Exception:
            self.logger.exception(f"Error opening file {filename}")

        return results

    def _get_headers(self, queue, target):
        """Static method for request to scrape header information from ip

        Args:
            target: string to make request to

        Returns:
            ip/hostname and tuple containing headers
        """
        http = None
        https = None
        # May add option later to set UserAgent
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0"
        }
        try:
            http = requests.get(
                f"http://{target}",
                headers=headers,
                timeout=1,
                verify=False).headers
            http = str(http)
        except requests.ConnectionError:
            pass
        except OSError:
            pass
        try:
            https = requests.get(
                f"https://{target}",
                headers=headers,
                timeout=1,
                verify=False).headers
            https = str(https)
        except requests.ConnectionError:
            pass
        except OSError:
            pass
        queue.put([target, (http, https)])
        # return target, (http, https)

    def headers(self):
        """Attempts to grab header data for all ips/hostnames

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
        # Threading is done against the staticmethod.
        # Feel free to change the max_workers if your system allows.
        # May add option to specify threaded workers.
        pool = multiprocessing.Pool(40)

        qu_manager = multiprocessing.Manager()
        queue = qu_manager.Queue()
        get_headers_partial = partial(self._get_headers, queue)
        _ = list(tqdm(pool.imap_unordered(get_headers_partial, ips), total=len(ips), desc="Getting headers for ip..."))
        pool.close()
        pool.join()

        print("Updating database with ip headers")
        dbcurs.execute('BEGIN TRANSACTION')
        domain_rep = self.domain.replace(".", "_")
        while not queue.empty():
            ipv4, (http, https) = queue.get()
            dbcurs.execute(f"""UPDATE data
                                SET http_headers=?, https_headers=?
                                WHERE ip = ?
                                AND domain= ?
                                """,
                           (http, https, ipv4, domain_rep))
        dbcurs.execute("COMMIT")

        hostnames = dbcurs.execute(f"""SELECT hostname
                                FROM data
                                WHERE ip IS NOT NULL
                                AND domain='{self.domain.replace('.','_')}'"""
                                   ).fetchall()
        hostnames = [item[0] for item in hostnames]

        pool = multiprocessing.Pool(40)
        queue = qu_manager.Queue()
        get_headers_partial = partial(self._get_headers, queue)
        _ = list(tqdm(pool.map(get_headers_partial, hostnames), total=len(hostnames), desc="Getting headers for host..."))

        pool.close()
        pool.join()

        print("Updating database with hostname headers")
        dbcurs.execute('BEGIN TRANSACTION')
        domain_rep = self.domain.replace(".", "_")
        while not queue.empty():
            hostname, (http, https) = queue.get()
            dbcurs.execute(f"""UPDATE data
                                SET http_headers=?, https_headers=?
                                WHERE hostname = ?
                                AND domain= ?;""",
                           (http, https, hostname, domain_rep))
        dbcurs.execute("COMMIT")

        dbconn.close()

    def gen_output(self):
        """Generate dictionary containing all data from the database

        Returns:
            A dictionary containing all data from database

        """
        if not path.exists(self.dbfile):
            print("No database file found. Exiting")
            return None

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
                    most likely that if they have headers 
                    they have a screenshot
                    glob can run and take it's time.
                2. Grab all unique ips
                2a. Grab all unique hostnames

                3. Update json with all documents
        """
        for _, ipv4, hostname, http, https, _ in db_headers:
            ip_screenshots = glob.glob("**/*{}*".format(ipv4), recursive=True)
            hostname_screeshots = glob.glob(
                "**/*{}*".format(hostname), recursive=True)

            image_files = []
            for _file in ip_screenshots:
                image_files += [join_abs(getcwd(), _file)]
            for _file in hostname_screeshots:
                image_files += [join_abs(getcwd(), _file)]
            file_index[ipv4] = {
                "hostnames": [hostname],
                "http_header": http,
                "https_header": https,
                "images": image_files
            }

        for ipv4, hostname in db_ips:
            if ipv4 not in file_index:
                file_index[ipv4] = {
                    "hostnames": [hostname],
                    "http_header": "",
                    "https_header": "",
                    "images": []
                }
            elif hostname not in file_index[ipv4]['hostnames']:
                file_index[ipv4]['hostnames'] += [hostname]
        return file_index
