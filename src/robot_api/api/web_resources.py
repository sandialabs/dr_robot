# -*- coding: utf8 -*-
"""WebTool module

Contains all web based modules for Dr.ROBOT. All modules
implement the Abstract Base Class WebTool to make running 
any user created modules easier.

"""
import requests
import netaddr
import socket
import logging
import shodan
import json
import re
from bs4 import BeautifulSoup
from abc import ABC, abstractmethod

LOG = logging.getLogger(__name__)


class WebTool(ABC):
    def __init__(self, **kwargs):
        """
        ABC class
        Args:
            **kwargs:
                api_key (str): api key for service
                user (str): ) user for service
                password (str): password for service
                proxies (str): proxies for service
                domain (str): domain for service
                output (str): output for service

        """
        self.proxies = kwargs.get('proxies', None)
        self.domain = kwargs.get('domain', None)
        self.output = kwargs.get('output_file', None)
        self.verbose = kwargs.get('verbose', False)
        self.results = []

    @abstractmethod
    def do_query(self):
        """Abstract method for query

        All modules implement this method. This method
        is called by Dr.ROBOT so that we can dynamically
        import and call modules without having to do
        anything special
        """
        pass

    def _print(self, msg):
        if self.verbose:
            print("[D] " + msg)
        LOG.debug(msg)

    def _write_results(self):
        """
        Write output of queries to file
        Returns:

        """
        with open(self.output, 'w') as f:
            for item in self.results:
                f.write(f"{item}\n")


class Arin(WebTool):
    """Arin web module
    
    Reaches out to ARIN api to grab IP ranges. Generates A TON
    of IPS. Best not used unless you have time and are loud

    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = kwargs.get('api_key', None)
        if not self.api_key:
            raise ValueError("API Key cannot be empty")

    def __getattr__(self, item):
        return self

    def _lookup_org(self):
        """
        Queries ARIN for the organization handle given the domain.

        Returns:
            (String) Handle for Organization

        """
        url = "https://whois.arin.net/ui/query.do"
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json'}
        ipv4 = socket.gethostbyname(self.domain)
        data = {'xslt': 'https://localhost:8080/whoisrws-servlet/arin.xsl',
                'flushCache': False,
                'queryinput': ipv4,
                'whoisSubmitButton': '+'}
        res = requests.post(
            url,
            headers=headers,
            data=data,
            verify=False,
            proxies=self.proxies,
            timeout=10)
        return res.json().get('ns4:pft').get('org').get('handle').get('$')

    def _generate_ips(self, all_cidrs):
        """
        Convert cidr ranges to ip addresses

        Returns:
            (List) ip address'
        """
        ips = []
        for cidr in all_cidrs:
            if not cidr.is_private() and cidr.prefixlen >= 16:
                ips += [ip for ip in cidr]
        return ips

    def do_query(self):
        """
        Queries ARIN CIDR ranges for the domain passed in on instantiation

        Returns:

        """
        print("[*] Beginning Arin Query")
        LOG.info('Starting ARIN Query for ' + self.domain)
        try:
            org_name = self._lookup_org()
            if not org_name:
                raise ValueError(
                    "[!] Org name was not found ARIN query cannot continue")
            if not self.api_key:
                raise ValueError("[!] Arin API Key not found")
            url = 'http://whois.arin.net/rest/org/' + \
                org_name + '/nets?apikey=' + self.api_key
            self._print(f"Making request to url {url}")

            headers = {'Accept': 'application/json'}
            LOG.info('Getting ' + org_name + ' ARIN Query from url: ' + url)
            result = requests.get(
                url,
                headers=headers,
                proxies=self.proxies,
                verify=False)
            self._print(
                f"Result content and status_code {result.content}, {result.status_code}")
            if result.status_code == 200:
                all_cidrs = []
                result_json = result.json()

                self._print(f"{json.dumps(result_json, indent=4)}")

                if isinstance(result_json['nets']['netRef'], list):
                    for x in result_json['nets']['netRef']:
                        result_cidr_list = netaddr.iprange_to_cidrs(
                            x['@startAddress'], x['@endAddress'])
                        all_cidrs.append(result_cidr_list[0])
                else:
                    result_cidr = netaddr.iprange_to_cidrs(
                        result_json['nets']['netRef']['@startAddress'],
                        result_json['nets']['netRef']['@endAddress'])
                    all_cidrs.append(result_cidr[0])

                LOG.info('CIDR of ' + org_name + ' is: %s', all_cidrs)
                self.results = self._generate_ips(all_cidrs)
                self._write_results()
            else:
                self._print('Failed to get data for: ' + self.org_name)

            print("[*] Finished ARIN Query")

        except requests.exceptions.HTTPError:
            LOG.exception("HTTPError in Arin Scan")
        except requests.exceptions.ConnectionError:
            LOG.exception("Connection Error in Arin Scan")
        except requests.exceptions.RequestException:
            LOG.exception("RequestException Err in Arin Scan")
        except ValueError:
            LOG.exception("ValueError in Arin Scan")


class Shodan(WebTool):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = kwargs.get('api_key', None)
        if not self.api_key:
            raise ValueError("API Key cannot be None")

    def do_query(self):
        """
        Queries Shodan for the domain passed in on instantiation

        Returns:

        """
        print("[*] Beginning Shodan Query")

        try:
            shod = shodan.Shodan(self.api_key)
            shod._session.proxies = self.proxies
            shod._session.verify = False
            res = shod.search(self.domain)
            for item in res['matches']:
                if item['hostnames']:
                    self.results += item['hostnames']
                self._print(
                    "Host: {} \n"
                    "\t Product: {} \n"
                    "\t PORT : {} \n"
                    "\t Country Code : {} \n"
                    "\t timestamp: {} \n" .format(
                        " ".join(item.get("hostnames", "")), 
                            item.get("product", ""), 
                            item.get("port", ""), 
                            item.get("location", ""), 
                            item.get("timestamp", "")))
                self._write_results()
            print("[*] Finished Shodan Query")
        except shodan.APIError:
            print("[!] Shodan Error. See log for more details")
            LOG.exception()


class Dumpster(WebTool):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ENDPOINT = "https://dnsdumpster.com"
        self.hostnames = []

    def _grab_csrf(self):
        """
        Gather CSRF token from response so that we can continue making requests.

        Returns:
            (String) CSRF token
        """
        response = requests.get(
            self.ENDPOINT,
            verify=False,
            proxies=self.proxies)
        reg = re.compile(r"csrftoken=([0-9A-Za-z]*)")
        if response.status_code == 200:
            match = reg.search(response.headers.get("Set-Cookie"))
            return match.group(1)
        return None

    def do_query(self):
        """
        Queries DNSDumpster.com for domain information.

        Returns:

        """
        print("[*] Beginning Dumpster Query")
        try:
            csrf = self._grab_csrf()
            cookies = {
                "csrftoken": csrf
            }
            headers = {
                "referer": self.ENDPOINT
            }
            data = {
                "csrfmiddlewaretoken": csrf,
                "targetip": self.domain
            }
            res = requests.post(
                self.ENDPOINT,
                data=data,
                headers=headers,
                cookies=cookies,
                proxies=self.proxies,
                verify=False,
            )
            self._print(f"Dumpster query at url {self.ENDPOINT}" +
                        f"\nwith data {data}\n" +
                        f"and headers{headers}\n" +
                        f"proxies {self.proxies}\n")
            soup = BeautifulSoup(res.content, 'html.parser')
            tds = soup.findAll('td', {'class': 'col-md-4'})
            for td in tds:
                if td.text:
                    self.results += [td.text.strip()]

            self._write_results()
        except requests.exceptions.ConnectionError:
            LOG.exception("[!] Connection Error check network configuration")
        except requests.exceptions.RequestException:
            LOG.exception(f"[!] Request failed SHODAN")
        except IndexError:
            LOG.exception(f"[!] No CSRF in response SHODAN")
        self._print("[*] End Dumpster Query")


class HackerTarget(WebTool):
    """Module for HackerTarget.com
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ENDPOINT = "https://api.hackertarget.com/hostsearch/?q={}".format(
            self.domain)

    def do_query(self):
        """
        Queries HackerTarget.com for domain information

        Returns:

        """
        print("[*] Beginning HackerTarget Query")
        try:
            res = requests.get(
                self.ENDPOINT,
                verify=False,
                proxies=self.proxies)
            self._print(f"Making request to url {self.ENDPOINT}" +
                        f"with proxies {self.proxies}")
            lines = res.content.splitlines()
            if len(lines) < 2:
                print("Domain not found on hackertarget")
                return
            for line in res.content.split():
                unused_hostname, ip = str(line, 'utf-8').split(',')
                self.results += [ip.strip()]
            self._write_results()
        except requests.exceptions.ConnectionError as er:
            LOG.exception("[!] Connection Error check network configuration")
        except requests.exceptions.RequestException as er:
            LOG.exception(f"[!] Request failed HackerTarget")
        except OSError as er:
            LOG.exception("OSError in HackerTarget")
        self._print("[*] End HackerTarget Query")


class VirusTotal(WebTool):
    """Module for VirusTotal.com
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ENDPOINT = "https://www.virustotal.com/ui/domains/{}/subdomains?limit=40".format(
            self.domain)

    def do_query(self):
        """
        Queries VirusTotal for domain inforamtion

        Returns:

        """
        headers = {
            "Content-Type": "application/json"
        }
        print("[*] Begin VirusTotal Query")
        try:
            res = requests.get(
                self.ENDPOINT,
                proxies=self.proxies,
                verify=False,
                headers=headers)
            self._print(f"Making request to url {self.ENDPOINT}" +
                        f"with proxies {self.proxies}" +
                        f"with headers {headers}")

            next_group = res.json().get('links', None).get('next', None)

            while next_group:
                for subdomain in res.json().get('data', None):
                    self.results += [subdomain.get('id').strip()]

                next_group = res.json().get('links', None).get('next', None)
                if next_group:
                    res = requests.get(
                        str(next_group),
                        proxies=self.proxies,
                        verify=False,
                        headers=headers)

            self._write_results()

        except requests.ConnectionError:
            LOG.exception("[!] Connection Error check network configuration")
        except requests.exceptions.RequestException:
            LOG.exception("[!] Request failed Virus")
        except OSError:
            LOG.exception("OSError in Virus")
        self._print("[*] End VirtusTotal Query")
