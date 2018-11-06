import requests
import netaddr
import socket
import logging
import shodan
import json
import re
from bs4 import BeautifulSoup
from abc import ABC, abstractmethod

class WebTool(ABC):
    def __init__(self,  **kwargs):
        """
        ABC class
        Args:
            **kwargs:
                api_key : (String) [Optional] api key for service
                user : (String) [Optional] user for service
                password : (String) [Optional] password for service
                proxies : (String) [Optional] proxies for service
                domain : (String) [Optional] domain for service
                output : (String) [Optional] output for service

        """
        self.proxies = kwargs.get('proxies', None)
        self.domain = kwargs.get('domain', None)
        self.output = kwargs.get('output_file', None)
        self.results = []

    @abstractmethod
    def do_query(self):
        pass

    def _write_results(self):
        """
        Write output of queries to file
        Returns:

        """
        with open(self.output, 'w') as f:
            for item in self.results:
                f.write(f"{item}\n")

class Arin(WebTool):
    def __init__(self,  **kwargs):
        super().__init__(**kwargs)
        self.api_key = kwargs.get('api_key', None)
        if not self.api_key:
            raise ValueError("API Key cannot be empty")

    def __getattr__(self, item):
        return self

    def _lookup_org(self):
        """
        Queries ARIN for the organization handle given the domain.
        Returns: (String) Handle for Organization

        """
        url = "https://whois.arin.net/ui/query.do"
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'}
        ip = socket.gethostbyname(self.domain)
        data = {'xslt': 'https://localhost:8080/whoisrws-servlet/arin.xsl',
                'flushCache': False,
                'queryinput': ip,
                'whoisSubmitButton': '+'}
        res = requests.post(url, headers=headers, data=data, verify=False, proxies=self.proxies, timeout=10)
        return res.json().get('ns4:pft').get('org').get('handle').get('$')

    def _generate_ips(self, all_cidrs):
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
        logging.info('Starting ARIN Query for ' + self.domain)
        try:
            org_name = self._lookup_org()
            if not org_name:
                raise ValueError("[!] Org name was not found ARIN query cannot continue")
            if not self.api_key:
                raise ValueError("[!] Arin API Key not found")
            url = 'http://whois.arin.net/rest/org/' + org_name + '/nets?apikey=' + self.api_key
            headers = {'Accept': 'application/json'}
            logging.info('Getting ' + org_name + ' ARIN Query from url: ' + url)
            result = requests.get(url, headers=headers, proxies=self.proxies, verify=False)
            if result.status_code == 200:
                all_cidrs = []
                result_json = result.json()
                logging.debug(f"\t{json.dumps(result_json, indent=4)}")

                if type(result_json['nets']['netRef']) is list:
                    for x in result_json['nets']['netRef']:
                        result_cidr_list = netaddr.iprange_to_cidrs(x['@startAddress'],
                                x['@endAddress'])
                        all_cidrs.append(result_cidr_list[0])
                else:
                    result_cidr = netaddr.iprange_to_cidrs(result_json['nets']['netRef']['@startAddress'],
                            result_json['nets']['netRef']['@endAddress'])
                    all_cidrs.append(result_cidr[0])

                logging.info('CIDR of ' + org_name+ ' is: %s', all_cidrs)
                self.results = self._generate_ips(all_cidrs)
                self._write_results()
            else:
                logging.error('Failed to get data for: ' + self.org_name)

            print("[*]\t Finished ARIN Query")

        except requests.exceptions.HTTPError as er:
            print(f"[!]\t\t Might be related to network configuration, check proxy/dns. {er}")
            logging.error(er)
        except requests.exceptions.ConnectionError as er:
            logging.error(er)
            print(f"[!]\t\t Might be related to network configuration, check proxy/dns. {er}")
        except requests.exceptions.RequestException as er:
            logging.error(er)
        except ValueError as er:
            print(f"{er}\t\t")
            logging.error(er)


class Shodan(WebTool):
    def __init__(self,  **kwargs):
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
                logging.info("Host: {} \n"\
                        "\t Product: {} \n"\
                        "\t PORT : {} \n"\
                        "\t Country Code : {} \n"\
                        "\t timestamp: {} \n"\
                        .format(" ".join(item.get("hostnames", "")), item.get("product", ""), item.get("port",""), item.get("location", ""), item.get("timestamp", "")))
                self._write_results()
            print("[*]\t Finished Shodan Query")
        except shodan.APIError as er:
            print("[!]\t\t Shodan Error. See log for more details")
            logging.error(er)


class Dumpster(WebTool):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ENDPOINT = "https://dnsdumpster.com"
        self.hostnames = []

    def _grab_csrf(self):
        response = requests.get(self.ENDPOINT, verify=False, proxies=self.proxies)
        reg = re.compile(r"csrftoken=([0-9A-Za-z]*)")
        if response.status_code == 200:
            match = reg.search(response.headers.get("Set-Cookie"))
            return match.group(1)
        return None

    def do_query(self):
        print("[*] Beginning Dumpster Query")
        try:
            csrf = self._grab_csrf()
            cookies = {
                    "csrftoken" : csrf
                    }
            headers = {
                    "referer":self.ENDPOINT
                    }
            data = {
                    "csrfmiddlewaretoken" : csrf,
                    "targetip": self.domain
                    }
            res = requests.post(self.ENDPOINT, data=data, headers=headers, cookies=cookies, proxies=self.proxies, verify=False,)
            soup = BeautifulSoup(res.content, 'html.parser')
            tds = soup.findAll('td', {'class':'col-md-4'})
            for td in tds:
                if td.text:
                    self.results += [td.text.strip()]

            self._write_results()
        except requests.exceptions.ConnectionError as er:
            logging.error(f"[!] Connection Error check network configuration {er}")
            print(f"[!] Connection Error check network configuration {er}")
        except requests.exceptions.RequestException as er:
            logging.error(f"[!] Request failed {er}")
            print(f"[!] Request failed {er}")
        except IndexError as er:
            logging.error(f"[!] No CSRF in response {er}")
            print(f"[!] No CSRF in response {er}")
        print("[*]\t End Dumpster Query")

class HackerTarget(WebTool):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ENDPOINT = "https://api.hackertarget.com/hostsearch/?q={}".format(self.domain)

    def do_query(self):
        print("[*] Beginning HackerTarget Query")
        try:
            res = requests.get(self.ENDPOINT, verify=False, proxies=self.proxies)
            for line in res.content.split():
                unused_hostname, ip = str(line, 'utf-8').split(',')
                self.results += [ip.strip()]
            self._write_results()
        except requests.exceptions.ConnectionError as er:
            logging.error(f"[!] Connection Error check network configuration {er}")
            print(f"[!] Connection Error check network configuration {er}")
        except requests.exceptions.RequestException as er:
            logging.error(f"[!] Request failed {er}")
            print(f"[!] Request failed {er}")
        except OSError as er:
            logging.error(er)
            print(f"[!] Writing to file failed {er}")
        print("[*]\t End HackerTarget Query")

class VirusTotal(WebTool):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ENDPOINT = "https://www.virustotal.com/ui/domains/{}/subdomains?limit=40".format(self.domain)

    def do_query(self):
        headers = {
                "Content-Type": "application/json"
                }
        print("[*] Begin VirusTotal Query")
        try:
            res = requests.get(self.ENDPOINT, proxies=self.proxies, verify=False, headers=headers)

            next_group = res.json().get('links', None).get('next', None)

            while next_group:
                for subdomain in res.json().get('data', None):
                    self.results += [subdomain.get('id').strip()]

                next_group = res.json().get('links', None).get('next', None)
                if next_group:
                    res = requests.get(str(next_group), proxies=self.proxies, verify=False, headers=headers)

            self._write_results()

        except requests.ConnectionError as er:
            logging.error(f"[!] Connection Error check network configuration {er}")
            print(f"[!] Connection Error check network configuration {er}")
        except requests.exceptions.RequestException as er:
            logging.error(f"[!] Request failed {er}")
            print(f"[!] Request failed {er}")
        except OSError as er:
            logging.error(er)
            print(f"[!] Writing to file failed {er}")
        print("[*]\t End VirtusTotal Query")
