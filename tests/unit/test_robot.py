import unittest
import pytest
from unittest.mock import patch, mock_open

from src.robot import Robot
import shutil
import os

def mock_gethostbyaddr(ip):
    print("Called with {}".format(ip))
    return [ip]

class TestRobot(object):

    @pytest.fixture(autouse=True)
    def setup_class(self, tmpdir):
        # self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.ROOT_DIR = tmpdir.strpath
        self.USER_CONFIG = self.ROOT_DIR + '/dockers/user_config.json'
        os.makedirs(self.ROOT_DIR + "/dockers")
        with open(self.USER_CONFIG, 'w') as f:
            f.write("{}")
        self.robot = Robot(root_dir=self.ROOT_DIR, user_config=self.USER_CONFIG, domain="tests.com")
        self.robot.domain = "tests.com"

    @patch('src.robot.Robot._grab_headers', return_value=True)
    @patch('src.robot.Robot._hostname_aggregation', return_value = ["1.1.1.1"])
    @patch('src.robot.Robot._run_webtools', return_value = [False])
    def test_gather_webtools(self, mock_run, mock_aggregation, mock_headers):
        attr = {
                "webtools" : {
                    "Shodan" :
                    {
                        "short_name": "shodan",
                        "class_name": "Shodan",
                        "description" : "Query SHODAN for publicly facing sites of given domain",
                        "output_file" : "shodan.txt"
                        }
                    }
                }
        self.robot.gather(**attr)
        mock_run.assert_called_with(attr['webtools'])

        mock_aggregation.assert_called_with(None, ["shodan.txt"])

    @patch('src.robot.Robot._grab_headers', return_value=True)
    @patch('src.robot.Robot._hostname_aggregation', return_value = ["1.1.1.1"])
    @patch('src.robot.Robot._run_dockers', return_value = [False])
    def test_gather_scanners(self, mock_run, mock_aggregation, mock_headers):
        attr = {
                "scanners_dockers": {
                    "Aquatone": {
                        "name": "Aquatone",
                        "default": 1,
                        "docker_name": "aqua",
                        "default_conf": "dockers/Dockerfile.Aquatone.tmp",
                        "active_conf": "dockers/Dockerfile.Aquatone",
                        "description": "AQUATONE is a set of tools for performing reconnaissance on domain names",
                        "src": "https://github.com/michenriksen/aquatone",
                        "output": "/aquatone",
                        "output_file" : "aquatone.txt"
                        }
                    }
                }

        self.robot.gather(**attr)
        mock_run.assert_called_with(attr['scanners_dockers'])

        mock_aggregation.assert_called_with(None, ["aquatone.txt"])

    @patch('src.robot.sqlite3')
    @patch('src.robot.logging')
    @patch('src.robot.getsize', return_value=1)
    @patch('socket.gethostbyaddr', side_effect=mock_gethostbyaddr)
    def test_aggregate(self, mock_gethostbyaddr, mock_size, mock_loggin, mock_sql):
        """
        Verify that the text parser does not write ipv4 addresses that exist within the SECCENT list
        :return:
        """
        self.robot.domain = "tests.com"
        self.robot.OUTPUT_DIR += "/tests.com"

        logging = mock_loggin()
        logging.info.return_value = True
        logging.error.return_value = True
        sql = mock_sql()
        sql.connect().cursor().execute.return_value=True
        sql.connect().cursor.return_value=True
        sql.connect().commit.return_value=True
        sql.connect().exit.return_value=True
        sql.connect.return_value=True
        if not os.path.exists(self.ROOT_DIR + "/output/tests.com"):
            os.makedirs(self.ROOT_DIR + "/output/tests.com")
        ips = "\n".join(["43.88.223.14", "223.134.196.150", "201.141.10.80", "105.129.173.222", "23.18.31.124"])

        with patch("src.robot.open", mock_open(read_data=ips), create=True) as m:
            m.return_value.__iter__ = lambda self: self
            m.return_value.__next__ = lambda self: next(iter(self.readline, ''))
            with patch("src.robot.walk") as mockwalk:
                mockwalk.return_value = [('/foo', [],  ['seccent.txt'])]
                output = self.robot._hostname_aggregation(output_files=["seccent.txt"])

    @patch('src.robot.Ansible')
    def test_run_ansible(self, mock_ansible):
        ansibles = {
                "Test": {
                    "ansible_arguments": {"tests": "test"},
                    }
                }
        infile = "tests"
        self.robot._run_ansible(ansibles, infile)

        mock_ansible.assert_called_once_with(ansible_arguments={"tests": "test"},
                domain=self.robot.domain,
                infile='tests',
                output_dir=unittest.mock.ANY,
                ansible_file=unittest.mock.ANY)
        mock_instance = mock_ansible.return_value
        mock_instance.run.assert_called_once_with()

    @patch('src.web_resources.Arin')
    def test_run_webtools_arin(self, mock_arin):
        webtools = {
                "Arin":
                {
                    "class_name": "Arin",
                    "api_key": 'tests',
                    "output_file": 'arin.txt'
                    }
                }

        self.robot._run_webtools(webtools)

        mock_arin.assert_called_once_with(**{"api_key": 'tests',
            "domain": self.robot.domain,
            "output_file": unittest.mock.ANY,
            "username" : None,
            "password" : None,
            "endpoint" : None,
            "proxies": {
                'http': None,
                'https': None
                }})

    @patch('src.web_resources.Shodan')
    def test_run_webtools_shodan(self, mock_shodan):
        webtools = {
                "Shodan":
                {
                    "class_name": "Shodan",
                    "api_key": 'tests',
                    "output_file": 'arin.txt'
                    }
                }

        self.robot._run_webtools(webtools)

        mock_shodan.assert_called_once_with(**{"api_key": 'tests',
            "domain": self.robot.domain,
            "output_file": unittest.mock.ANY,
            "username" : None,
            "password" : None,
            "endpoint" : None,
            "proxies": {
                'http': None,
                'https': None
                }})

    @patch('src.web_resources.WebTool')
    def test_run_webtools_webtools(self, mock_web):
        webtools = {
                "WebTool":
                {
                    "class_name": "WebTool",
                    "api_key": 'tests',
                    "output_file": 'tests.txt'
                    }
                }

        self.robot._run_webtools(webtools)

        mock_web.assert_called_once_with(**{"api_key": 'tests',
            "domain": self.robot.domain,
            "output_file": unittest.mock.ANY,
            "username" : None,
            "password" : None,
            "endpoint" : None,
            "proxies": {
                'http': None,
                'https': None
                }})

    @patch('src.robot.Docker')
    def test_run_dockers(self, mock_dock):
        docker = {
                "Test": {
                    "name": "Test",
                    "default": 1,
                    "docker_name": "tests",
                    "default_conf": "dockers/Dockerfile.tests.tmp",
                    "active_conf": "dockers/Dockerfile.tests",
                    "description": "tests",
                    "src": "https://github.com",
                    "output": "/tests",
                    "output_file": "hosts.txt",
                    "proxy" : None,
                    "target" : self.robot.domain,
                    "dns" : None
                    }
                }

        self.robot._run_dockers(docker)
        OUTPUT_DIR = os.path.join(self.ROOT_DIR, "output")
        mock_dock.assert_called_once_with(active_config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../', docker['Test']['active_conf'])),
                default_config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../', docker['Test']['default_conf'])),
                docker_options=docker['Test'],
                output_dir=unittest.mock.ANY)
