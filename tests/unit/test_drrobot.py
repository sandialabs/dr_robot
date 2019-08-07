import unittest
import pytest
from unittest.mock import patch, mock_open
from drrobot import parse_args
from src.robot import Robot
import shutil
import os

class TestCLI(object):

    def test_parse_args_run(self):
        scanners = {
                "Test": {
                    "name": "test",
                    "default": 1,
                    "docker_name": "test"
                    }
                }
        webtools = {
                "WebTool":
                {
                    "short_name": "web",
                    "class_name": "WebTool",
                    "api_key": 'tests',
                    "output_file": 'tests.txt'
                    }
                }
        testinput = ["prog", "gather", "-test", "-web", "testdomain"]
        with patch('drrobot.sys.argv', testinput):
            parser = parse_args(scanners=scanners, webtools=webtools)
            args = parser.parse_args()
            assert args.Test
            assert args.WebTool

    def test_parse_args_run_optionals(self):
        scanners = {
                "Test": {
                    "name": "test",
                    "default": 1,
                    "docker_name": "test"
                    }
                }
        webtools = {
                "WebTool":
                {
                    "short_name": "web",
                    "class_name": "WebTool",
                    "api_key": 'tests',
                    "output_file": 'tests.txt'
                    }
                }
        testinput = ["prog","--proxy", "http://test.testproxy", "--dns", "testdns", "gather", "testdomain" ]
        with patch('drrobot.sys.argv', testinput):
            parser = parse_args(scanners=scanners, webtools=webtools)
            args = parser.parse_args()
            assert args.proxy in "http://test.testproxy"
            assert args.dns in "testdns"

    def test_parse_args_post_tools(self):
        enumeration = {
                "Test": {
                    "short_name": "test",
                    }
                }
        testinput = ["prog", "inspect", "-test", "testdomain"]
        with patch('drrobot.sys.argv', testinput):
            parser = parse_args(enumeration=enumeration)
            args = parser.parse_args()
            assert args.Test

    def test_parse_args_upload(self):
        upload_dest= {
                "Test": {
                    "short_name": "test",
                    }
                }
        testinput = ["prog",  "upload", "-test", "testdomain"]
        with patch('drrobot.sys.argv', testinput):
            parser = parse_args(upload_dest=upload_dest)
            args = parser.parse_args()
            assert args.Test

    def test_parse_args_no_input(self):
        webtools = {
                "WebTool":
                {
                    "short_name": "web",
                    "class_name": "WebTool",
                    "api_key": 'tests',
                    "output_file": 'tests.txt'
                    }
                }
        try:
            parser = parse_args(webtools=webtools)
            args = parser.parse_args()
        except:
            assert True
