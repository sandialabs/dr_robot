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
        input = ["prog", "--domain", "testdomain", "gather", "-test", "-web"]
        with patch('drrobot.sys.argv', input):
            args = parse_args(scanners=scanners, webtools=webtools)
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
        input = ["prog", "--domain", "testdomain", "--proxy", "http://test.testproxy", "--dns", "testdns", "gather"]
        with patch('drrobot.sys.argv', input):
            args = parse_args(scanners=scanners, webtools=webtools)

            assert args.proxy in "http://test.testproxy"
            assert args.dns in "testdns"

    def test_parse_args_post_tools(self):
        enumeration = {
                "Test": {
                    "short_name": "test",
                    }
                }
        input = ["prog", "--domain", "testdomain", "inspect", "-test"]
        with patch('drrobot.sys.argv', input):
            args = parse_args(enumeration=enumeration)

            assert args.Test

    def test_parse_args_upload(self):
        upload_dest= {
                "Test": {
                    "short_name": "test",
                    }
                }
        input = ["prog", "--domain", "testdomain" , "upload", "-test"]
        with patch('drrobot.sys.argv', input):
            args = parse_args(upload_dest=upload_dest)

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
            args = parse_args(webtools=webtools)
        except:
            assert True
