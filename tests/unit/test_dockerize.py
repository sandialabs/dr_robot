from src.dockerize import Docker
from docker.errors import APIError
import unittest
import pytest
from unittest.mock import patch, mock_open

class TestDocker(object):

    @pytest.fixture(autouse=True)
    def setUp(self):
        self.test_options = {
                "tests" : "tests",
                "name" : "tests",
                "docker_name" : "tests",
                "output" : "tests"
                }
        self.test_default_config = "testpath"
        self.test_active_config = "testpath"
        self.test_output = "testoutputpath"

        self.test_dock = Docker(docker_options=self.test_options,
                active_config_path=self.test_active_config,
                default_config_path=self.test_default_config,
                output_dir=self.test_output)

    def test_initialize(self):
        assert self.test_dock._docker_options ==  self.test_options
        assert self.test_dock._default_config_path == self.test_default_config
        assert self.test_dock._active_config_path == self.test_active_config
        assert self.test_dock.OUTPUT_DIR == self.test_output

    def test_build_file_not_exist_initconfig(self):
        with pytest.raises(OSError):
            self.test_dock._init_config()

    def test_build_exceptions(self):
        with pytest.raises(OSError):
            self.test_dock.build()
