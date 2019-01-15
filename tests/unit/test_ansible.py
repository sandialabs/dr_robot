import pytest
from src.ansible import Ansible

class TestAnsible(object):

    @pytest.fixture(scope="module")
    def setup(self):
        args = {
                "ansible_arguments": {
                    "config" : "testconfig",
                    "flags" : "--private-key test"
                    },
                "domain": "test.com",
                "infile": "testfile",
                "output_dir" : "test_output",
                "ansible_file_location" : "test_ansible_file"

                }
        return Ansible(**args)

    def test_verify_ansible_command(self, setup):
        setup.build()
        assert "ansible-playbook --private-key test testconfig" in setup.final_command

    def test_sanity_errors(self):
        with pytest.raises(TypeError):
            a = Ansible(**{})
            a.build()

    def test_sanity_none_args(self):
        args = {
                "ansible_arguments": {
                    "config": None,
                    "flags": "ASDAS"
                    },
                "domain": None,
                "infile": None,
                "output_dir" : "test_output",
                "ansible_file_location" : "test_ansible_file"
                }
        with pytest.raises(TypeError):
            ansible = Ansible(**args)
