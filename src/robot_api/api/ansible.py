# -*- coding: utf8 -*-
""" Ansible module

Module for running ansible playbooks

Attributes:
    ansible_arguments (dict): Contains config, flags, and extra_flags options
    ansible_file_location (str): location to playbook
    domain (str): target domain
    ansible_base (str): Base command string
    output_dir (str): location to dump output of playbook
    infile (str): Infile for playbook job
    verbose (bool): More output Yes/No
    final_command (str): Final command to run
"""
import logging
import subprocess
from string import Template
from robot_api.parse import join_abs

LOG = logging.getLogger(__name__)


class Ansible:
    def __init__(self, **kwargs):
        """
        Build Ansible object

        Args:

            **kwargs: {
                "ansible_arguments" : {
                    "config" : "$config/httpscreenshot_play.yml",
                    "flags": "-e '$extra' -i configs/ansible_inventory",
                    "extra_flags":{
                        "1" : "variable_host=localhost",
                        "2" : "variable_user=user", 
                        "3" : "infile=$infile",
                        "4" : "outfile=$outfile/httpscreenshots.tar",
                        "5" : "outfolder=$outfile/httpscreenshots"
                    }
                },
                "ansible_file_location" : "location",
                "verbose" : True,
                "domain" : "target.domain"
            }

        Returns:

        """
        self.ansible_base = "ansible-playbook $flags $config"
        self.ansible_arguments = kwargs.get('ansible_arguments')
        self.ansible_file = kwargs.get('ansible_file_location', None)
        if not self.ansible_file:
            raise TypeError(
                "argument ansible_file must be of type string, not 'NoneType'")

        self.domain = kwargs.get('domain', None)
        if not self.domain:
            raise TypeError(
                "argument domain must be of type string, not 'NoneType'")
        self.output_dir = kwargs.get('output_dir')
        self.infile = kwargs.get('infile', None)
        if not self.infile:
            self.infile = join_abs(self.output_dir, "aggregated")

        self.verbose = kwargs.get('verbose', False)
        self.final_command = None

    def _print(self, msg):
        """Utility for logging
        """
        if self.verbose:
            print("[D] " + msg)
        LOG.debug(msg)

    def build(self):
        """Build the final command for the ansible process.
        Uses the arguments provided in the ansible_arguments

        Args:

        Returns:

        """
        try:
            system_replacements = {
                "infile": self.infile,
                "outdir": self.output_dir,
                "config": self.ansible_file
            }

            extra_flags = self.ansible_arguments.get('extra_flags', None)
            extra_replace_string = ""

            self._print(f"building with extra flags {extra_flags}")

            if extra_flags:
                for _, val in extra_flags.items():
                    cur_str = Template(val)
                    extra_replace_string += cur_str.safe_substitute(
                        system_replacements) + " "

            flags = Template(self.ansible_arguments.get("flags"))
            config = Template(self.ansible_arguments.get("config"))

            """
            This may seem redundant but this prepends the
            path of the ansible location to the ansible file
            specified in the config.
            All the flags are added to the flags
            argument to be input into the final command
            """
            substitutes = {
                "flags": flags.safe_substitute(extra=extra_replace_string),
                "config": config.safe_substitute(system_replacements)
            }

            _temp = Template(self.ansible_base)
            self.final_command = _temp.safe_substitute(substitutes)

            self._print(f"Final ansible command {self.final_command}")
        except BaseException:
            raise TypeError("NoneType object supplied in Dict build")

    def run(self):
        """Run the final command built at runtime

        Args:

        Returns:

        """
        try:
            self.build()
            _ = subprocess.check_output(
                self.final_command,
                shell=True,
                stderr=subprocess.STDOUT,
                universal_newlines=True)
        except subprocess.CalledProcessError:
            print(f"[!] CallProcessError check logs")
            LOG.exception("Called Process Error Ansible")
        except OSError:
            print(f"[!] OSError check logs")
            LOG.exception("OSError in Ansible")
        except subprocess.SubprocessError:
            print(f"[!] SubprocessError check logs")
            LOG.exception("Subprocess Error in Ansible")
        except TypeError:
            print(f"[!] TypeError check logs")
            LOG.exception("Type Error in Ansible")
