import logging
import os
import subprocess
from string import Template
from . import join_abs

logger = logging.getLogger(__name__)
class Ansible:
    def __init__(self, **kwargs):
        """
        Build Ansible object

        Args:

            **kwargs: {
                "ansible_substitutes" : keywords to replace at run time for python job
                "ansible_file_location" : path to ansible playbooks
                "domain" : domain to scan
                "infile" : file to upload to ansible server for scan
            }

        Returns:

        """
        self.ansible_base = "ansible-playbook $flags $config"
        self.ansible_arguments = kwargs.get('ansible_arguments')
        self.ansible_file = kwargs.get('ansible_file_location', None)
        if not self.ansible_file:
            raise TypeError("argument ansible_file must be of type string, not 'NoneType'")


        self.domain = kwargs.get('domain', None)
        if not self.domain:
            raise TypeError("argument domain must be of type string, not 'NoneType'")
        self.output_dir = kwargs.get('output_dir')
        self.infile = kwargs.get('infile', None)
        if not self.infile:
            self.infile = join_abs(self.output_dir,"aggregated")

        self.verbose = kwargs.get('verbose', False)
        self.final_command = None

    def _print(self, msg):
        if self.verbose:
            print("[D] " + msg)
        logger.debug(msg)

    def build(self):
        """
        Build the final command for the ansible process.
        Uses the arguments provided in the ansible_arguments

        Args:

        Returns:

        """
        try:
            system_replacements = {
                    "infile": self.infile,
                    "outfile": self.output_dir,
                    "config": self.ansible_file
                    }

            extra_flags = self.ansible_arguments.get('extra_flags', None)
            extra_replace_string = ""
            
            self._print(f"building with extra flags {extra_flags}")

            if extra_flags:
                for k, v in extra_flags.items():
                    cur_str = Template(v)
                    extra_replace_string += cur_str.safe_substitute(system_replacements) + " "

            flags = Template(self.ansible_arguments.get("flags"))
            config = Template(self.ansible_arguments.get("config"))

            """
            This may seem redundant but this prepends the path of the ansible location to the ansible file
            specified in the config.
            all the flags are added to the flags argument to be input into the final command
            """
            substitutes = {
                    "flags" : flags.safe_substitute(extra=extra_replace_string),
                    "config" : config.safe_substitute(system_replacements)
                    }

            t = Template(self.ansible_base)
            self.final_command = t.safe_substitute(substitutes)

            self._print(f"Final ansible command {self.final_command}")
        except:
            raise TypeError("NoneType object supplied in Dict build")

    def run(self):
        """
        Run the final command built at runtime

        Args:

        Returns:

        """
        try:
            self.build()
            call = subprocess.check_output(self.final_command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as er:
            print(f"[!] {er} : {er.output}")
            logger.exception("Called Process Error Ansible")
        except OSError as er:
            print(f"[!] {er}: {er.output}")
            logger.exception("OSError in Ansible")
        except subprocess.SubprocessError as er:
            print(f"[!] {er}: {er.output}")
            logger.exception("Subprocess Error in Ansible")
        except TypeError as er:
            print(f"[!] {er}: {er.output}")
            logger.exception("Type Error in Ansible")
