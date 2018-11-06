import logging
import os
import subprocess
from string import Template
from . import join_abs
class Ansible:
    def __init__(self, **kwargs):
        """
        Build Ansible object
        Args:
            **kwargs: {
                "ansible_substitutes" : keywords to replace at run time for python job
                "domain" : domain of scan
                "infile" : file for playbook to use
            }
        """
        self.ansible_base = "ansible-playbook $flags $config"
        self.ansible_arguments = kwargs.get('ansible_arguments')
        self.ansible_file = kwargs.get('ansible_file', None)
        if not self.ansible_file:
            raise TypeError("argument ansible_file must be of type string, not 'NoneType'")


        self.domain = kwargs.get('domain', None)
        if not self.domain:
            raise TypeError("argument domain must be of type string, not 'NoneType'")
        self.output_dir = kwargs.get('output_dir')
        self.infile = kwargs.get('infile', None)
        if self.infile is None or os.path.isfile(self.infile):
            self.infile = join_abs(self.output_dir,"aggregated", "aggregated_hostnames.txt")

        self.final_command = None

    def build(self):
        try:
            system_replacements = {
                    "infile": self.infile,
                    "outfile": self.output_dir,
                    "config": self.ansible_file
                    }
            """
            This needs to be redone.
            Right now it gets the string:
                extra_flags <- "some extra flags string"
            then it tries to iterate over some string. But it should be a dictionary? But I am not sure that is the right way anymore????
            """
            extra_flags = self.ansible_arguments.get('extra_flags', None)
            extra_replace_string = ""
            if extra_flags:
                for k, v in extra_flags.items():
                    cur_str = Template(v)
                    extra_replace_string += cur_str.safe_substitute(system_replacements) + " "

            flags = Template(self.ansible_arguments.get("flags"))
            config = Template(self.ansible_arguments.get("config"))

            substitutes = {
                    "flags" : flags.safe_substitute(extra=extra_replace_string),
                    "config" : config.safe_substitute(system_replacements)
                    }

            t = Template(self.ansible_base)
            self.final_command = t.safe_substitute(substitutes)

        except:
            raise TypeError("NoneType object supplied in Dict build")

    def run(self):
        try:
            self.build()
            call = subprocess.check_output(self.final_command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as er:
            print(f"[!] {er} : {er.output}")
            logging.error(f"{er}: {er.output}")
        except OSError as er:
            print(f"[!] {er}: {er.output}")
            logging.error(f"{er}: {er.output}")
        except subprocess.SubprocessError as er:
            print(f"[!] {er}: {er.output}")
            logging.error(f"{er}: {er.output}")
        except TypeError as er:
            print(f"[!] {er}: {er.output}")
            logging.error(f"{er}: {er.output}")
