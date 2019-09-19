# -*- coding: utf8 -*-
""" Config Module

Utility methods for loading configuration files,
Generating template and config files into HOME directory
Checking if tools exist
"""
import json
from subprocess import Popen
from os import devnull, environ, path, makedirs
import pkg_resources
try:
    import errno
except Exception:
    from os import errno


def generate_configs():
    """Loads configuration files and templates into users home directory.

    Returns:
        None
    """

    CONFIG_DIR = path.join(environ.get("HOME","."),".drrobot")
    if not path.exists(CONFIG_DIR):
        makedirs(CONFIG_DIR)

    if not path.isfile(path.join(CONFIG_DIR, "config.json")):
        with open(path.join(CONFIG_DIR, "config.json"), 'wb') as _file:
            config = pkg_resources.resource_string(__name__, 
                                                   'configs/default_config.json')
            _file.write(config)

    if not path.isfile(path.join(CONFIG_DIR, "ansible_inventory")):
        with open(path.join(CONFIG_DIR, "ansible_inventory"), 'wb') as _file:
            config = pkg_resources.resource_string(__name__, 
                                                   'configs/ansible_inventory')
            _file.write(config)

    if not path.exists(path.join(CONFIG_DIR, "docker_buildfiles")):
        makedirs(path.join(CONFIG_DIR, "docker_buildfiles"))

    for _file in pkg_resources.resource_listdir(__name__, "docker_buildfiles"):
        if not path.isfile(path.join(CONFIG_DIR, "docker_buildfiles", _file)):
            fpath = path.join("docker_buildfiles", _file)
            contents = pkg_resources.resource_string(__name__, fpath)
            with open(path.join(CONFIG_DIR, "docker_buildfiles", _file),
                      'wb') as _file:
                _file.write(contents)

    if not path.exists(path.join(CONFIG_DIR, "ansible_plays")):
        makedirs(path.join(CONFIG_DIR, "ansible_plays"))

    for _file in pkg_resources.resource_listdir(__name__, "ansible_plays"):
        if not path.isfile(path.join(CONFIG_DIR, "ansible_plays", _file)):
            fpath = path.join("ansible_plays", _file)
            contents = pkg_resources.resource_string(__name__, fpath)
            with open(path.join(CONFIG_DIR, "ansible_plays", _file),
                      'wb') as _file:
                _file.write(contents)


def tool_check():
    """Checks if Docker or Ansible exists
    """

    TOOLS = ["ansible", "docker"]
    for name in TOOLS:
        try:
            dnull = open(devnull)
            Popen([name], stdout=dnull, stderr=dnull).communicate()
        except OSError as error:
            if error.errno == errno.ENOENT:
                print(f"[!!] Tool {name} not found in path. " + 
                      "If we error out it is your fault.")


def load_config(config):
    """Load all data from the json file in the USERS home directory

    Returns:
        A dict of the USER defined tools and their options for running them :

        { "scanners" : {...},
        "webtools" : {...},
        "enumeration" : {...},
        "upload_dest" : {...},
    """

    with open(config, 'r') as f:
        config = json.load(f)

    scanners = config.get('Scanners', {})
    webtools = config.get('WebTools', {})
    enumeration = config.get('Enumeration', {})
    upload_dest = config.get('Upload', {})
    return {"scanners": scanners,
            "webtools": webtools,
            "enumeration": enumeration,
            "upload_dest": upload_dest}


def get_config():
    """Utility to fetch the path to the configuration file.

    If HOME is not defined just check the current directory.

    Returns:
        A string path that points to the config.json file.
    """
    return path.join(environ.get("HOME", "."), ".drrobot", "config.json")
