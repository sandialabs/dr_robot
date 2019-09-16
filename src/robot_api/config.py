import json
import pkg_resources
from subprocess import Popen
from os import devnull, environ, path, makedirs
try:
    import errno
except BaseException:
    from os import errno

def generate_configs():

    CONFIG_DIR = path.join(environ.get("HOME","."),".drrobot")
    if not path.exists(CONFIG_DIR):
        makedirs(CONFIG_DIR)

    if not path.isfile(path.join(CONFIG_DIR, "config.json")):
        with open(path.join(CONFIG_DIR, "config.json"), 'wb') as f:
            config = pkg_resources.resource_string(__name__, 'configs/default_config.json')
            f.write(config)

    if not path.isfile(path.join(CONFIG_DIR, "ansible_inventory")):
        with open(path.join(CONFIG_DIR, "ansible_inventory"), 'wb') as f:
            config = pkg_resources.resource_string(__name__, 'configs/ansible_inventory')
            f.write(config)

    if not path.exists(path.join(CONFIG_DIR, "docker_buildfiles")):
        makedirs(path.join(CONFIG_DIR, "docker_buildfiles"))

    for _file in pkg_resources.resource_listdir(__name__, "docker_buildfiles"):
        if not path.isfile(path.join(CONFIG_DIR, "docker_buildfiles", _file)):
            fpath = path.join("docker_buildfiles", _file)
            contents = pkg_resources.resource_string(__name__, fpath)
            with open(path.join(CONFIG_DIR, "docker_buildfiles", _file), 'wb') as f:
                f.write(contents)

    if not path.exists(path.join(CONFIG_DIR, "ansible_plays")):
        makedirs(path.join(CONFIG_DIR, "ansible_plays"))

    for _file in pkg_resources.resource_listdir(__name__, "ansible_plays"):
        if not path.isfile(path.join(CONFIG_DIR, "ansible_plays", _file)):
            fpath = path.join("ansible_plays", _file)
            contents = pkg_resources.resource_string(__name__, fpath)
            with open(path.join(CONFIG_DIR, "ansible_plays", _file), 'wb') as f:
                f.write(contents)

def tool_check():

    TOOLS = ["ansible", "docker"]
    for name in TOOLS:
        try:
            dnull = open(devnull)
            Popen([name], stdout=dnull, stderr=dnull).communicate()
        except OSError as e:
            if e.errno == errno.ENOENT:
                print(f"[!!] Tool {name} not found in path.")


def load_config(config):

    with open(config, 'r') as f:
        config = json.load(f)

    scanners = config.get('Scanners', {})
    webtools = config.get('WebTools', {})
    enumeration = config.get('Enumeration', {})
    upload_dest = config.get('Upload', {})
    serve = config.get('Serve', {})
    return {"scanners": scanners,
            "webtools": webtools,
            "enumeration": enumeration,
            "upload_dest": upload_dest,
            "server": serve}

def get_config():
    return path.join(environ.get("HOME", "."), ".drrobot", "config.json")
