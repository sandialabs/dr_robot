from os import makedirs, devnull, errno
from os.path import dirname, abspath, join, exists, isfile
from shutil import copy, rmtree
from subprocess import Popen
from src.robot import Robot
from src import join_abs
import logging
import json
import argparse
import sys
from enum import Enum
from sqlite3 import DatabaseError
ROOT_DIR = dirname(abspath(__file__))
USER_CONFIG = join(ROOT_DIR, 'configs', 'user_config.json')
TOOLS = ["ansible", "docker"]

class Module(Enum):
    DOCKER = 1
    ANSIBLE = 2


if not isfile(USER_CONFIG) and isfile(join(ROOT_DIR, 'configs', 'default_config.json')):
    print(ROOT_DIR)
    copy(join(ROOT_DIR, 'configs', 'default_config.json'), USER_CONFIG)
elif not isfile(join(ROOT_DIR, 'configs', 'default_config.json')):
    print("default_config.json does not exist and user_config.json does not exist. checkout the file via git.")
    sys.exit(1)

def parse_args(scanners={}, enumeration={}, webtools={}, upload_dest={}):
    """
    Parse arguments supplied at command line.
    A few of the flags are generated from the config file loaded in the init.

    Returns: (Dict) parsed args

    """
    parser = argparse.ArgumentParser(description="Docker DNS recon tool")

    parser.add_argument('--proxy',
            default=None,
            type=str,
            help="proxy server URL to set DOCKER http_proxy too")

    parser.add_argument('--dns',
            default=None,
            type=str,
            help="DNS server to add to resolv.conf of DOCKER containers")

    parser.add_argument("--domain",
            type=str,
            required=True,
            help="Domain to run scan against")

    subparser = parser.add_subparsers(dest='actions')

    parser_gather = subparser.add_parser('gather',
            help="Run scanners against the given domain and gather resources. You have the option to run using"
            "any dockers/webtools you may have included in your config.")

    for k in scanners.keys():
        parser_gather.add_argument(f"-{scanners[k].get('docker_name', None)}",
                f'--{k}',
                action='store_true',
                help=scanners[k].get('description', "No description provided"),
                default=False)

    for k in webtools.keys():
        parser_gather.add_argument(f"-{webtools[k].get('short_name', None)}",
                f'--{k}',
                action='store_true',
                help=webtools[k].get('description', "No description provided"),
                default=False)

    parser_gather.add_argument('--ignore',
            default=None,
            type=str,
            action='append',
            help="Space seperated list of subnets to ignore")

    parser_gather.add_argument('--headers',
            default=False,
            action='store_true',
            help="If headers should be scraped from ip addresses gathered")
    # Disabled for initial release
    # parser_run.add_argument('--verify',
    #                         default=None,
    #                         type=str,
    #                         help="Verify results of scan against another scan. [Requires flag to match scans being done]")

    parser_inspect = subparser.add_parser('inspect',
            help="Run further tools against domain information gathered from previous step."
            "Note: you must either supply a file which contains a list of IP/Hostnames or"
            "The targeted domain must have a db under the dbs folder")

    for k in enumeration.keys():
        parser_inspect.add_argument(f"-{enumeration[k].get('short_name')}",
                f"--{k}",
                action='store_true',
                help=enumeration[k].get('description', "No description provided"),
                default=False)

    parser_inspect.add_argument('--file',
            default=None,
            type=str,
            help="(NOT WORKING) File with hostnames to run further inspection on")

    parser_upload = subparser.add_parser('upload',
            help="Upload recon data to Mattermost. Currently only works with a"
            "folder that contain PNG images.")

    for k in upload_dest.keys():
        parser_upload.add_argument(f"-{upload_dest[k].get('short_name')}",
                f"--{k}",
                action='store_true',
                help=upload_dest[k].get('description', "No description provided"))

    parser_upload.add_argument(f"--filepath",
            default=None,
            type=str,
            help="Filepath to the folder containing images"
            "to upload. This is relative to the domain "
            "specified. By default this will just be the path to the output folder")


    parser_rebuild = subparser.add_parser('rebuild',
            help="Rebuild the database with additional files/all files from previous runtime")

    parser_rebuild.add_argument("-f",
            "--files",
            nargs="*",
            help="Additional files to supply outside of the ones in the config file")

    parser_dumpdb = subparser.add_parser("dumpdb", 
            help="Dump the database of ip,hostname,banners to a text file")

    if not len(sys.argv) > 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

def tool_check():
    """
    Verifies list of tools is installed on your system.
    Assumes binary name as shown above
    :return: NULL
    """
    for name in TOOLS:
        try:
            dnull = open(devnull)
            Popen([name], stdout=dnull, stderr=dnull).communicate()
        except OSError as e:
            if e.errno == errno.ENOENT:
                print(f"[!!!!] Tool {name} does not exists and you will most likely run into issues [!!!!]")

def load_config():
    """
    Load config from user_config.json found under the configs folder

    :return: (Dict) dictionary of tools found under their respective categories
    """
    with open(USER_CONFIG, 'r') as f:
        config = json.load(f)

    scanners = config.get('Scanners', {})
    webtools = config.get('WebTools', {})
    enumeration = config.get('Enumeration', {})
    upload_dest = config.get('Upload', {})
    return {"scanners":scanners,
            "webtools":webtools,
            "enumeration":enumeration,
            "upload_dest":upload_dest}

if __name__ == '__main__':
    try:
        if not exists(join_abs(ROOT_DIR, "logs")):
            makedirs(join_abs(ROOT_DIR, "logs"))

        logging.basicConfig(format='[!] %(asctime)s:%(lineno)d \t%(message)s',
                filename=join_abs(ROOT_DIR, "logs", "drrobot.log"),
                level=logging.DEBUG)
        tools = load_config()

        args = parse_args(**tools)

        logging.debug(args)

        tool_check()

        drrobot = Robot(root_dir=ROOT_DIR,
                user_config=USER_CONFIG,
                **tools,
                dns=getattr(args, 'dns', None),
                proxy=getattr(args, 'proxy', None),
                domain=getattr(args, 'domain'),
                verify=getattr(args, 'verify', None))

        if not exists(join_abs(ROOT_DIR, "dbs")):
            makedirs(join_abs(ROOT_DIR, "dbs"))

        if not exists(join_abs(ROOT_DIR, "output", getattr(args, 'domain'))):
            makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain')))

        if not exists(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "aggregated")):
            makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "aggregated"))

        if args.actions in "gather":

            webtools = {k: v for k, v in tools.get("webtools").items() if getattr(args, k) if True}
            scanners_dockers = {k: v for k, v in tools.get("scanners").items() if
                    getattr(args, k) is True and v["default"] == Module.DOCKER.value}
            scanners_ansible = {k: v for k, v in tools.get("scanners").items() if
                    getattr(args, k) is True and v["default"] == Module.ANSIBLE.value}
            drrobot.gather(webtools=webtools, scanners_dockers=scanners_dockers, scanners_ansible=scanners_ansible, headers=getattr(args, "headers", False))

        if args.actions in 'inspect':
            post_enum_dockers = {k: v for k, v in tools.get("enumeration").items() if
                    getattr(args, k) is True and v["default"] == Module.DOCKER.value}
            post_enum_ansible = {k: v for k, v in tools.get("enumeration").items() if
                    getattr(args, k) is True and v["default"] == Module.ANSIBLE.value}

            file = getattr(args, 'file', None)
            drrobot.inspection(post_enum_ansible=post_enum_ansible, post_enum_dockers=post_enum_dockers, file=file)

        if args.actions in "upload":
            filepath = getattr(args, "filepath")

            upload_dest = {k:v for k, v in tools.get("upload_dest").items() if
                    getattr(args, k) is True}
            drrobot.upload(filepath=filepath, upload_dest=upload_dest)

        if args.actions in "rebuild":
            files = getattr(args, "files", None)
            if files is None:
                files = []

            def gen_dict_extract(key, var):
                if hasattr(var,'items'):
                    for k, v in var.items():
                        if k == key:
                            yield v
                        if isinstance(v, dict):
                            for result in gen_dict_extract(key, v):
                                yield result
                        elif isinstance(v, list):
                            for d in v:
                                for result in gen_dict_extract(key, d):
                                    yield result

            for output in gen_dict_extract("output_file", tools):
                files += [output]

            drrobot.rebuild(files=files)
        
        if args.actions in "dumpdb":
            if exists(join_abs(ROOT_DIR, "dbs", f"{getattr(args, 'domain')}.db")):
                if not exists(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "headers")):
                    makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "headers"))
                drrobot.dumpdb()
            else:
                print("[!] DB file does not exists, try running gather first")

    except json.JSONDecodeError as er:
        print("[!] JSON load error, configuration file is bad. MUST FIX")
        logging.error(er)
    except DatabaseError as er:
        print(f"[!] Something went wrong with SQLite {er}")
        logging.error(er)
    except KeyboardInterrupt:
        print("[!] Cancelling scan")
    except OSError as er:
        logging.error(er)
        print(f"[!] {er}")
    except TypeError as er:
        logging.error(er)
        print(f"[!] {er}")
