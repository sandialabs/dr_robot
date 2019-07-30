from os import makedirs, devnull, errno
from os.path import dirname, abspath, join, exists, isfile
from subprocess import Popen
from src.robot import Robot
from src import join_abs
import logging
import json
import argparse
import sys
from shutil import copy
from enum import Enum
from sqlite3 import DatabaseError
ROOT_DIR = dirname(abspath(__file__))
USER_CONFIG = join(ROOT_DIR, 'configs', 'user_config.json')
TOOLS = ["ansible", "docker"]


class Mode(Enum):
    DOCKER = 1
    ANSIBLE = 2


if not isfile(USER_CONFIG) and isfile(join(ROOT_DIR, 'configs', 'default_config.json')):
    copy(join(ROOT_DIR, 'configs', 'default_config.json'), USER_CONFIG)
elif not isfile(join(ROOT_DIR, 'configs', 'default_config.json')):
    print("default_config.json does not exist and user_config.json does not exist. checkout the file via git.")
    sys.exit(1)


def parse_args(scanners={}, enumeration={}, webtools={}, upload_dest={}, server={}):

    """
    Parse arguments supplied at command line.
    A few of the flags are generated from the config file loaded in the init.

    Returns: (Dict) parsed args

    """
    parser = argparse.ArgumentParser(description="Docker DNS recon tool")

    parser.add_argument('--proxy',
                        default=None,
                        type=str,
                        help="Proxy server URL to set DOCKER http_proxy too")

    parser.add_argument('--dns',
                        default=None,
                        type=str,
                        help="DNS server to add to resolv.conf of DOCKER containers")

    parser.add_argument('--verbose',
                        default=False,
                        action="store_true",
                        help="Display verbose statements")

    parser.add_argument('--dbfile',
                        default="drrobot.db",
                        type=str,
                        help="Specify what db file to use for saving data too")

    subparser = parser.add_subparsers(dest='actions')
    ##########################
    # GATHER
    ##########################

    parser_gather = subparser.add_parser('gather',
                                         help="Runs initial scanning phase where tools under the webtools/scanners"
                                         "category will run and gather information used in the following phases")

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
                               default=True,
                               action='store_true',
                               help="If headers should be scraped from ip addresses gathered")

    parser_gather.add_argument("domain",
                            type=str,
                            help="Domain to run scan against")

    # Disabled for initial release
    # parser_run.add_argument('--verify',
    #                         default=None,
    #                         type=str,
    #                         help="Verify results of scan against another scan. [Requires flag to match scans being done]")
    ##########################
    #INSPECT
    ##########################

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

    parser_inspect.add_argument("domain",
                                type=str,
                                help="Domain to run scan against")
    ##########################
    #UPLOAD
    ##########################

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

    parser_upload.add_argument("domain",
                                type=str,
                                help="Domain to run scan against")
    ##########################
    #REBUILD
    ##########################

    parser_rebuild = subparser.add_parser('rebuild',
                                          help="Rebuild the database with additional files/all files from previous runtime")

    parser_rebuild.add_argument("-f",
                                "--files",
                                nargs="*",
                                help="Additional files to supply outside of the ones in the config file")

    parser_rebuild.add_argument("domain",
                                type=str,
                                help="Domain to dump output of")
    ##########################
    #DUMPDB
    ##########################

    parser_dumpdb = subparser.add_parser("dumpdb",
                                         help="Dump the database of ip,hostname,banners to a text file")
    parser_dumpdb.add_argument("domain",
                                type=str,
                                help="Domain to show data for")
    ##########################
    #OUTPUT
    ##########################
    parser_output = subparser.add_parser("output",
                                         help="Generate output in specified format. Contains all information from scans (images, headers, hostnames, ips)")

    parser_output.add_argument("format",
                               choices=["json", "xml"],
                               default="json",
                               help="Generate json file under outputs folder (format)")

    parser_output.add_argument("--output",
                               default=None,
                               help="Alternative location to create output file")

    parser_output.add_argument("domain",
                                type=str,
                                help="Domain to dump output of")
    ##########################
    #SERVE
    ##########################

    parser_serve = subparser.add_parser("serve",
                                         help="Serve database file in docker container using django")

    if not len(sys.argv) > 1:
        parser.print_help()
        sys.exit(1)

    return parser


def tool_check():
    """
    Verifies list of tools is installed on your system.
    Assumes binary names are as shown in the list of TOOLS
    Args:

    Returns:

    """
    for name in TOOLS:
        try:
            dnull = open(devnull)
            Popen([name], stdout=dnull, stderr=dnull).communicate()
        except OSError as e:
            if e.errno == errno.ENOENT:
                print(f"[!!] Tool {name} not found in path.")


def load_config():
    """
    Load config from user_config.json found under the configs folder

    Args:

    Returns:
        (Dict) dictionary of tools found under their respective categories
    """
    with open(USER_CONFIG, 'r') as f:
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
            "server" : serve}

def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.NOTSET)
    formatter = logging.Formatter('%(asctime)s [%(levelname)-5s|%(name)s] \t%(message)s')

    handler = logging.FileHandler(filename=join_abs(ROOT_DIR, "logs", "drrobot.err"))
    handler.setLevel(logging.ERROR)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    handler = logging.FileHandler(filename=join_abs(ROOT_DIR, "logs", "drrobot.dbg"))
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


    logging.getLogger("urllib3.connectionpool").disabled=True

    return logger

if __name__ == '__main__':
    try:
        if not exists(join_abs(ROOT_DIR, "logs")):
            makedirs(join_abs(ROOT_DIR, "logs"))

        log = setup_logger()

        tools = load_config()

        parser = parse_args(**tools)
        args = parser.parse_args()

        if not args.actions:
            print("No action selected, exiting...")
            sys.exit(1)

        log.debug(args)

        tool_check()

        drrobot = Robot(root_dir=ROOT_DIR,
                        user_config=USER_CONFIG,
                        **tools,
                        dns=getattr(args, 'dns', None),
                        proxy=getattr(args, 'proxy', None),
                        domain=getattr(args, 'domain', None),
                        verbose=getattr(args, 'verbose'),
                        dbfile=getattr(args, 'dbfile'),
                        verify=getattr(args, 'verify', None))

        if not exists(join_abs(ROOT_DIR, "dbs")):
            makedirs(join_abs(ROOT_DIR, "dbs"))

        if getattr(args, 'domain', None):
            if not exists(join_abs(ROOT_DIR, "output", getattr(args, 'domain'))):
                makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain')))

            if not exists(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "aggregated")):
                makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "aggregated"))

        if args.actions in "gather":

            try:
                drrobot._print("Beginning gather")
                webtools = {k: v for k, v in tools.get("webtools").items() if getattr(args, k) if True}
                drrobot._print(f"Webtools:\n{webtools}")

                scanners_dockers = {k: v for k, v in tools.get("scanners").items() if
                                    getattr(args, k) is True and Mode[v["mode"]] == Mode.DOCKER}
                drrobot._print(f"Scanners as Dockers: {json.dumps(scanners_dockers, indent=4)}")

                scanners_ansible = {k: v for k, v in tools.get("scanners").items() if
                                    getattr(args, k) is True and Mode[v["mode"]] == Mode.ANSIBLE}
                drrobot._print(f"Scanners as Ansible Play: {json.dumps(scanners_ansible, indent=4)}")

                if not webtools and not scanners_ansible and not scanners_dockers:
                    print("[*] No scanners/webtools provided, exiting...")
                    parser.print_help()
                    sys.exit(0)

                drrobot.gather(webtools=webtools, scanners_dockers=scanners_dockers, scanners_ansible=scanners_ansible, headers=getattr(args, "headers", False))
            except KeyError as e:
                print(f"[!] Mode {e} not found. Please fix config file")

        if args.actions in 'inspect':

            try:
                drrobot._print("Beginning inspection")
                post_enum_dockers = {k: v for k, v in tools.get("enumeration").items() if
                                     getattr(args, k) is True and Mode[v["mode"]] == Mode.DOCKER}
                drrobot._print(f"Inspection dockers {json.dumps(post_enum_dockers, indent=4)}")

                post_enum_ansible = {k: v for k, v in tools.get("enumeration").items() if
                                     getattr(args, k) is True and Mode[v["mode"]] == Mode.ANSIBLE}
                drrobot._print(f"Inspection ansible {json.dumps(post_enum_ansible, indent=4)}")

                if not post_enum_ansible and not post_enum_dockers:
                    print("[*] No scanners/webtools provided, exiting...")
                    parser.print_help()
                    sys.exit(0)
                    
            except KeyError as e:
                print(f"[!] Mode {e} not found. Please fix config file")

            file = getattr(args, 'file', None)
            drrobot.inspection(post_enum_ansible=post_enum_ansible, post_enum_dockers=post_enum_dockers, file=file)

        if args.actions in "upload":

            filepath = getattr(args, "filepath")
            drrobot._print(f"Beginning upload with file path: {filepath}")

            upload_dest = {k: v for k, v in tools.get("upload_dest").items() if
                           getattr(args, k) is True}
            drrobot._print(f"Upload tools: {json.dumps(upload_dest, indent=4)}")

            drrobot.upload(filepath=filepath, upload_dest=upload_dest)

        if args.actions in "rebuild":
            files = getattr(args, "files", None)
            if files is None:
                files = []

            def gen_dict_extract(key, var):
                if hasattr(var, 'items'):
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

        if args.actions in "output":
            _format = getattr(args, "format")
            output = getattr(args, "output")
            #TODO implement other output formats
            drrobot.generate_output(_format, output)

        if args.actions in "dumpdb":
            if exists(join_abs(ROOT_DIR, "dbs", f"{getattr(args, 'domain')}.db")):
                if not exists(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "headers")):
                    makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "headers"))
                drrobot.dumpdb()
            else:
                print("[!] DB file does not exists, try running gather first")
        
        if args.actions in "serve":
            # TODO Add check for running container
            print("Serving drrobot container. (Warning, you will have to stop the container on your own)")
            drrobot.serve(server=tools.get("server"))

    except json.JSONDecodeError as er:
        print(f"[!] JSON load error, configuration file is bad.\n {er}")
        log.error(er)
    except DatabaseError as er:
        print(f"[!] Something went wrong with SQLite\n {er}")
        log.error(er)
    except KeyboardInterrupt:
        print("[!] Cancelling scan")
    except OSError as er:
        log.error(er)
        print(f"[!] {er}")
    except TypeError as er:
        log.error(er)
        print(f"[!] {er}")
