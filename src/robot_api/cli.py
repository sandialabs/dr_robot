# -*- coding: utf-8 -*-
"""Cli module for Dr.ROBOT

This module sets up the logger and configuration files for cli usage.
"""
from os import makedirs, path, environ
import logging
import json
import sys
from enum import Enum
from sqlite3 import DatabaseError

from robot_api.robot import Robot
from robot_api.parse import parse_args, join_abs
from robot_api.config import load_config, generate_configs, tool_check, get_config


ROOT_DIR = path.join(environ.get("HOME","."),".drrobot")

generate_configs()


class Mode(Enum):
    """Class for simple option handling when loading the config file.

    Leave for extending upon later

    """
    DOCKER = 1
    ANSIBLE = 2


def setup_logger():
    """Setup our logging instance.
    Returns:
        A logger for writing to two seperate files depending on error or debug messages
    """
    logger = logging.getLogger()
    logger.setLevel(logging.NOTSET)
    formatter = logging.Formatter(
            '%(asctime)s {%(pathname)s:%(lineno)d}: \t%(message)s')

    handler = logging.FileHandler(
        filename=join_abs(
            ROOT_DIR,
            "logs",
            "drrobot.err"))
    handler.setLevel(logging.ERROR)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    handler = logging.FileHandler(
        filename=join_abs(
            ROOT_DIR,
            "logs",
            "drrobot.dbg"))
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logging.getLogger("urllib3.connectionpool").disabled = True

    return logger


def create_dirs(parser):
    """Create directories for domain under output folder
    """
    args = parser.parse_args()
    if getattr(args, 'domain', None):
        if not path.exists(
                        join_abs(ROOT_DIR, "output", getattr(args, 'domain'))):
            makedirs(
                join_abs(ROOT_DIR, "output", getattr(args, 'domain')))

        if not path.exists(
                        join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "aggregated")):
            makedirs(
                join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "aggregated"))


def start_gather(drrobot, tools, parser):
    """Gather data using OSINT tools

    This method starts off the gather phase of Dr.ROBOT.
    Meant to be passive, HOWEVER, pay attention to the tools
    you are using. Not all tools are passive and as such it is
    important to double check what you are running.


    TODO:
        * Track passive tools vs none passive
    """
    args = parser.parse_args()
    print("Beginning gather")
    verbose = getattr(args, "verbose", False)
    webtools = {
        k: v for k, v in tools.get("webtools").items() if getattr(args, k)
        }
    if verbose:
        print(f"Webtools:\n{webtools}")

    scanners_dockers = {k: v for k, v
                        in tools.get("scanners").items()
                        if getattr(args, k)
                        is True and Mode[v["mode"]] == Mode.DOCKER}
    if verbose:
        print(f"Scanners as Dockers: \
        {json.dumps(scanners_dockers, indent=4)}")

    scanners_ansible = {k: v for k, v
                        in tools.get("scanners").items()
                        if getattr(args, k)
                        is True
                        and Mode[v["mode"]] == Mode.ANSIBLE}
    if verbose:
        print(f"Scanners as Ansible Play: \
                {json.dumps(scanners_ansible, indent=4)}")

    if not webtools and \
        not scanners_ansible and \
            not scanners_dockers:
        print("[*] No scanners/webtools provided, exiting...")
        parser.print_help()
        sys.exit(0)

    drrobot.gather(
        webtools=webtools,
        scanners_dockers=scanners_dockers,
        scanners_ansible=scanners_ansible,
        headers=getattr(
            args,
            "headers",
            False))


def start_inspect(drrobot, tools, parser):
    """Begin inspection of domain using aggregated data.

    This module starts off the "inspection" phase of Dr.ROBOT
    Inspection is a none-passive portion of this tool and is meant
    to generate more interesting output using the aggregated data
    """
    print("Beginning inspection")
    args = parser.parse_args()
    verbose = getattr(args, "verbose", False)
    post_enum_dockers = {k: v for k, v
                         in tools.get("enumeration").items()
                         if getattr(args, k)
                         is True
                         and Mode[v["mode"]] == Mode.DOCKER}
    if verbose:
        print(f"Inspection dockers \
                    {json.dumps(post_enum_dockers, indent=4)}")

    post_enum_ansible = {k: v for k, v
                         in tools.get("enumeration").items()
                         if getattr(args, k)
                         is True
                         and Mode[v["mode"]] == Mode.ANSIBLE}
    if verbose:
        print(f"Inspection ansible \
                    {json.dumps(post_enum_ansible, indent=4)}")

    if not post_enum_ansible and not post_enum_dockers:
        print("[*] No scanners/webtools provided, exiting...")
        parser.print_help()
        sys.exit(0)

    _file = getattr(args, 'file', None)
    drrobot.inspection(
        post_enum_ansible=post_enum_ansible,
        post_enum_dockers=post_enum_dockers,
        file=_file)


def start_upload(drrobot, tools, parser):
    """Uploads files/images to destination

    TODO:
        * Other upload destinations
    """
    args = parser.parse_args()
    filepath = getattr(args, "filepath")
    if filepath is None:
        print("No filepath provided, exiting...")
        sys.exit(0)
    elif not path.exists(filepath):
        print("Filepath does not exists, exiting...")
        sys.exit(0)

    print(f"Beginning upload with file path: {filepath}")

    upload_dest = {k: v for k, v in tools.get("upload_dest").items() if
                   getattr(args, k) is True}
    print(
        f"Upload tools: {json.dumps(upload_dest, indent=4)}")

    drrobot.upload(filepath=filepath, upload_dest=upload_dest)


def start_rebuild(drrobot, tools, parser):
    """Rebuild database with given files/directory

    Parsers the config file and files argument and loads all relevant files to
    throw through the aggregation module
    """
    args = parser.parse_args()
    files = getattr(args, "files", None)
    headers = getattr(args, "headers", False)
    if files is None:
        files = []

    def gen_dict_extract(key, var):
        if hasattr(var, 'items'):
            for _key2, _val2 in var.items():
                if _key2 == key:
                    yield _val2
                if isinstance(_val2, dict):
                    for result in gen_dict_extract(key, _val2):
                        yield result
                elif isinstance(_val2, list):
                    for _dict in _val2:
                        for result in gen_dict_extract(key, _dict):
                            yield result

    for output in gen_dict_extract("output_file", tools):
        files += [output]
    for folder in gen_dict_extract("output_folder", tools):
        files += [folder]

    drrobot.rebuild(files=files, headers=headers)


def start_dumpdb(drrobot, parser):
    """Dump database to output folder for given domain

    Generates all header text files and aggregated files under
    $HOME/.drrobot/output/<domain>/aggregated
    """
    args = parser.parse_args()
    dbpath = getattr(args, "dbfile")

    if path.exists(dbpath):
        if not path.exists(
                        join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "headers")):
            makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain'), "headers"))
        drrobot.dumpdb()
    else:
        print("[!] DB file does not exists, try running gather first")


def start_output(drrobot, parser):
    """Generate output

    Dump database and generate json/xml file

    TODO:
        * Other output forms
    """
    args = parser.parse_args()
    _format = getattr(args, "format")
    output = getattr(args, "output")
    drrobot.generate_output(_format, output)

def run():
    """Main method for running Dr.ROBOT.

    Returns:
        Nothing.
    """
    try:
        if not path.exists(join_abs(ROOT_DIR, "logs")):
            makedirs(join_abs(ROOT_DIR, "logs"))

        log = setup_logger()

        tools = load_config(get_config())

        parser = parse_args(**tools, root_dir=ROOT_DIR)

        if len(sys.argv) <= 1:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        log.debug(args)

        tool_check()

        drrobot = Robot(root_dir=ROOT_DIR,
                        user_config=get_config(),
                        **tools,
                        dns=getattr(args, 'dns', None),
                        proxy=getattr(args, 'proxy', None),
                        domain=getattr(args, 'domain', None),
                        verbose=getattr(args, 'verbose'),
                        dbfile=getattr(args, 'dbfile'),
                        verify=getattr(args, 'verify', None))

        if not path.exists(join_abs(ROOT_DIR, "dbs")):
            makedirs(join_abs(ROOT_DIR, "dbs"))

        create_dirs(parser)
        log.debug(f"Dumping tools for run :{tools}")

        if args.actions in "gather":
            start_gather(drrobot, tools, parser)

        if args.actions in 'inspect':
            start_inspect(drrobot, tools, parser)

        if args.actions in "upload":
            start_upload(drrobot, tools, parser)

        if args.actions in "rebuild":
            start_rebuild(drrobot, tools, parser)

        if args.actions in "output":
            start_output(drrobot, parser)

        if args.actions in "dumpdb":
            start_dumpdb(drrobot, parser)

    except json.JSONDecodeError as error:
        print(f"[!] JSON load error, configuration file is bad.\n {error}")
        log.exception(error)
    except DatabaseError as error:
        print(f"[!] Something went wrong with SQLite\n {error}")
        log.exception(error)
    except KeyboardInterrupt:
        print("[!] KeyboardInterrup, exiting...")
    except OSError as error:
        log.exception(error)
        print(f"[!] OSError {error}")
    except TypeError as error:
        log.exception(error)
        print(f"[!] {error}")


if __name__ == "__main__":
    run()
