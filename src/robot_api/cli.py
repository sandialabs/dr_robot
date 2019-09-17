from os import makedirs, path, environ
import logging
import json
import sys
from shutil import copy
from enum import Enum
from sqlite3 import DatabaseError
import pkg_resources

from robot_api.robot import Robot
from robot_api.parse import  parse_args, join_abs
from robot_api.config import load_config, generate_configs, tool_check, get_config


ROOT_DIR = path.join(environ.get("HOME","."),".drrobot")

generate_configs()

class Mode(Enum):
    DOCKER = 1
    ANSIBLE = 2

def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.NOTSET)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)-5s|%(name)s] \t%(message)s')

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


def run():
    try:
        if not path.exists(join_abs(ROOT_DIR, "logs")):
            makedirs(join_abs(ROOT_DIR, "logs"))

        log = setup_logger()

        tools = load_config(get_config())

        parser = parse_args(**tools, root_dir=ROOT_DIR)

        if not len(sys.argv) > 1:
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

        if getattr(args, 'domain', None):
            if not path.exists(
                join_abs(
                    ROOT_DIR,
                    "output",
                    getattr(
                        args,
                        'domain'))):
                makedirs(join_abs(ROOT_DIR, "output", getattr(args, 'domain')))

            if not path.exists(
                join_abs(
                    ROOT_DIR,
                    "output",
                    getattr(
                        args,
                        'domain'),
                    "aggregated")):
                makedirs(
                    join_abs(
                        ROOT_DIR,
                        "output",
                        getattr(
                            args,
                            'domain'),
                        "aggregated"))

        if args.actions in "gather":

            try:
                drrobot._print("Beginning gather")
                webtools = {
                    k: v for k,
                    v in tools.get("webtools").items() if getattr(
                        args,
                        k) if True}
                drrobot._print(f"Webtools:\n{webtools}")

                scanners_dockers = {k: v for k, v
                                    in tools.get("scanners").items()
                                    if getattr(args, k)
                                    is True and Mode[v["mode"]] == Mode.DOCKER}
                drrobot._print(f"Scanners as Dockers: \
                        {json.dumps(scanners_dockers, indent=4)}")

                scanners_ansible = {k: v for k, v
                                    in tools.get("scanners").items()
                                    if getattr(args, k)
                                    is True
                                    and Mode[v["mode"]] == Mode.ANSIBLE}
                drrobot._print(
                    f"Scanners as Ansible Play: \
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
            except KeyError as e:
                print(f"[!] Mode {e} not found. Please fix config file")

        if args.actions in 'inspect':

            try:
                drrobot._print("Beginning inspection")
                post_enum_dockers = {k: v for k, v
                                     in tools.get("enumeration").items()
                                     if getattr(args, k)
                                     is True
                                     and Mode[v["mode"]] == Mode.DOCKER}
                drrobot._print(
                    f"Inspection dockers \
                            {json.dumps(post_enum_dockers, indent=4)}")

                post_enum_ansible = {k: v for k, v
                                     in tools.get("enumeration").items()
                                     if getattr(args, k)
                                     is True
                                     and Mode[v["mode"]] == Mode.ANSIBLE}
                drrobot._print(
                    f"Inspection ansible \
                            {json.dumps(post_enum_ansible, indent=4)}")

                if not post_enum_ansible and not post_enum_dockers:
                    print("[*] No scanners/webtools provided, exiting...")
                    parser.print_help()
                    sys.exit(0)

            except KeyError as e:
                print(f"[!] Mode {e} not found. Please fix config file")

            _file = getattr(args, 'file', None)
            drrobot.inspection(
                post_enum_ansible=post_enum_ansible,
                post_enum_dockers=post_enum_dockers,
                file=_file)

        if args.actions in "upload":

            filepath = getattr(args, "filepath")
            if filepath is None:
                print("No filepath provided, exiting...")
                sys.exit(0)
            elif not path.exists(filepath):
                print("Filepath does not exists, exiting...")
                sys.exit(0)

            drrobot._print(f"Beginning upload with file path: {filepath}")

            upload_dest = {k: v for k, v in tools.get("upload_dest").items() if
                           getattr(args, k) is True}
            drrobot._print(
                f"Upload tools: {json.dumps(upload_dest, indent=4)}")

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
            for folder in gen_dict_extract("output_folder", tools):
                files += [folder]

            drrobot.rebuild(files=files)

        if args.actions in "output":
            _format = getattr(args, "format")
            output = getattr(args, "output")
            # TODO implement other output formats
            drrobot.generate_output(_format, output)

        if args.actions in "dumpdb":
            dbpath = getattr(args, "dbfile")

            if path.exists(dbpath):
                if not path.exists(
                    join_abs(
                        ROOT_DIR,
                        "output",
                        getattr(
                            args,
                            'domain'),
                        "headers")):
                    makedirs(
                        join_abs(
                            ROOT_DIR,
                            "output",
                            getattr(
                                args,
                                'domain'),
                            "headers"))
                drrobot.dumpdb()
            else:
                print("[!] DB file does not exists, try running gather first")

    except json.JSONDecodeError as er:
        print(f"[!] JSON load error, configuration file is bad.\n {er}")
        log.error(er)
    except DatabaseError as er:
        print(f"[!] Something went wrong with SQLite\n {er}")
        log.error(er)
    except KeyboardInterrupt:
        print("[!] KeyboardInterrup, exiting...")
    except OSError as er:
        log.error(er)
        print(f"[!] e {er}")
    except TypeError as er:
        log.error(er)
        print(f"[!] {er}")


if __name__ == "__main__":
    run()
