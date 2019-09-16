import argparse
import json
import pkg_resources
from os import devnull, environ, path, makedirs

def join_abs(*args):
    return path.abspath(path.join(*args))

def parse_args(
        scanners={},
        enumeration={},
        webtools={},
        upload_dest={},
        server={},
        root_dir="."):

    parser = argparse.ArgumentParser(description="Docker DNS recon tool")

    parser.add_argument('--proxy',
                        default=None,
                        type=str,
                        help="Proxy server URL to set DOCKER http_proxy too")

    parser.add_argument(
        '--dns',
        default=None,
        type=str,
        help="DNS server to add to resolv.conf of DOCKER containers")

    parser.add_argument('--verbose',
                        default=False,
                        action="store_true",
                        help="Display verbose statements")

    parser.add_argument('--dbfile',
                        default=join_abs(root_dir, "dbs", "drrobot.db"),
                        type=str,
                        help="Specify what db file to use for saving data too")

    subparser = parser.add_subparsers(dest='actions')
    ##########################
    # GATHER
    ##########################

    parser_gather = subparser.add_parser(
        'gather',
        help="Runs initial scanning phase where tools under the webtools/scanners"
        "category will run and gather information used in the following phases")

    for k in scanners.keys():
        parser_gather.add_argument(
            f"-{scanners[k].get('docker_name', None)}",
            f'--{k}',
            action='store_true',
            help=scanners[k].get(
                'description',
                "No description provided"),
            default=False)

    for k in webtools.keys():
        parser_gather.add_argument(
            f"-{webtools[k].get('short_name', None)}",
            f'--{k}',
            action='store_true',
            help=webtools[k].get(
                'description',
                "No description provided"),
            default=False)

    parser_gather.add_argument(
        '--ignore',
        default=None,
        type=str,
        action='append',
        help="Space seperated list of subnets to ignore")

    parser_gather.add_argument(
        '--headers',
        default=False,
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
    # INSPECT
    ##########################

    parser_inspect = subparser.add_parser(
        'inspect',
        help="Run further tools against domain information gathered from previous step."
        "Note: you must either supply a file which contains a list of IP/Hostnames or"
        "The targeted domain must have a db under the dbs folder")

    for k in enumeration.keys():
        parser_inspect.add_argument(
            f"-{enumeration[k].get('short_name')}",
            f"--{k}",
            action='store_true',
            help=enumeration[k].get(
                'description',
                "No description provided"),
            default=False)

    # parser_inspect.add_argument('--file',
    #                             default=None,
    #                             type=str,
    # help="(NOT WORKING) File with hostnames to run further inspection on")

    parser_inspect.add_argument("domain",
                                type=str,
                                help="Domain to run scan against")
    ##########################
    # UPLOAD
    ##########################

    parser_upload = subparser.add_parser(
        'upload', help="Upload recon data to Mattermost/Slack")

    for k in upload_dest.keys():
        parser_upload.add_argument(
            f"-{upload_dest[k].get('short_name')}",
            f"--{k}",
            action='store_true',
            help=upload_dest[k].get(
                'description',
                "No description provided"))

    parser_upload.add_argument(
        f"filepath", type=str, help="Filepath to the folder containing images"
        "to upload. This is relative to the domain "
        "specified. By default this will just be the path to the output folder")
    ##########################
    # REBUILD
    ##########################

    parser_rebuild = subparser.add_parser(
        'rebuild',
        help="Rebuild the database with additional files/all files from previous runtime")

    parser_rebuild.add_argument("domain",
                                type=str,
                                help="Domain to dump output of")

    parser_rebuild.add_argument(
        "-f",
        "--files",
        nargs="*",
        help="Additional files to supply outside of the ones in the config file")

    ##########################
    # DUMPDB
    ##########################

    parser_dumpdb = subparser.add_parser(
        "dumpdb",
        help="Dump contents of database (ip,hostname,banners) to a text file with hostname for filename")
    parser_dumpdb.add_argument("domain",
                               type=str,
                               help="Domain to show data for")
    ##########################
    # OUTPUT
    ##########################
    parser_output = subparser.add_parser(
        "output",
        help="Generate output in specified format. Contains all information from scans (images, headers, hostnames, ips)")

    parser_output.add_argument(
        "format",
        choices=[
            "json",
            "xml"],
        default="json",
        help="Generate json file under outputs folder (format)")

    parser_output.add_argument(
        "--output",
        default=None,
        help="Alternative location to create output file")

    parser_output.add_argument("domain",
                               type=str,
                               help="Domain to dump output of")
    ##########################
    # SERVE
    ##########################

    parser_serve = subparser.add_parser(
        "serve", help="Serve database file in docker container using django")

    return parser
