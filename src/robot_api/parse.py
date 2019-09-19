import argparse
import json
import pkg_resources
from os import devnull, environ, path, makedirs


def join_abs(*args):
    """Utility method to call abspath and join
    without having to write it out every single time

    Args:
        *args: Multiple string like parameters to be joined

    Returns:
        string to the absolute path pointed to by *args

    """
    return path.abspath(path.join(*args))

def parse_args(
        scanners=None,
        enumeration=None,
        webtools=None,
        upload_dest=None,
        root_dir="."):
    """Generate the argparse options given the configuration file.

    Args:
        scanners: dict of scanners defined in config.json
        enumeration: dict of enumeration tools defined in config.json
        webtools: dict of webtools defined in config.json
        upload_dest: List of upload locations defined in config.json
        root_dir: Root directory of the config.json 

    Returns:
        parser given all available options provided at cli
    """

    if scanners is None:
        scanners = {}

    if enumeration is None:
        enumeration = {}

    if webtools is None:
        webtools = {}

    if upload_dest is None:
        upload_dest = {}

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
        help="Runs gather phase with tools under the webtools/scanners")

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

    ##########################
    # INSPECT
    ##########################

    parser_inspect = subparser.add_parser(
        'inspect',
        help="Run inspection phase against aggregated data "
        "Note: you must either supply a file containing a list of IP/Hostnames"
        " or the targeted domain must have a db under the dbs folder")

    for k in enumeration.keys():
        parser_inspect.add_argument(
            f"-{enumeration[k].get('short_name')}",
            f"--{k}",
            action='store_true',
            help=enumeration[k].get(
                'description',
                "No description provided"),
            default=False)

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
        "specified. By default this will be the path to the output folder")
    ##########################
    # REBUILD
    ##########################

    parser_rebuild = subparser.add_parser(
        'rebuild',
        help="Rebuild the database with additional files from previous runs")

    parser_rebuild.add_argument("domain",
                                type=str,
                                help="Domain to dump output of")

    parser_rebuild.add_argument(
        "-f",
        "--files",
        nargs="*",
        help="Additional files to supply outside of the config file")

    parser_rebuild.add_argument(
        "--headers",
        action="store_true",
        default=False,
        help="Rebuild with headers")

    ##########################
    # DUMPDB
    ##########################

    parser_dumpdb = subparser.add_parser(
        "dumpdb",
        help="Dump contents of database (ip,hostname,banners) to a text file")

    parser_dumpdb.add_argument("domain",
                               type=str,
                               help="Domain to show data for")
    ##########################
    # OUTPUT
    ##########################
    parser_output = subparser.add_parser(
        "output",
        help="Generate output in specified format. Contains all "
        "information from scans (images, headers, hostnames, ips)")

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

    return parser
