import docker
from os.path import isfile
from string import Template
import logging
import time
import json
from tqdm import tqdm

logger = logging.getLogger(__name__)
class Docker:
    def __init__(self, **kwargs):
        """

        Args:
            **kwargs:
                docker_options : (Dict) of arguments to build docker with (name, descriptions, output)
                active_config_path: (String) filepath of config to use for "active" configuration
                default_config_path: (String) filepath of config to use as default template.
                output_dir: (String) output directory to mount on docker

        Returns:

        """
        self._docker_options = kwargs.get('docker_options', None)

        self._default_config_path = kwargs.get('default_config_path', None)
        self._active_config_path = kwargs.get('active_config_path', None)

        self.verbose = kwargs.get('verbose', False)
        self.container = None
        self.status = None
        self.name = None
        self.network = "bridge"

        self.OUTPUT_DIR = kwargs.get('output_dir', None)

    def _print(self, msg):
        if self.verbose:
            print("[D] " + msg)
        logger.debug(msg)

    def kill(self):
        try:
            self.container.kill()
        except docker.errors.APIError as er:
            self._print("Error when trying to send kill signal to docker container.")

    def _init_config(self):
        """
        Creates active configuration from template with appropriate values replaced.
        Returns:

        Args:

        Returns:

        """
        if isfile(self._default_config_path):
            logger.info(f"Creating Dockerfile for {self._docker_options['name']}")
        elif not isfile(self._default_config_path):
            raise OSError('Default configuration file is not found, please fix')

        self.name = self._docker_options['name']
        self.network_mode = self._docker_options['network_mode']
        self._print(f"Making config with args:{json.dumps(self._docker_options, indent=4)}")

        with open(self._default_config_path, 'r') as cfg:
            t = Template(cfg.read())
        with open(self._active_config_path, 'w') as out:
            out.write(t.safe_substitute({k : v if v else '\'\'' for k,v in self._docker_options.items()}))

    def build(self):
        """
        Generates docker image from active_config

        Args:

        Returns:

        """
        client = docker.from_env()
        self._init_config()
        print(f"[*] Building Docker image: {self.name}")
        with open(self._active_config_path, 'rb') as f:
            _, _ = client.images.build(fileobj=f,
                    tag=f"{self._docker_options['docker_name']}:{self._docker_options['docker_name']}",
                    rm=True,
                    network_mode=self.network)
            self.status = "built"
        self._print(f"""Built with options:
                        -f {self._active_config_path}
                        -t {self._docker_options['docker_name']}:{self._docker_options['docker_name']}
                        --rm
                        --network {self.network}
                    """)

    def run(self):
        """
        Builds and runs docker container.

        Args:

        Returns:

        """
        print(f"[*] Running container {self._docker_options['docker_name']}")
        client = docker.from_env()

        volumes = self._docker_options.get("volumes", None)
        if volumes is None:
            volumes = {
                    self.OUTPUT_DIR: {
                        'bind': self._docker_options['output'],
                        'mode': 'rw'
                        }
                    }
        self.container = client.containers.run(image=f"{self._docker_options['docker_name']}:{self._docker_options['docker_name']}",
                dns=[self._docker_options.get('dns')] if self._docker_options.get('dns', None) else None,
                auto_remove=True,
                tty=True,
                detach=True,
                command=self._docker_options.get('command', None),
                ports=self._docker_options.get('ports', None),
                volumes=volumes)

        self.status = self.container.status

        self._print(f"mount point specified here: {volumes}")


    def update_status(self):
        """
        Thread watcher to update status of container

        Args:

        Returns:

        """
        try:
            with tqdm() as pbar:
                pbar.set_description(f"Docker container {self.name}, running...")
                while True:
                    self.container.reload()
                    time.sleep(5)
                    self.status = self.container.status
                    pbar.refresh()

        except docker.errors.NotFound:
            self._print(f"[*] Docker container {self._docker_options['docker_name']} exited")
            self.status = 'exited'
        except AttributeError:
            print("Container is None")
