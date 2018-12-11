import docker
from os.path import isfile
from string import Template
import logging
import time
from tqdm import tqdm
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
        self._active_config_path =kwargs.get('active_config_path', None)

        self.container = None
        self.status = None
        self.name = None
        self.OUTPUT_DIR = kwargs.get('output_dir', None)

    def _init_config(self):
        """
        Creates active configuration from template with appropriate values replaced.
        Returns:

        Args:

        Returns:

        """
        if isfile(self._default_config_path):
            logging.info(f"[*]Creating Dockerfile for {self._docker_options['name']}")
        elif not isfile(self._default_config_path):
            raise OSError('Default configuration file is not found, please fix')

        self.name = self._docker_options['name']

        logging.info(f"\t[.]With args:{self._docker_options}")
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
                    rm=True)
            self.status = "built"

    def run(self):
        """
        Builds and runs docker container.

        Args:

        Returns:

        """
        print(f"[*] Running container {self._docker_options['docker_name']}")
        client = docker.from_env()

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
                volumes=volumes)

        self.status = self.container.status



    def update_status(self):
        """
        Thread watcher to update status of container

        Args:

        Returns:

        """
        try:
            with tqdm() as pbar:
                pbar.set_description(f"{self.name} Progress")
                while True:
                    self.container.reload()
                    time.sleep(5)
                    self.status = self.container.status
                    pbar.update()

        except docker.errors.NotFound as er:
            print(f"[*] Docker container {self._docker_options['docker_name']} exited")
            self.status = 'exited'
        except AttributeError as er:
            print("Container is None")
