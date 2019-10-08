# -*- coding: utf8 -*-
""" Upload module

This module handles the uploading of files and images to a
supplied destination. This module contains one base class
from which all modules are derived so Dr.ROBOT may call and treat
all extended classes equally
"""
from abc import ABC, abstractmethod
import logging
import datetime
from os import walk, stat
from os.path import exists, abspath, isdir, isfile, basename
from mattermostdriver import Driver, exceptions
import slack

from robot_api.parse import join_abs

LOG = logging.getLogger(__name__)


class Forum(ABC):
    def __init__(self, **kwargs):
        """ABC class
        Args:
            **kwargs:
                api_key (str): api key for service
                username (str): username for service
                password (str): password for service
                url (str): url for service
                domain (str): domain for service

        """
        self.api_key = kwargs.get('api_key', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.url = kwargs.get('url', None)
        self.domain = kwargs.get('domain', None)

    @abstractmethod
    def upload(self, **kwargs):
        """Abstractmethod

        Method to be used in order to keep instantiation
        and execution simple in calling function
        Args:
            **kwargs: Any extra values needed for execution.

        Returns:

        """
        pass


class Mattermost(Forum):
    def __init__(self, **kwargs):
        """Initialize Mattermost class which extends Chat ABC
        Args:
            **kwargs (dict): args to pass to Chat ABC
            team_channel (str): required for posting to channel
            channel_name (str): required for posting to channel
        """
        super().__init__(**kwargs)
        self.inst = Driver({
            'url': self.url,
            'verify': False,
            'token': self.api_key,
            'username': self.username,
            'port': kwargs.get('port', 8065)
        })
        self.team_name = kwargs.get("team_name", None)
        self.channel_name = kwargs.get("channel_name", None)
        self.filepath = kwargs.get("filepath", None)

    def _upload_files(self, file_location, channel_id):
        file_ids = []
        for root, dirs, files in walk(file_location):
            for filename in files:
                # TODO add optional parameters for adjusting size. Implement
                # file splitting
                print(f"[...] Uploading {filename}")
                if stat(join_abs(root, filename)).st_size / 1024 ** 2 > 49:
                    print(f"[!]\tFile {filename} is to big, ignoring for now")
                    continue
                else:
                    file_ids += [
                        self.inst.files.upload_file(
                            channel_id=channel_id,
                            files={
                                'files': (
                                    filename,
                                    open(
                                        join_abs(
                                            root,
                                            filename),
                                        'rb'))})['file_infos'][0]['id']]
                    if len(file_ids) >= 5:
                        self.inst.posts.create_post(options={
                            'channel_id': channel_id,
                            'message': f"Recon Data {datetime.datetime.now()}",
                            'file_ids': file_ids
                        })
                        file_ids = []
        if len(file_ids) > 0:
            self.inst.posts.create_post(options={
                'channel_id': channel_id,
                'message': f"Recon Data {datetime.datetime.now()}",
                'file_ids': file_ids
            })

    def upload(self, **kwargs):
        """File upload

        Args:
            filepath (str): optional filepath to check for files to upload
        Returns:

        """
        print("[*] doing post message")
        try:
            self.inst.login()

            team_id = self.inst.teams.get_team_by_name(self.team_name)['id']
            channel_id = self.inst.channels.get_channel_by_name(
                channel_name=self.channel_name, team_id=team_id)['id']
        except exceptions.NoAccessTokenProvided as er:
            print(f"[!] NoAccessTokenProvided {er}")
            LOG.exception()
        except exceptions.InvalidOrMissingParameters as er:
            print(f"[!] InvalidOrMissingParameters {er}")
            LOG.exception()

        try:
            if isfile(self.filepath):
                file_ids = [
                    self.inst.files.upload_file(
                        channel_id=channel_id, files={
                            'files': (
                                basename(
                                    self.filepath), open(
                                    join_abs(
                                        self.filepath), 'rb'))})['file_infos'][0]['id']]

                self.inst.posts.create_post(options={
                    'channel_id': channel_id,
                    'message': f"Recon Data {datetime.datetime.now()}",
                    'file_ids': file_ids
                })

            elif isdir(self.filepath):
                file_location = abspath(self.filepath)

                self._upload_files(file_location, channel_id)

        except exceptions.ContentTooLarge:
            print(f"[!] ContentTooLarge in upload")
            LOG.exception()
        except exceptions.ResourceNotFound:
            print(f"[!] ResourceNotFound in upload")
            LOG.exception()
        except OSError:
            print(f"[!] File not found in upload")
            LOG.exception()


class Slack(Forum):
    def __init__(self, **kwargs):
        """Initialize Slack Client
        """
        super().__init__(**kwargs)

        self.channel_name = kwargs.get("channel_name", None)
        self.filepath = kwargs.get("filepath", None)

    def _get_files(self, file_location, max_filesize=50):
        """Generator to grab individual files for upload

        Args:
            file_location (str): Location of file(s) to upload
            max_filesize (int): Max allowed file size, in megabytes

        Returns:
            (Tuple) (filename, path to file)
        """
        if not exists(file_location):
            return None

        for root, _, files in walk(file_location):
            for filename in files:
                # TODO add optional parameters for adjusting size. Implement
                # file splitting
                print(f"[...] Uploading {filename}")
                if stat(join_abs(root, filename)).st_size / \
                        1024 ** 2 > max_filesize:
                    print(f"[!]\tFile {filename} is to big, ignoring for now")
                    continue
                else:
                    yield (filename, join_abs(root, filename))

    def upload(self, **kwargs):
        slack_client = slack.WebClient(self.api_key)

        # try:
        if isfile(self.filepath):
            slack_client.files_upload(
                channels=self.channel_name,
                file=self.filepath)

        elif isdir(self.filepath):
            print(self.filepath)
            if self.filepath and exists(abspath(self.filepath)):
                file_location = abspath(self.filepath)

            for filename, filepath in self._get_files(file_location):
                print(filename, filepath)
                slack_client.files_upload(
                    channels=self.channel_name,
                    file=filepath)
        # except Exception as ex:
        #    print(str(ex))
        #    LOG.exception(ex)
