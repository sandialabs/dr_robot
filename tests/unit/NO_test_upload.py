from src.upload import Mattermost
import unittest
import pytest
from unittest.mock import patch, mock_open, ANY
from os.path import join, abspath

class TestUploadMattermost(object):

    def test_init_nones(self):
        with pytest.raises(TypeError):
            Mattermost()
        assert True

    def test_init_with_only_url(self):
        attr = {
                'url' : "testurl"
                }
        Mattermost(**attr)
        assert True
"""
    @patch('src.upload.isdir', return_value=True)
    @patch('src.upload.Driver', autospec=True)
    @patch('src.upload.exists', return_value=True)
    def test_upload_files(self, mock_exists, mock_driver, mock_is_dir):
        mock_driver.login.return_value = True
        mock_driver.teams.get_team_by_name.return_value = {"id" : "test"}
        mock_driver.channels.get_channel_by_name.return_value = {"id" : "test_channel"}

        filepath = "testpath"
        domain = "test"

        driver = Mattermost(domain=domain)
        with patch('src.upload.Mattermost._upload_images') as m:
            m.return_value=True
            driver.upload(filepath=filepath)
            m.assert_called_with(abspath(filepath),  ANY)

    @patch('src.upload.Driver', autospec=True)
    @patch('src.upload.exists', return_value=True)
    def test_bad_filepath_handled(self, mock_exists, mock_driver):
        mock_driver.login.return_value = True
        mock_driver.teams.get_team_by_name.return_value = {"id": "test"}
        mock_driver.channels.get_channel_by_name.return_value = {"id": "test_channel"}


        filepath = "testtar.tar"
        domain = "test"

        driver = Mattermost(url="testurl")
        driver.upload(filepath=filepath)
        assert True

    @patch('src.upload.Driver', autospec=True)
    @patch('src.upload.exists', return_value=True)
    def test_upload_files_called_with_correct_params(self, mock_exists, mock_driver):
        mock_driver.login.return_value = True
        mock_driver.teams.get_team_by_name.return_value = {"id" : "test"}
        mock_driver.channels.get_channel_by_name.return_value = {"id" : "test_channel"}

        filepath = "testpath"
        domain = "test"

        driver = Mattermost(domain=domain)
        with patch('src.upload.open', new_callable=mock_open()) as m:
            driver.upload(filepath=filepath)
"""

