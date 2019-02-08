# Changelog

```
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
```
## [1.1.0] - Feb 2019 

Current Release

### Added

* Changelog :)

* **Nmap-screenshot** docker container which allows one to use the nmap screenshot NSE script
* **Knockpy** docker container added
* **Eyewitness** docker container added
* **Amass** docker container added 
* ```---verbosity``` flag added as well as some useful log files that should contain any exceptions and debugging information respectively.

### Removed

* ```--domain``` option in favor of required domain. (Can't run tool without domain)

### Changed

* Changed default configuration options
  * ```network_mode``` allows us to pass host network to the docker daemon for ease of use
  * ```DOCKER``` or ```ANSIBLE ``` mode for Scanners and Inspection tools. Change for what mode you would like them to utilize
  * Ansible configuration optoins
    * ```"flags": "-e '$extra' -i configs/ansible_inventory",``` This option allows you to have a **dr_robot** specific ansible inventory.
    * ```variable_user``` option to specify what user Ansible should use to log in 
* Changed folders for docker containers to *docker_buildfiles*
* Tests to utilize Travis CI 

### Fixed

* Updated Eyewitness to use a specific commit hash. ```--headless``` flag was removed in favor of ```--web```
* Added user created and generated files to ```.gitignore```
* Fixed Duplication of IP and Hostnames in the aggregated section 
* Duplicated docker containers showing up. 
* Docker containers running pass **Keyboard Interrupt**

## [1.0.0] - Nov  2018

Initial Release






