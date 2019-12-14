#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community"
}

DOCUMENTATION = '''
---
module: fortimgr_address
version_added: "2.3"
short_description: Manages Address resources and attributes
description:
  - Manages FortiManager Address configurations using jsonrpc API
author: Jacob McGill (@jmcgill298)
options:
  adom:
    description:
      - The ADOM the configuration should belong to.
    required: true
    type: str
  host:
    description:
      - The FortiManager's Address.
    required: true
    type: str
  lock:
    description:
      - True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM
    required: false
    default: True
    type: bool
  password:
    description:
      - The password associated with the username account.
    required: false
    type: str
  port:
    description:
      - The TCP port used to connect to the FortiManager if other than the default used by the transport
        method(http=80, https=443).
    required: false
    type: int
  provider:
    description:
      - Dictionary which acts as a collection of arguments used to define the characteristics
        of how to connect to the device.
      - Arguments hostname, username, and password must be specified in either provider or local param.
      - Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.
    required: false
    type: dict
  session_id:
    description:
      - The session_id of an established and active session
    required: false
    type: str
  state:
    description:
      - The desired state of the specified object.
      - absent will delete resource if it exists.
      - param_absent will remove passed params from the object config if necessary and possible.
      - present will update the configuration if needed.
    required: false
    default: present
    type: str
    choices: ["absent", "param_absent", "present"]
  use_ssl:
    description:
      - Determines whether to use HTTPS(True) or HTTP(False).
    required: false
    default: True
    type: bool
  username:
    description:
      - The username used to authenticate with the FortiManager.
    required: false
    type: str
  validate_certs:
    description:
      - Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)
    required: false
    default: False
    type: bool
  address_name:
    description:
      - The name of the Address object.
    required: true
    type: str
  address_type:
    description:
      - The type of address the Address object is.
    required: false
    type: str
    choices: ["ipmask", "iprange", "fqdn", "wildcard", "wildcard-fqdn"]
  allow_routing:
    description:
      - Determines if the address can be used in static routing configuration.
    required: false
    type: str
    options: ["enable", "disable"]
  associated_intfc:
    description:
      - The interface associated with the Address.
    required: false
    type: list
  color:
    description:
      - A tag that can be used to group objects
    required: false
    type: int
  comment:
    description:
      - A comment to add to the Address
    required: false
    type: str
  end_ip:
    description:
      - The last IP associated with an Address when the type is iprange.
    required: false
    type: str
  fqdn:
    description:
      - The fully qualified domain name associated with an Address when the type is fqdn.
    required: false
    type: str
  network_address: 
    description:
      - The network address to use when address_type is ipmask.
      - The network_mask param must be used in conjuction with network_address.
      - Alternatively, the subnet param can be used for cidr notation.
    required: false
    type: str
  network_mask: 
    description:
      - The netmask to use when address_type is ipmask.
      - The network_address param must be used in conjuction with network_mask.
      - Alternatively, the subnet param can be used for cidr notation.
    required: false
    type: str
  start_ip:
    description:
      - The first IP associated with an Address when the type is iprange.
    required: false
    type: str
  subnet:
    description:
      - The subnet associated with an Address when the type is ipmask.
      - This supports sending a string as cidr notation or a two element list that
        would be returned from getting existing address objects.
      - Alternatively, the network_address and network_mask params can be used.
    required: false
    type: list
  wildcard:
    description:
      - The wildcard associated with an Address when the type is wildcard.
      - This supports sending a string as cidr notation or a two element list that
        would be returned from getting existing address objects.
      - Alternatively, the wildcard_address and wildcard_mask params can be used.
    required: false
    type: list
  wildcard_address:
    description:
      - The wildcard address to use when address_type is wildcard.
      - The wildcard_mask param must be used in conjunction with the wildcard_address.
      - Alternatively, the wildcard param can be used for cidr notation.
    required: false
    type: str
  wildcard_fqdn:
    description:
      - The wildcard FQDN associated with an Address when the type is wildcard-fqdn.
    required: false
    type: str
  wildcard_mask:
    description:
      - The wildcard mask to use when address_type is wildcard.
      - The wildcard_address param must be used in conjuction with the wildcard_mask
      - Alternatively, the wildcard param can be used for cidr notation.
    required: false
    type: str
'''

EXAMPLES = '''
- name: Add iprange Address
  fortimanager_address:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    address_name: "server01"
    address_type: "iprange"
    associated_intfc: "any"
    comment: "App01 Server"
    start_ip: "10.10.10.21"
    end_ip: "10.10.10.26"
- name: Modify iprange Address range
  fortimanager_address:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    address_name: "server01"
    address_type: "iprange"
    associated_intfc: "any"
    comment: "App01 Server"
    start_ip: "10.10.10.21"
    end_ip: "10.10.10.32"
- name: Add ipmask Address
  fortimanager_address:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    port: 8443
    validate_certs: True
    state: "present"
    address_name: "server02"
    address_type: "iprange"
    subnet: "10.20.30.0/24"
- name: Add ipmask Address
  fortimanager_address:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    port: 8443
    validate_certs: True
    state: "present"
    address_name: "server02"
    address_type: "iprange"
    network_address: "10.20.31.0"
    mask: "255.255.255.0"
- name: Delete Address
  fortimanager_address:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    use_ssl: False
    adom: "lab"
    address_name: "server02"
    state: "absent"
'''

RETURN = '''
existing:
    description: The existing configuration for the Address (uses address_name) before the task executed.
    returned: always
    type: dict
    sample: {"allow-routing": "disable", "associated-interface": ["any"], "color": 0,
             "comment": "App01 Server", "end-ip": "10.10.10.26", "name": "Server01", "start-ip": "10.10.10.21",
             "type": "iprange", "uuid": "353259f6-3caf-51e7-ad56-13759b17ff46", "visibility": "enable"}
config:
    description: The configuration that was pushed to the FortiManager.
    returned: always
    type: dict
    sample: {"end-ip": "10.10.10.32", "name": "Server01"}
locked:
    description: The status of the ADOM lock command
    returned: When lock set to True
    type: bool
    sample: True
saved:
    description: The status of the ADOM save command
    returned: When lock set to True
    type: bool
    sample: True
unlocked:
    description: The status of the ADOM unlock command
    returned: When lock set to True
    type: bool
    sample: True
'''

import time

import requests
from ansible import __version__ as ansible_version
if float(ansible_version[:3]) < 2.4:
    raise ImportError("Ansible versions below 2.4 are not supported")
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.six import string_types


requests.packages.urllib3.disable_warnings()


class FortiManager(object):
    """
    This is the Base Class for FortiManager modules. All methods common across several FortiManager Classes should be
    defined here and inherited by the sub-class.
    """

    def __init__(self, host, user, passw, use_ssl=True, verify=False, adom="", package="", api_endpoint="", **kwargs):
        """
        :param host: Type str.
                     The IP or resolvable hostname of the FortiManager.
        :param user: Type str.
                     The username used to authenticate with the FortiManager.
        :param passw: Type str.
                      The password associated with the user account.
        :param use_ssl: Type bool.
                        The default is True, which uses HTTPS instead of HTTP.
        :param verify: Type bool.
                       The default is False, which does not verify the certificate against the list of trusted
                       certificates.
        :param adom: Type str.
                     The FortiManager ADOM which the configuration should belong to.
        :param package: Type str.
                        The FortiManager policy package that should be used.
        :param api_endpoint: Type str.
                             The API endpoint used for a particular configuration section.
        :param kwargs: Type dict. Currently supports port.
        :param headers: Type dict.
                        The headers to include in HTTP requests.
        :param port: Type str.
                     Passing the port parameter will override the default HTTP(S) port when making requests.
        """
        self.host = host
        self.user = user
        self.passw = passw
        self.verify = verify
        self.api_endpoint = api_endpoint
        self.adom = adom
        self.package = package
        self.dvmdb_url = "/dvmdb/adom/{}/".format(self._escape_params_url(self.adom))
        self.obj_url = "/pm/config/adom/{}/obj/firewall/{}".format(self._escape_params_url(self.adom),
                                                                   self.api_endpoint)
        self.pkg_url = "/pm/config/adom/{}/pkg/{}/firewall/{}".format(self._escape_params_url(self.adom), self.package,
                                                                      self.api_endpoint)
        self.wsp_url = "/dvmdb/adom/{}/workspace/".format(self._escape_params_url(self.adom))
        self.headers = {"Content-Type": "application/json"}
        if "port" not in kwargs:
            self.port = ""
        else:
            self.port = ":{}".format(kwargs["port"])

        if use_ssl:
            self.url = "https://{fw}{port}/jsonrpc".format(fw=self.host, port=self.port)
        else:
            self.url = "http://{fw}{port}/jsonrpc".format(fw=self.host, port=self.port)

    def add_config(self, new_config):
        """
        This method is used to submit a configuration request to the FortiManager. Only the object configuration details
        need to be provided; all other parameters that make up the API request body will be handled by the method.

        :param new_config: Type list.
                           The "data" portion of the configuration to be submitted to the FortiManager.
        :return: The response from the API request to add the configuration.
        """
        body = {"method": "add", "params": [{"url": self.obj_url, "data": new_config, "session": self.session}]}
        response = self.make_request(body)

        return response

    @staticmethod
    def cidr_to_network(network):
        """
        Method is used to convert a network address in CIDR notation to a list with address and mask.
  
        :param network: Type str.
                        The network address in CIDR notation.
  
        :return: A list with address and mask in that order.
        """
        cidr_mapping = {
                "0": "0.0.0.0",
                "1": "128.0.0.0",
                "2": "192.0.0.0",
                "3": "224.0.0.0",
                "4": "240.0.0.0",
                "5": "248.0.0.0",
                "6": "252.0.0.0",
                "7": "254.0.0.0",
                "8": "255.0.0.0",
                "9": "255.128.0.0",
                "10": "255.192.0.0",
                "11": "255.224.0.0",
                "12": "255.240.0.0",
                "13": "255.248.0.0",
                "14": "255.252.0.0",
                "15": "255.254.0.0",
                "16": "255.255.0.0",
                "17": "255.255.128.0",
                "18": "255.255.192.0",
                "19": "255.255.224.0",
                "20": "255.255.240.0",
                "21": "255.255.248.0",
                "22": "255.255.252.0",
                "23": "255.255.254.0",
                "24": "255.255.255.0",
                "25": "255.255.255.128",
                "26": "255.255.255.192",
                "27": "255.255.255.224",
                "28": "255.255.255.240",
                "29": "255.255.255.248",
                "30": "255.255.255.252",
                "31": "255.255.255.254",
                "32": "255.255.255.255"
            }
  
        if "/" in network:
            network_address = network.split("/")
            mask = network_address.pop()
            
            if mask and int(mask) in range(0, 33):
                network_address.append(cidr_mapping[mask])
            else:
                network_address = []
        else:
            network_address = []
  
        return network_address

    @staticmethod
    def cidr_to_wildcard(wildcard):
        """
        Method is used to convert a wildcard address in CIDR notation to a list with address and mask.
  
        :param wildcard: Type str.
                        The wildcard address in CIDR notation.
  
        :return: A list with address and mask in that order.
        """
        cidr_mapping = {
            "0": "255.255.255.255",
            "1": "127.255.255.255",
            "2": "63.255.255.255",
            "3": "31.255.255.255",
            "4": "15.255.255.255",
            "5": "7.255.255.255",
            "6": "3.255.255.255",
            "7": "1.255.255.255",
            "8": "0.255.255.255",
            "9": "0.127.255.255",
            "10": "0.63.255.255",
            "11": "0.31.255.255",
            "12": "0.15.255.255",
            "13": "0.7.255.255",
            "14": "0.3.255.255",
            "15": "0.1.255.255",
            "16": "0.0.255.255",
            "17": "0.0.127.255",
            "18": "0.0.63.255",
            "19": "0.0.31.255",
            "20": "0.0.15.255",
            "21": "0.0.7.255",
            "22": "0.0.3.255",
            "23": "0.0.1.255",
            "24": "0.0.0.255",
            "25": "0.0.0.127",
            "26": "0.0.0.63",
            "27": "0.0.0.31",
            "28": "0.0.0.15",
            "29": "0.0.0.7",
            "30": "0.0.0.3",
            "31": "0.0.0.1",
            "32": "0.0.0.0"
            }
  
        if "/" in wildcard:
            wildcard_address = wildcard.split("/")
            mask = wildcard_address.pop()

            if mask and int(mask) in range(0, 33):
                wildcard_address.append(cidr_mapping[mask])
            else:
                wildcard_address = []
        else:
            wildcard_address = []
  
        return wildcard_address

    def config_absent(self, module, proposed, existing):
        """
        This function is used to determine the appropriate configuration to remove from the FortiManager when the
        "state" parameter is set to "absent" and to collect the dictionary data that will be returned by the Ansible
        Module.

        :param module: The AnsibleModule instance.
        :param proposed: The proposed config to send to the FortiManager.
        :param existing: The existing configuration for the item on the FortiManager (using the "name" key to get item).
        :return: A dictionary containing the module exit values.
        """
        changed = False
        config = {}

        if existing:
            # check if proposed is to remove a dynamic_mapping
            if "dynamic_mapping" not in proposed:
                config = self.config_delete(module, proposed["name"])
                changed = True
            else:
                diff = self.get_diff_mappings(proposed, existing)
                if diff:
                    config = self.config_update(module, diff)
                    changed = True

        return {"changed": changed, "config": config, "existing": existing}

    def config_delete(self, module, name):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "absent" and only the
        name is provided as input into the Ansible Module. The config_lock is used to lock the configuration if the lock
        param is set to True. The config_response method is used to handle the logic from the response to delete the
        object.

        :param module: The Ansible Module instance started by the task.
        :param name: Type str.
                     The name of the object to be removed from the FortiManager.
        :return: A dictionary that corresponds to the configuration that was sent in the request body to the
                 FortiManager API. This dict will map to the "config" key returned by the Ansible Module.
        """
        # lock config if set and module not in check mode
        if module.params["lock"] and not module.check_mode:
            self.config_lock(module)

        # configure if not in check mode
        if not module.check_mode:
            response = self.delete_config(name)
            self.config_response(module, response.json(), module.params["lock"])

        return {"method": "delete", "params": [{"url": self.obj_url + "/{}".format(self._escape_params_url(name))}]}

    def config_lock(self, module, msg="Unable to Lock the Configuration; Validate the ADOM is not Currently Locked."):
        """
        This method is used to handle the logic for Ansible modules for locking the ADOM when "lock" is set to True. The
        lock method is used to make the request to the FortiManager.

        :param module: The Ansible Module instance started by the task.
        :param msg: Type str.
                    A message for the module to return upon failure.
        :return: True if lock successful.
        """
        lock_status = self.lock()
        if lock_status["result"][0]["status"]["code"] != 0:
            # try to logout before failing
            self.logout()
            module.fail_json(msg=msg, locked=False, saved=False, unlocked=False, fortimanager_response=lock_status)

        return True

    def config_new(self, module, new_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and their is
        not currently an object of the same type with the same name. The config_lock is used to lock the configuration
        if the lock param is set to True. The config_response method is used to handle the logic from the response to
        create the object.

        :param module: The Ansible Module instance started by the task.
        :param new_config: Type dict.
                           The config dictionary with the objects configuration to send to the FortiManager API. This
                           corresponds to the "data" portion of the request body.
        :return: A dictionary that corresponds to the configuration that was sent in the request body to the
                 FortiManager API. This dict will map to the "config" key returned by the Ansible Module.
        """
        # lock config if set and module not in check mode
        if module.params["lock"] and not module.check_mode:
            self.config_lock(module)

        # configure if not in check mode
        if not module.check_mode:
            response = self.add_config(new_config)
            self.config_response(module, response.json(), module.params["lock"])

        return {"method": "add", "params": [{"url": self.obj_url, "data": new_config}]}

    def config_param_absent(self, module, proposed, existing):
        """
        This function is used to determine the appropriate configuration to remove from the FortiManager when the
        "state" parameter is set to "param_absent" and to collect the dictionary data that will be returned by the
        Ansible Module.

        :param module: The AnsibleModule instance.
        :param proposed: The proposed config to send to the FortiManager.
        :param existing: The existing configuration for the item on the FortiManager (using the "name" key to get item).
        :return: A dictionary containing the module exit values.
        """
        changed = False
        config = {}

        if existing:
            # determine what diff method to call
            if "dynamic_mapping" not in proposed:
                diff = self.get_diff_remove(proposed, existing)
            else:
                diff = self.get_diff_remove_map(proposed, existing)

            if diff:
                config = self.config_update(module, diff)
                changed = True

        return {"changed": changed, "config": config, "existing": existing}

    def config_present(self, module, proposed, existing):
        """
        This function is used to determine the appropriate configuration to send to the FortiManager API when the
        "state" parameter is set to "present" and to collect the dictionary data that will be returned by the Ansible
        Module.

        :param module: The AnsibleModule instance.
        :param proposed: The proposed config to send to the FortiManager.
        :param existing: The existing configuration for the item on the FortiManager (using the "name" key to get item).
        :return: A dictionary containing the module exit values.
        """
        changed = False
        config = {}

        if not existing:
            config = self.config_new(module, proposed)
            changed = True
        else:
            # determine what diff method to call
            if "dynamic_mapping" not in proposed:
                diff = self.get_diff_add(proposed, existing)
            else:
                diff = self.get_diff_add_map(proposed, existing)

            if diff:
                config = self.config_update(module, diff)
                changed = True

        return {"changed": changed, "config": config, "existing": existing}

    def config_response(self, module, json_response, lock):
        """
        This method is to handle the logic for Ansible modules for handling the config request's response. If the lock
        parameter is set to true and the config was successful, the config_save and config_unlock methods are used to
        save the configuration and unlock the ADOM session. If the lock parameter is set to true and the config was
        unsuccessful, the config_unlock method is used to attempt to unlock the ADOM session before failing. If the lock
        parameter is set to False and the configuration is unsuccessful, the module will fail with the json response.

        :param module: The Ansible Module instance started by the task.
        :param json_response: Type dict.
                              The json response from the requests module's configuration request.
        :param lock: Type bool.
                     The setting of the configuration lock. True means locking mechanism is in place.
        :return: True if configuration was saved and the adom unlocked.
        """
        # save if config successful and session locked
        status_code = json_response["result"][0]["status"]["code"]
        if status_code == 0 and lock:
            self.config_save(module)
            self.config_unlock(module)
        # attempt to unlock if config unsuccessful
        elif status_code != 0 and lock:
            self.config_unlock(module, msg=json_response, saved=False)
            module.fail_json(msg="Unable to Apply Config", locked=True, saved=False, unlocked=True, fortimanager_response=json_response)
        # fail if not using lock mode and config unsuccessful
        elif status_code != 0:
            module.fail_json(msg="Unable to Apply Config", fortimanager_response=json_response)

    def config_save(self, module, msg="Unable to Save Config, Successfully Unlocked"):
        """
        This method is used to handle the logic for Ansible modules for saving a config when "lock" is set to True. The
        save method is used to make the request to the FortiManager. If the save is unsuccessful, the module will use
        the config_unlock method to attempt to unlock before failing.

        :param module: The Ansible Module instance started by the task.
        :param msg: Type str.
                    A message for the module to return upon failure.
        :return: True if the configuration was saved successfully.
        """
        save_status = self.save()
        if save_status["result"][0]["status"]["code"] != 0:
            self.config_unlock(module, "Config Updated, but Unable to Save or Unlock", False)
            # try to logout before failing
            self.logout()
            module.fail_json(msg=msg, locked=True, saved=False, unlocked=True, fortimanager_response=save_status)

        return True

    def config_unlock(self, module, msg="Config Saved, but Unable to Unlock", saved=True):
        """
        This method is used to handle the logic for Ansible modules for locking the ADOM when "lock" is set to True. The
        config_lock is used to lock the configuration if the lock param is set to True. The unlock method is used to
        make the request to the FortiManager.

        :param module: The Ansible Module instance started by the task.
        :param msg: Type str.
                    A message for the module to return upon failure.
        :param saved: Type bool.
                      The save status of the configuration.
        :return: True if unlock successful.
        """
        unlock_status = self.unlock()
        if unlock_status["result"][0]["status"]["code"] != 0:
            # try to logout before failing
            self.logout()
            module.fail_json(msg=msg, locked=True, saved=saved, unlocked=False, fortimanager_response=unlock_status)

        return True

    def config_update(self, module, update_config):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "present" and their is
        not currently an object of the same type with the same name. The config_response method is used to handle the
        logic from the response to update the object.

        :param module: The Ansible Module instance started by the task.
        :param update_config: Type dict.
                              The config dictionary with the objects configuration to send to the FortiManager API. Only
                              the keys that have updates need to be included. This corresponds to the "data" portion of
                              the request body.
        :return: A dictionary that corresponds to the configuration that was sent in the request body to the
                 FortiManager API. This dict will map to the "config" key returned by the Ansible Module.
        """
        # lock config if set and module not in check mode
        if module.params["lock"] and not module.check_mode:
            self.config_lock(module)

        # configure if not in check mode
        if not module.check_mode:
            response = self.update_config(update_config)
            self.config_response(module, response.json(), module.params["lock"])

        return {"method": "update", "params": [{"url": self.obj_url, "data": update_config}]}

    def create_revision(self, proposed):
        """
        This method is used to create an ADOM revision on the FortiManager. The make_request method is used to make the
        API request to add the revision.

        :param proposed: Type list.
                         The data portion of the API Request.
        :return: The json response data from the request to make a revision.
        """
        rev_url = "{}revision".format(self.dvmdb_url)
        body = {"method": "add", "params": [{"url": rev_url, "data": proposed}], "session": self.session}
        response = self.make_request(body).json()

        return response

    def delete_config(self, name):
        """
        This method is used to submit a configuration request to delete an object from the FortiManager.

        :param name: Type str.
                     The name of the object to be removed from the FortiManager.
        :return: The response from the API request to delete the configuration.
        """
        item_url = self.obj_url + "/{}".format(self._escape_params_url(name))
        body = {"method": "delete", "params": [{"url": item_url}], "session": self.session}
        response = self.make_request(body)

        return response

    def delete_revision(self, version):
        """
        This method is used to delete an ADOM revision from the FortiManager. The make_request method is used to submit
        the request to the FortiManager.

        :param version: Type str.
                        The version number corresponding to the revision to delete.
        :return: The json response data from the request to delete the revision.
        """
        rev_url = "{}revision/{}".format(self.dvmdb_url, version)
        body = {"method": "delete", "params": [{"url": rev_url}], "session": self.session}
        response = self.make_request(body).json()

        return response

    def get_adom_fields(self, adom, fields=[]):
        """
        This method is used to get all adoms currently configured on the FortiManager. A list of fields can be passed
        in to limit the scope of what data is returned for the ADOM.

        :param adom: Type str.
                     The name of the ADOM to retrieve the configuration for.
        :param fields: Type list.
                       A list of fields to retrieve for the ADOM.
        :return: The json response from the request to retrieve the configured ADOM. An empty list is returned if the
                 request does not return any data.
        """
        body = dict(method="get", params=[dict(url="/dvmdb/adom", filter=["name", "==", adom], fields=fields)],
                    verbose=1, session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_adoms_fields(self, fields=[]):
        """
        This method is used to get all adoms currently configured on the FortiManager. A list of fields can be passed
        in to limit the scope of what data is returned per ADOM.

        :param fields: Type list.
                       A list of fields to retrieve for each ADOM.
        :return: The json response from the request to retrieve the configured ADOMs. An empty list is returned if the
                 request does not return any data.
        """
        body = dict(method="get", params=[dict(url="/dvmdb/adom", fields=fields)], verbose=1, session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_all(self):
        """
        This method is used to get all objects currently configured on the FortiManager for the ADOM and API Endpoint.

        :return: The list of configuration dictionaries for each object. An empty list is returned if the request does
                 not return any data.
        """
        body = {"method": "get", "params": [{"url": self.obj_url}], "verbose": 1, "session": self.session}
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_all_custom(self, url):
        """
        This method is used to get all objects currently configured for the specified URL.

        :param url: Type str.
                    The URL of the endpoint to retrieve configurations from.
        :return: The list of configuration dictionaries for each object. An empty list is returned if the request does
                 not return any data.
        """
        body = dict(method="get", params=[{"url": url}], verbose=1, session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_all_fields(self, fields):
        """
        This method is used to get all objects currently configured on the FortiManager for the ADOM and API Endpoint.
        The configuration fields retrieved are limited to the list defined in the fields variable.

        :param fields: Type list.
                       The list of fields to return for each object.
        :return: The list of configuration dictionaries for each object. An empty list is returned if the request does
                 not return any data.
        """
        params = [{"url": self.obj_url, "fields": fields}]
        body = {"method": "get", "params": params, "verbose": 1, "session": self.session}
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_all_packages(self, adom):
        """
        This method is used to get all packages associated with an ADOM.

        :param adom: Type str.
                     The ADOM from which to retrieve packages.
        :return: A list of package names associated with the ADOM. If the ADOM is not found or does not have any
                 packages, then an empty list is returned.
        """
        body = dict(method="get", params=[{"url": "/pm/pkg/adom/{}".format(adom)}], verbose=1, session=self.session)
        response = self.make_request(body)
        package_dicts = response.json().get("result", [{}])[0].get("data", [])

        packages = []
        for pkg in package_dicts:
            if pkg.get("name"):
                packages.append(pkg["name"])

        return packages

    def get_device_config(self, device, vdom, config_url, fields=[]):
        """
        This method is used to retrieve the configurations from the managed device.

        :param device: Type str.
                       The device to retrieve the configuration from.
        :param vdom: Type str.
                     The vdom to retrieve the configuration from.
        :param config_url: Type str.
                           The url associated with the configuration section to retrieve.
        :param fields: Type list.
                       A list of configuration fields to retrieve from the device.
        :return: The json response from the request to retrieve the static routes. An empty list is returned if the
                 request does not return any data.
        """
        config_url = "/pm/config/device/{}/vdom/{}/{}".format(device, vdom, config_url)
        body = dict(method="get", params=[dict(url=config_url, fields=fields)], verbose=1, session=self.session)
        response = self.make_request(body).json()["result"][0].get("data", [])

        if not response:
            response = []

        return response

    def get_device_fields(self, device, fields=[]):
        """
        This method is used to retrieve information about a managed device from FortiManager. A list of fields can be
        passed int o limit the scope of what data is returned for the device.

        :param device: Type str.
                       The name of the device to retrieve information for.
        :param fields: Type list.
                       A list of fields to retrieve for the device.
        :return: The json response from the request to retrieve the configured device. An empty list is returned if the
                 request does not return any data.
        """
        body = dict(method="get", params=[dict(url="/dvmdb/device", filter=["name", "==", device], fields=fields)],
                    verbose=1, session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_device_ha(self, device):
        """
        This method is used to get HA information for a device managed by FortiManager.

        :param device: The device to retrieve the HA status from.
        :return: The json response from the request to retrieve the HA status. An empty list is returned if the request
                 does not return any data.
        """
        if not self.adom:
            dev_url = "/dvmdb/device/{}/ha_slave".format(self._escape_params_url(self.adom), device)
        else:
            dev_url = "{}device/{}/ha_slave".format(self.dvmdb_url, device)
        body = dict(method="get", params=[dict(url=dev_url)], verbose=1, session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_device_vdoms(self, device):
        """
        This method is used to retrieve the VDOMs associated with a device managed by FortiManager.

        :param device: The device to retrieve the HA status from.
        :return: The json response from the request to retrieve the HA status. An empty list is returned if the request
                 does not return any data.
        """
        if not self.adom:
            dev_url = "/dvmdb/device/{}/vdom".format(device)
        else:
            dev_url = "{}device/{}/vdom".format(self.dvmdb_url, device)
        body = dict(method="get", params=[dict(url=dev_url)], verbose=1, session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_devices_fields(self, fields=[], dev_filter=[]):
        """
        This method is used to retrieve information about a managed devices from FortiManager. A list of fields can be
        passed int o limit the scope of what data is returned for each the device.

        :param fields: Type list.
                       A list of fields to retrieve for the device.
        :param dev_filter: Type list.
                       A list matching to a filter parameter for API requests [<key>, <operator>, <value>].
        :return: The json response from the request to retrieve the configured devices. An empty list is returned if the
                 request does not return any data.
        """
        if not self.adom:
            dev_url = "/dvmdb/device"
        else:
            dev_url = "{}device".format(self.dvmdb_url)

        body = dict(method="get", params=[dict(url=dev_url, fields=fields, filter=dev_filter)], verbose=1,
                    session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    @staticmethod
    def get_diff_add(proposed, existing):
        """
        This method is used to get the difference between two configurations when the "proposed" configuration is a dict
        of configuration items that should exist in the configuration for the object in the FortiManager. Either the
        get_item or get_item_fields methods should be used to obtain the "existing" variable; if either of those methods
        return an empty dict, then you should use the add_config method to add the new object.

        :param proposed: Type dict.
                         The configuration that should not exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs configuration removed.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        config = {}
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            if existing_field and proposed_field != existing_field:
                if isinstance(existing_field, list):
                    proposed_field = set(proposed_field)
                    if not proposed_field.issubset(existing_field):
                        config[field] = list(proposed_field.union(existing_field))
                elif isinstance(existing_field, dict):
                    config[field] = dict(set(proposed_field.items()).union(existing_field.items()))
                elif isinstance(existing_field, int) or isinstance(existing_field, string_types):
                    config[field] = proposed_field
            elif field not in existing:
                config[field] = proposed_field

        if config:
            config["name"] = proposed["name"]

        return config

    @staticmethod
    def get_diff_add_map(proposed, existing):
        """
        This method is used to get the difference between two dynamic_mapping configurations when the "proposed"
        configuration is a dict of configuration items that should exist in the configuration for the object in the
        FortiManager. Either the get_item or get_item_fields method should be used to obtain the "existing" variable; if
        either of those methods return an empty dict, then you should use the add_config method to add the new object.

        :param proposed: Type dict.
                         The configuration that should exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs its configuration modified.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        name = proposed.get("name")
        proposed_map = proposed.get("dynamic_mapping")[0]
        proposed_scope = proposed_map.pop("_scope")[0]
        existing_map = existing.get("dynamic_mapping")
        config = dict(name=name, dynamic_mapping=[])
        present = False

        # check if proposed mapping already exists and make necessary updates to config
        if existing_map:
            for mapping in existing_map:
                if proposed_scope in mapping["_scope"]:
                    present = True
                    updated_map = {}
                    for field in proposed_map.keys():
                        proposed_field = proposed_map[field]
                        existing_field = mapping.get(field)
                        # only consider relevant fields that have a difference
                        if existing_field and proposed_field != existing_field:
                            if isinstance(existing_field, list):
                                proposed_field = set(proposed_field)
                                if not proposed_field.issubset(existing_field):
                                    updated_map[field] = list(proposed_field.union(existing_field))
                            elif isinstance(existing_field, dict):
                                updated_map[field] = dict(set(proposed_field.items()).union(existing_field.items()))
                            elif isinstance(existing_field, int) or isinstance(existing_field, string_types):
                                updated_map[field] = proposed_field
                        elif field not in mapping:
                            updated_map[field] = proposed_field
                    # config update if dynamic_mapping dict has any keys, need to append _scope key
                    if updated_map:
                        # add scope to updated_map and append the config to the list of other mappings
                        updated_map["_scope"] = mapping["_scope"]
                        config["dynamic_mapping"].append(updated_map)
                    else:
                        # set config to a null dictionary if dynamic mappings are identical and exit loop
                        config = {}
                        break
                else:
                    # keep unrelated mapping in diff so that diff can be used to update FortiManager
                    config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

        # add mapping to config if it does not currently exist
        if not present:
            config = proposed
            config["dynamic_mapping"][0]["_scope"] = [proposed_scope]
            if existing_map:
                for mapping in existing_map:
                    config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

        return config

    @staticmethod
    def get_diff_mappings(proposed, existing):
        """
        This method is to get the diff of just the mapped Fortigate devices.
        :param proposed: Type dict.
                         The configuration that should not exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs configuration removed.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        config = dict(name=proposed["name"], dynamic_mapping=[])
        existing_map = existing.get("dynamic_mapping")
        if existing_map:
            for mapping in existing_map:
                if mapping["_scope"] != proposed["dynamic_mapping"][0]["_scope"]:
                    config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

            if len(config["dynamic_mapping"]) == len(existing_map):
                config = {}
        else:
            config = {}

        return config

    @staticmethod
    def get_diff_remove(proposed, existing):
        """
        This method is used to get the difference between two configurations when the "proposed" configuration is a dict
        of configuration items that should not exist in the configuration for the object in the FortiManager. Either the
        get_item or get_item_fields methods should be used to obtain the "existing" variable; if either of those methods
        return an empty dict, then the object does not exist and there is no configuration to remove.

        :param proposed: Type dict.
                         The configuration that should not exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs configuration removed.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        config = {}
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            if existing_field and isinstance(existing_field, list):
                existing_field = set(existing_field)
                diff = existing_field.difference(proposed_field)
                if diff != existing_field:
                    config[field] = list(diff)
            elif existing_field and isinstance(existing_field, dict):
                diff = dict(set(proposed.items()).difference(existing.items()))
                if diff != existing_field:
                    config[field] = diff

        if config:
            config["name"] = proposed["name"]

        return config

    @staticmethod
    def get_diff_remove_map(proposed, existing):
        """
        This method is used to get the difference between two dynamic_mapping configurations when the "proposed"
        configuration is a dict of configuration items that should not exist in the configuration for the object in the
        FortiManager. Either the get_item or get_item_fields method should be used to obtain the "existing" variable; if
        either of those methods return an empty dict, then the object does not exist and there is no configuration to
        remove.

        :param proposed: Type dict.
                         The configuration that should not exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs configuration removed.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        name = proposed.get("name")
        proposed_map = proposed.get("dynamic_mapping")[0]
        proposed_scope = proposed_map.pop("_scope")[0]
        existing_map = existing.get("dynamic_mapping")
        config = dict(name=name, dynamic_mapping=[])
        present = False

        # check if proposed mapping already exists and make necessary updates to config
        if existing_map:
            for mapping in existing_map:
                if proposed_scope in mapping["_scope"]:
                    present = True
                    updated_map = {}
                    for field in proposed_map.keys():
                        proposed_field = proposed_map[field]
                        existing_field = mapping.get(field)
                        if existing_field and isinstance(existing_field, list):
                            existing_field = set(existing_field)
                            diff = existing_field.difference(proposed_field)
                            if diff != existing_field:
                                updated_map[field] = list(diff)
                        elif existing_field and isinstance(existing_field, dict):
                            diff = dict(set(proposed_map.items()).difference(mapping.items()))
                            if diff != existing_field:
                                updated_map[field] = diff
                    # config update if dynamic_mapping dict has any keys, need to append _scope key
                    if updated_map:
                        # add scope to updated_map and append the config to the list of other mappings
                        updated_map["_scope"] = mapping["_scope"]
                        config["dynamic_mapping"].append(updated_map)
                    else:
                        # remove dynamic mapping from proposed if proposed matches existing config
                        config = {}
                        break
                else:
                    # keep unrelated mapping in diff so that diff can be used to update FortiManager
                    config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

        # set config to empty dict if mapping was not found, representing no change
        if not present:
            config = {}

        return config

    def get_ha(self):
        """
        This method is used to retrieve the HA status of the FortiManager.

        :return: The json response data from the request to retrieve the HA status.
        """
        body = dict(method="get", params=[dict(url="/cli/global/system/ha")], verbose=1, session=self.session)
        response = self.make_request(body).json()["result"][0].get("data", [])

        return response

    def get_install_status(self, name):
        """
        This method is used to get the config and connection status of the specified FortiGate.

        :param name: Type str.
                     The name of the FortiGate from which to retrieve the current status.
        :return: The json response data from the request to retrieve device status.
        """
        params = [{"url": "{}device".format(self.dvmdb_url), "filter": ["name", "==", name],
                   "fields": ["name", "conf_status", "conn_status"]}]
        body = {"method": "get", "params": params, "verbose": 1, "session": self.session}
        response = self.make_request(body).json()

        return response

    def get_item(self, name):
        """
        This method is used to get a specific object currently configured on the FortiManager for the ADOM and API
        Endpoint.

        :param name: Type str.
                     The name of the object to retrieve.
        :return: The configuration dictionary for the object. An empty dict is returned if the request does
                 not return any data.
        """
        item_url = self.obj_url + "/{}".format(self._escape_params_url(name))
        body = {"method": "get", "params": [{"url": item_url}], "verbose": 1, "session": self.session}
        response = self.make_request(body)

        return response.json()["result"][0].get("data", {})

    def get_item_fields(self, name, fields):
        """
        This method is used to get a specific object currently configured on the FortiManager for the ADOM and API
        Endpoint. The configuration fields retrieved are limited to the list defined in the fields variable.

        :param name: Type str.
                     The name of the object to retrieve.
        :param fields: Type list.
                       The list of fields to return for each object.
        :return: The list of configuration dictionaries for each object. An empty list is returned if the request does
                 not return any data.
        """
        params = [{"url": self.obj_url, "filter": ["name", "==", name], "fields": fields}]
        body = {"method": "get", "params": params, "verbose": 1, "session": self.session}
        response = self.make_request(body)
        response_data = response.json()["result"][0].get("data", [{}])

        if response_data:
            return response_data[0]
        else:
            return {}

    def get_revision(self, name=""):
        """
        This method is used to retrieve ADOM revisions from the FortiManager. If name is not specified, all revisions
        will be returned.

        :param name: Type str.
                     The name of the revision to retrieve.
        :return: The json response data from the request to retrieve the revision.
        """
        params = [{"url": "{}revision".format(self.dvmdb_url)}]
        if name:
            # noinspection PyTypeChecker
            params[0].update({"filter": ["name", "==", name]})

        body = {"method": "get", "params": params, "verbose": 1, "session": self.session}
        response = self.make_request(body).json()

        return response

    def get_status(self):
        """
        This method is used to retrieve the status of the FortiManager.

        :return: The json response data from the request to retrieve system status.
        """
        body = dict(method="get", params=[dict(url="/sys/status")], verbose=1, session=self.session)
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_task(self, task, wait):
        """
        This method is used to get the status of a task.

        :param task: Type str.
                     The task id to retrieve
        :param wait: Type int.
                     The number of minutes to wait before failing.
        :return: The json results from the task once completed, failed, or time ran out.
        """
        body = {"method": "get", "params": [{"url": "task/task/{}".format(task)}], "verbose": 1,
                "session": self.session}
        percent_complete = 0
        countdown = time.localtime().tm_min

        while percent_complete != 100:
            response = self.make_request(body).json()
            if response["result"][0]["status"]["code"] == 0:
                percent_complete = response["result"][0]["data"]["percent"]

            # limit execution time to specified time in minutes
            if time.localtime().tm_min - countdown > wait:
                break
            elif countdown in range((60 - wait), 61) and time.localtime().tm_min in range(wait):
                break
            else:
                time.sleep(15)

        return response

    def install_package(self, proposed):
        """
        This method is used to install a package to the end devices.

        :param proposed: Type list.
                         The data portion of the API Request.
        :return: The json result data from the task associated with request to make install the package.
        """
        body = {"method": "exec", "params": [{"url": "/securityconsole/install/package", "data": proposed, "id": 1,
                                              "session": self.session}]}

        response = self.make_request(body).json()

        # collect task id
        if response["result"][0]["status"]["code"] == 0:
            task = response["result"][0]["data"]["task"]
        else:
            return response

        # check for task completion
        task_status = self.get_task(task, 10)

        return task_status

    def lock(self):
        """
        The lock method is used to lock the ADOM to enable configurations to be sent to the FortiManager when it has
        workspace mode enabled.

        :return: The JSON response from the request to lock the session.
        """
        body = {"method": "exec", "params": [{"url": self.wsp_url + "lock"}], "session": self.session}
        response = self.make_request(body)

        return response.json()

    def login(self):
        """
        The login method is used to establish a session with the FortiManager. All necessary parameters need to be
        established at class instantiation.

        :return: The response from the login request. The instance session is also set, and defaults to None if the
        login was not successful
        """
        params = [{"url": "/sys/login/user", "data": {"user": self.user, "passwd": self.passw}}]
        body = {"method": "exec", "params": params}
        login = self.make_request(body)

        self.session = login.json().get("session")

        return login

    def logout(self):
        """
        The login method is used to establish a session with the FortiManager. All necessary parameters need to be
        established at class instantiation.

        :return: The response from the login request. The instance session is also set, and defaults to None if the
        login was not successful
        """
        body = dict(method="exec", params=[{"url": "/sys/logout"}], session=self.session)
        logout = self.make_request(body)

        return logout

    def make_request(self, body):
        """
        This method is used to make a request to the FortiManager API. All requests to FortiManager use the POST method
        to the same URL.

        :param body: Type dict.
                     The JSON body with the necessary request params.
        :return: The response from the API request.
        """
        response = requests.post(self.url, json=body, headers=self.headers, verify=self.verify)

        return response

    def preview_install(self, package, device, vdoms, lock):
        """
        This method is used to preview what changes will be pushed to the end device when the package is installed. The
        Fortimanager requires the install process be started with the preview flag in order for policy updates to be
        included in the preview request. This method will handle this process, and cancel the install task after the
        preview has been generated. This method also makes use of FortiManager's "id" field to keep track of the stages
        (install preview, generate preview, retrieve preview, cancel install) the method is currently executing, and
        returns the ID in the response. If the module returns early, then the "id" field can be used to determine where
        the failure occurred.

        :param package: Type str.
                        The name of the package in consideration for install.
        :param device: Type str.
                       The FortiNet to preview install.
        :param vdoms: Type list.
                      The list of vdoms associated with the vdom to preview install
        :param lock: Type bool
                     Determines whether the package install preview will use the auto lock field.
        :return: The json response data from the request to preview install the package.
        """
        # issue package install with preview flag to include policy in preview
        flags = ["preview"]
        if lock:
            flags.append("auto_lock_ws")

        proposed = [{"adom": self.adom, "flags": flags, "pkg": package, "scope": [device]}]
        response = self.install_package(proposed)

        if response["result"][0].get("data", {"state": "error"}).get("state") == "done":
            # generate preview request
            proposed = [{"adom": self.adom, "device": device, "vdoms": vdoms}]
            body = {"method": "exec", "params": [{"url": "/securityconsole/install/preview", "data": proposed}],
                    "id": 2, "session": self.session}
            response = self.make_request(body).json()
        else:
            response.update({"id": 1})
            return response

        # collect task id
        if response["result"][0]["status"]["code"] == 0:
            task = response["result"][0]["data"]["task"]
        else:
            return response

        task_status = self.get_task(task, 5)
        if task_status["result"][0]["data"]["percent"] == 100:
            # cancel install task
            url = "/securityconsole/package/cancel/install"
            params = [{"url": url, "data": [{"adom": self.adom, "device": device}]}]
            body = {"method": "exec", "params": params, "id": 3, "session": self.session}
            response = self.make_request(body).json()
        else:
            task_status.update({"id": 2})
            return task_status

        if response["result"][0]["status"]["code"] == 0:
            # get preview result
            params = [{"url": "/securityconsole/preview/result", "data": [{"adom": self.adom, "device": device}]}]
            body = {"method": "exec", "params": params, "id": 4,
                    "session": self.session}
            response = self.make_request(body).json()
        else:
            return response

        return response

    def restore_revision(self, version, proposed):
        """
        This method is used to restore an ADOM to a previous revision.

        :param version: Type str.
                        The version number corresponding to the revision to delete.
        :param proposed: Type list.
                         The data portion of the API request.
        :return: The json response data from the request to delete the revision.
        """
        rev_url = "{}revision/{}".format(self.dvmdb_url, version)
        body = {"method": "clone", "params": [{"url": rev_url, "data": proposed}], "session": self.session}
        response = self.make_request(body).json()

        return response

    def save(self):
        """
        The save method is used to save the ADOM configurations during a locked session.

        :return: The JSON response from the request to save the session.
        """
        body = {"method": "exec", "params": [{"url": self.wsp_url + "commit"}], "session": self.session}
        response = self.make_request(body)

        return response.json()

    def unlock(self):
        """
        The unlock method is used to lock the ADOM to enable configurations to be sent to the FortiManager when it has
        workspace mode enabled.

        :return: The JSON response from the request to unlock the session.
        """
        body = {"method": "exec", "params": [{"url": self.wsp_url + "unlock"}], "session": self.session}
        response = self.make_request(body)

        return response.json()

    def update_config(self, update_config):
        """
        This method is used to submit a configuration update request to the FortiManager. Only the object configuration
        details need to be provided; all other parameters that make up the API request body will be handled by the
        method. Only fields that need to be updated are required to be in the "update_config" variable (EX: updating
        the comment for an address group only needs the "name" and "comment" fields in the configuration dictionary).
        When including a field in the configuration update, ensure that all items are included for the desired end-state
        (EX: adding address to an address group that already has ["svr01", "svr02"] should include all three
        addresses in the "member" list, ["svr01", "svr02", "svr03"]. If you want to remove part of an item's
        configuration, this method should be used, and the item to be removed should be left off the respective list
        (EX: removing an address from an address group that has ["svr01", "svr02", "svr03"] should have a "member" list
        like ["svr01", "svr02"] with the final state of the address group containing only svr01 and svr02).

        :param update_config: Type list.
                           The "data" portion of the configuration to be submitted to the FortiManager.
        :return: The response from the API request to add the configuration.
        """
        body = {"method": "update", "params": [{"url": self.obj_url, "data": update_config, "session": self.session}]}
        response = self.make_request(body)

        return response

    def _escape_params_url(self, url):
        """
        This private method is used to escape slash ("/") characters from a url string to be provided as a json-rpc request params.
        Slash characters are escaped by prefixing with a backslash ("\").
        If url is None, None is returned.

        :param url: Type str.
                        The url string to process.
        :return: The url string with slash characters escaped with a backslash ("\") or None if url is None.
        """
        if url is not None:
            return str(url).replace('/', '\\/')
        else:
            return None


class FMAddress(FortiManager):
    """
    This is the class used for interacting with the "address" API Endpoint. In addition to address specific methods, the
    api endpoint default value is set to "address."
    """

    def __init__(self, host, user, passw, use_ssl=True, verify=False, adom="", package="", api_endpoint="address",
                 **kwargs):
        super(FMAddress, self).__init__(host, user, passw, use_ssl, verify, adom, package, api_endpoint, **kwargs)

    @staticmethod
    def get_diff_add(proposed, existing):
        """
        This method is used to get the difference between two configurations when the "proposed" configuration is a dict
        of configuration items that should exist in the configuration for the object in the FortiManager. Either the
        get_item or get_item_fields methods should be used to obtain the "existing" variable; if either of those methods
        return an empty dict, then you should use the add_config method to add the new object.

        :param proposed: Type dict.
                         The configuration that should not exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs configuration removed.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        config = {}
        replace = ["associated-interface", "subnet", "wildcard"]
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            if existing_field and proposed_field != existing_field:
                # check for lists that need to be replaced instead of appended.
                if field in replace:
                    config[field] = proposed_field
                elif isinstance(existing_field, list):
                    proposed_field = set(proposed_field)
                    if not proposed_field.issubset(existing_field):
                        config[field] = list(proposed_field.union(existing_field))
                elif isinstance(existing_field, dict):
                    config[field] = dict(set(proposed_field.items()).union(existing_field.items()))
                elif isinstance(existing_field, int) or isinstance(existing_field, string_types):
                    config[field] = proposed_field
            elif field not in existing:
                config[field] = proposed_field

        if config:
            config["name"] = proposed["name"]

        return config

    @staticmethod
    def get_diff_add_map(proposed, existing):
        """
        This method is used to get the difference between two dynamic_mapping configurations when the "proposed"
        configuration is a dict of configuration items that should exist in the configuration for the object in the
        FortiManager. Either the get_item or get_item_fields method should be used to obtain the "existing" variable; if
        either of those methods return an empty dict, then you should use the add_config method to add the new object.

        :param proposed: Type dict.
                         The configuration that should exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs its configuration modified.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        name = proposed.get("name")
        proposed_map = proposed.get("dynamic_mapping")[0]
        proposed_scope = proposed_map.pop("_scope")[0]
        existing_map = existing.get("dynamic_mapping")
        config = dict(name=name, dynamic_mapping=[])
        present = False

        # check if proposed mapping already exists and make necessary updates to config
        if existing_map:
            for mapping in existing_map:
                if proposed_scope in mapping["_scope"]:
                    replace = ["subnet", "wildcard"]
                    present = True
                    updated_map = {}
                    for field in proposed_map.keys():
                        proposed_field = proposed_map[field]
                        existing_field = mapping.get(field)
                        # only consider relevant fields that have a difference
                        if existing_field and proposed_field != existing_field:
                            # check for lists that need to be replaced instead of appended.
                            if field in replace:
                                updated_map[field] = proposed_field
                            elif isinstance(existing_field, list):
                                proposed_field = set(proposed_field)
                                if not proposed_field.issubset(existing_field):
                                    updated_map[field] = list(proposed_field.union(existing_field))
                            elif isinstance(existing_field, dict):
                                updated_map[field] = dict(set(proposed_field.items()).union(existing_field.items()))
                            elif isinstance(existing_field, int) or isinstance(existing_field, string_types):
                                updated_map[field] = proposed_field
                        elif field not in mapping:
                            updated_map[field] = proposed_field
                    # config update if dynamic_mapping dict has any keys, need to append _scope key
                    if updated_map:
                        # add scope to updated_map and append the config to the list of other mappings
                        updated_map["_scope"] = mapping["_scope"]
                        config["dynamic_mapping"].append(updated_map)
                    else:
                        # set config to a null dictionary if dynamic mappings are identical and exit loop
                        config = {}
                        break
                else:
                    # keep unrelated mapping in diff so that diff can be used to update FortiManager
                    config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

        # add mapping to config if it does not currently exist
        if not present:
            config = proposed
            config["dynamic_mapping"][0]["_scope"] = [proposed_scope]
            if existing_map:
                for mapping in existing_map:
                    config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

        return config

    @staticmethod
    def get_diff_remove(proposed, existing):
        """
        This method is used to get the difference between two configurations when the "proposed" configuration is a dict
        of configuration items that should not exist in the configuration for the object in the FortiManager. Either the
        get_item or get_item_fields methods should be used to obtain the "existing" variable; if either of those methods
        return an empty dict, then the object does not exist and there is no configuration to remove.

        :param proposed: Type dict.
                         The configuration that should not exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs configuration removed.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        config = {}
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            ignore = ["associated-interface", "end-ip", "fqdn", "start-ip", "subnet", "type", "wildcard", "wildcard-fqdn"]
            if field in ignore:
                pass
            elif existing_field and isinstance(existing_field, list):
                existing_field = set(existing_field)
                diff = existing_field.difference(proposed_field)
                if diff != existing_field:
                    config[field] = list(diff)
            elif existing_field and isinstance(existing_field, dict):
                diff = dict(set(proposed.items()).difference(existing.items()))
                if diff != existing_field:
                    config[field] = diff

        if config:
            config["name"] = proposed["name"]

        return config

    @staticmethod
    def get_diff_remove_map(proposed, existing):
        """
        This method is used to get the difference between two dynamic_mapping configurations when the "proposed"
        configuration is a dict of configuration items that should not exist in the configuration for the object in the
        FortiManager. Either the get_item or get_item_fields method should be used to obtain the "existing" variable; if
        either of those methods return an empty dict, then the object does not exist and there is no configuration to
        remove.

        :param proposed: Type dict.
                         The configuration that should not exist for the object on the FortiManager.
        :param existing: Type dict.
                         The current configuration for the object that potentially needs configuration removed.
        :return: A dict corresponding to the "data" portion of an "update" request. This can be used to call the
                 update_config method.
        """
        name = proposed.get("name")
        proposed_map = proposed.get("dynamic_mapping")[0]
        proposed_scope = proposed_map.pop("_scope")[0]
        existing_map = existing.get("dynamic_mapping")
        config = dict(name=name, dynamic_mapping=[])
        present = False

        # check if proposed mapping already exists and make necessary updates to config
        if existing_map:
            for mapping in existing_map:
                if proposed_scope in mapping["_scope"]:
                    ignore = ["end-ip", "fqdn", "start-ip", "subnet", "type", "wildcard", "wildcard-fqdn"]
                    present = True
                    updated_map = {}
                    for field in proposed_map.keys():
                        proposed_field = proposed_map[field]
                        existing_field = mapping.get(field)
                        if field in ignore:
                            pass
                        elif existing_field and isinstance(existing_field, list):
                            existing_field = set(existing_field)
                            diff = existing_field.difference(proposed_field)
                            if diff != existing_field:
                                updated_map[field] = list(diff)
                        elif existing_field and isinstance(existing_field, dict):
                            diff = dict(set(proposed_map.items()).difference(mapping.items()))
                            if diff != existing_field:
                                updated_map[field] = diff
                    # config update if dynamic_mapping dict has any keys, need to append _scope key
                    if updated_map:
                        # add scope to updated_map and append the config to the list of other mappings
                        updated_map["_scope"] = mapping["_scope"]
                        config["dynamic_mapping"].append(updated_map)
                    else:
                        # remove dynamic mapping from proposed if proposed matches existing config
                        config = {}
                        break
                else:
                    # keep unrelated mapping in diff so that diff can be used to update FortiManager
                    config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

        # set config to empty dict if mapping was not found, representing no change
        if not present:
            config = {}

        return config


def main():
    base_argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        lock=dict(required=False, type="bool"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        session_id=dict(required=False, type="str"),
        state=dict(choices=["absent", "param_absent", "present"], type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        address_name=dict(required=False, type="str"),
        address_type=dict(choices=["ipmask", "iprange", "fqdn", "wildcard", "wildcard-fqdn"],
                          required=False, type="str"),
        allow_routing=dict(choices=["enable", "disable"], required=False, type="str"),
        associated_intfc=dict(required=False, type="list"),
        color=dict(required=False, type="int"),
        comment=dict(required=False, type="str"),
        end_ip=dict(required=False, type="str"),
        fqdn=dict(required=False, type="str"),
        network_address=dict(required=False, type="str"),
        network_mask=dict(required=False, type="str"),
        start_ip=dict(required=False, type="str"),
        subnet=dict(required=False, type="list"),
        wildcard=dict(required=False, type="list"),
        wildcard_address=dict(required=False, type="str"),
        wildcard_fqdn=dict(required=False, type="str"),
        wildcard_mask=dict(required=False, type="str")
    )
    argument_spec = base_argument_spec
    argument_spec["provider"] = dict(required=False, type="dict", options=base_argument_spec)

    module = AnsibleModule(argument_spec, supports_check_mode=True,
                           required_together=[["network_address", "network_mask"], ["wildcard_address", "wildcard_mask"]],
                           mutually_exclusive=[["network_address", "subnet"], ["wildcard", "wildcard_address"]])

    provider = module.params["provider"] or {}

    # allow local params to override provider
    for param, pvalue in provider.items():
        if module.params.get(param) is None:
            module.params[param] = pvalue

    # handle params passed via provider and insure they are represented as the data type expected by fortimanager
    adom = module.params["adom"]
    host = module.params["host"]
    lock = module.params["lock"]
    if lock is None:
        module.params["lock"] = True
    password = module.params["password"]
    port = module.params["port"]
    session_id = module.params["session_id"]
    state = module.params["state"]
    if state is None:
        state = "present"
    use_ssl = module.params["use_ssl"]
    if use_ssl is None:
        use_ssl = True
    username = module.params["username"]
    validate_certs = module.params["validate_certs"]
    if validate_certs is None:
        validate_certs = False
    address_name = module.params["address_name"]
    associated_intfc = module.params["associated_intfc"]
    if isinstance(associated_intfc, str):
        associated_intfc = [associated_intfc]
    color = module.params["color"]
    if isinstance(color, str):
        color = int(color)
    network_address = module.params["network_address"]
    network_mask = module.params["network_mask"]
    subnet = module.params["subnet"]
    if isinstance(subnet, str):
        subnet = [subnet]
    wildcard = module.params["wildcard"]
    if isinstance(wildcard, str):
        wildcard = [wildcard]
    wildcard_address = module.params["wildcard_address"]
    wildcard_mask = module.params["wildcard_mask"]

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, host=host, address_name=address_name)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    # validate address parameters are passed correctly
    if subnet and (network_address or network_mask):
        module.fail_json(msg="The subnet parameter cannot be used with the network_address and network_mask parameters")
    elif wildcard and (wildcard_address or wildcard_mask):
        module.fail_json(msg="The wildcard parameter cannot be used with the wildcard_address and wildcard_mask parameters")
    elif network_address and not network_mask:
        module.fail_json(msg="The network_address and network_mask parameters must be provided together; missing network_mask.")
    elif network_mask and not network_address:
        module.fail_json(msg="The network_address and network_mask parameters must be provided together; missing network_address.")
    elif wildcard_address and not wildcard_mask:
        module.fail_json(msg="The wildcard_address and wildcard_mask parameters must be provided together; missing wildcard_mask.")
    elif wildcard_mask and not wildcard_address:
        module.fail_json(msg="The wildcard_address and wildcard_mask parameters must be provided together; missing wildcard_address.")

    # use subnet variables to normalize the subnet into a list that fortimanager expects
    if subnet and len(subnet) == 1 and "/" in subnet[0]:
        subnet = FortiManager.cidr_to_network(subnet[0])
        if not subnet:
            module.fail_json(msg="The prefix must be a value between 0 and 32")
    elif subnet and len(subnet) == 1:
        subnet.append("255.255.255.255")
    elif network_address and network_mask:
        subnet = [network_address, network_mask]

    # use wildcard variables to normalize the wildcard into a list that fortimanager expects
    if wildcard and "/" in wildcard[0]:
        wildcard = FortiManager.cidr_to_wildcard(wildcard[0])
        if not wildcard:
            module.fail_json(msg="The prefix must be a value between 0 and 32")
    elif wildcard_address and wildcard_mask:
        wildcard = [wildcard_address, wildcard_mask]

    args = {
        "allow-routing": module.params["allow_routing"],
        "associated-interface": associated_intfc,
        "color": color,
        "comment": module.params["comment"],
        "end-ip": module.params["end_ip"],
        "fqdn": module.params["fqdn"],
        "name": address_name,
        "start-ip": module.params["start_ip"],
        "subnet": subnet,
        "type": module.params["address_type"],
        "wildcard": wildcard,
        "wildcard-fqdn": module.params["wildcard_fqdn"]
    }

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FMAddress(host, username, password, use_ssl, validate_certs, adom, **kwargs)
    if not session_id:
        session_login = session.login()
        if not session_login.json()["result"][0]["status"]["code"] == 0:
            module.fail_json(msg="Unable to login", fortimanager_response=session_login.json())
    else:
        session.session = session_id

    # get existing configuration from fortimanager and make necessary changes
    existing = session.get_item(proposed["name"])
    if state == "present":
        results = session.config_present(module, proposed, existing)
    elif state == "absent":
        results = session.config_absent(module, proposed, existing)
    else:
        results = session.config_param_absent(module, proposed, existing)

    # if module has made it this far and lock set, then all related return values are true
    if module.params["lock"] and results["changed"]:
        locked = dict(locked=True, saved=True, unlocked=True)
        results.update(locked)

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)


if __name__ == "__main__":
    main()

