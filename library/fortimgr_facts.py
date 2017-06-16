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
module: fortimgr_facts
version_added: "2.3"
short_description: Gathers facts from the FortiManager
description:
  - Gathers facts from the FortiManager using jsonrpc API
author: Jacob McGill (@jmcgill298)
options:
  adom:
    description:
      - The ADOM that should have package installed should belong to.
    required: false
    type: str
  host:
    description:
      - The FortiManager's Address.
    required: true
    type: str
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
  use_ssl:
    description:
      - Determines whether to use HTTPS(True) or HTTP(False).
    required: false
    default: True
    type: bool
  username:
    description:
      - The username used to authenticate with the FortiManager.
    required: true
    type: str
  validate_certs:
    description:
      - Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False).
    required: false
    default: False
    type: bool
  config_filter:
    description:
      - The list of configuration items to retrieve from the list of FortiGates managed by the FortiManager.
    required: false
    type: list
    choices: ["all", "route", "address", "address_group", "service", "service_group", "ip_pool", "vip", "vip_group",
              "policy"]
  fortigates:
    description:
      - A list of FortiGates to retrieve device information for; "all" can be used to retrieve all devices managed by
        the FortiManger.
      - If config_filter is defined, this list will be used to determine what devices to retrieve configuration from.
      - If config_filter is defined, this list should be a list of dictionaries with "name" and "vdom" keys defining
        the mapping for fortigate and vdom.
    required: false
    type: list
'''

EXAMPLES = '''
- name: Get Facts
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
- name: Get FortiGates
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
    fortigates:
      - "lab"
      - "prod"
      - "dmz"
- name: Get Configs
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
    fortigates:
      - name: "lab"
        vdom: "root
      - name: "prod"
        vdom: "root"
      - name: "dmz"
        vdom: "web"
      - name: "dmz"
        vdom: "dmz"
    config_filter:
      - "routes"
      - "policy"
- name: Get All Configs
  fortimgr_facts:
    host: "{{ inventory_hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    adom: "lab"
    fortigates:
      - "all"
    config_filter:
      - "all"
'''

RETURN = '''
fortimanager:
    description: Information and status about the FortiManager.
    returned: Always
    type: dict
    sample: {"adom": "Enabled", "adoms": [{"desc": "", "flags": "no_vpn_console", "mode": "gms", "name":
    "FortiAnalyzer", "os_ver": "5.0"}, {"desc": "", "flags": "no_vpn_console", "mode": "gms", "name": "FortiManager",
    "os_ver": "5.0"}, {"desc": "", "flags": "no_vpn_console", "mode": "gms", "name": "root", "os_ver": "5.0"}, {"desc":
    "", "flags": "no_vpn_console", "mode": "provider", "name": "rootp", "os_ver": "5.0"}, {"desc": "", "flags":
    "no_vpn_console", "mode": "gms", "name": "lab", "os_ver": "5.0"}], "high_availability": {"cluster_id": 1,
    "heartbeat_threshold": 3, "heartbeat_int": 5, "mode": "standalone"}, "license_status": null, "name": "fm_prod",
    "platform": "FMG-VM64-KVM", "serial_num": "FMG-VM0000000000", "version": "v5.4.0-build1019 160217 (GA)"}}
devices:
    description: Basic information about devices managed by the FortiManager.
    returned: Always
    type: dict
    sample: [{"app_ver": "", "av_ver": "1.00123(2015-12-11 13:18)", "build": 7605, "conf_status": "outofsync",
              "conn_mode": "passive", "conn_status": "up", "db_status": "mod", "desc": "", "dev_status": "aborted",
              "flags": "reload", "ha_group_id": 0, "ha_group_name": "labha ", "ha_mode": "AP", "ha_slave": [{"did":
              "lab_fg", "flags": 0, "idx": 0, "name": "lab_fg", "prio": 128, "role": 1, "sn": "FGVMEV0000000000",
              "status": 1}], "hostname": "lab_fg", "ip": "10.10.10.10", "ips_ver": "6.00741(2015-12-01 02:30)",
              "last_checked": 1496787213, "last_resync": 1496372428, "mgmt_if": "port1", "mgmt_mode": "fmgfaz",
              "mgt_vdom": "root", "os_type": "fos", "os_ver": "5.0", "patch": 4, "platform_str": "FortiGate-VM64-KVM",
              "sn": "FGVMEV0000000000", "source": "faz", "vdom": [{"comments": "", "devid": "lab_fg", "ext_flags": 1,
              "flags": "", "name": "root", "node_flags": 4, "opmode": "nat", "rtm_prof_id": 0, "status": "",
              "tab_status": ""}]}, {"app_ver": "", "av_ver": "", "build": 1007, "conf_status": "unknown", "conn_mode":
              "passive", "conn_status": "UNKNOWN", "db_status": "mod", "desc": "", "dev_status": "unknown", "flags":
              "is_model", "ha_group_id": 0, "ha_group_name": "", "ha_mode": "standalone", "hostname": "prod_fg", "ip":
              "", "ips_ver": "", "last_checked": 0, "last_resync": 0, "mgmt_if": "", "mgmt_mode": "fmgfaz", "mgt_vdom":
              "root", "os_type": "fos", "os_ver": "5.0", "patch": -1, "platform_str": "FortiGate-VM", "sn":
              "FGVMEV0000000001", "source": "faz", "vdom": [{"comments": "", "devid": "prod_fg", "ext_flags": 1,
              "flags": "", "name": "root", "node_flags": 4, "opmode": "nat", "rtm_prof_id": 0, "status": "",
              "tab_status": ""}]}]
configs:
    description: The configurations on the devices managed by the FortiManager.
    returned: Always
    type: dict
    sample: {"lab_fg": {"address_groups": [], "ip_pools": [], "service_groups": []}, "prod_fg": {"address_groups": [{
             "allow-routing": "enable", "color":1, "comment": "", "member": ["g"], "name": "a",
             "uuid": "74f4df96-4a01-51e7-0062-081788762948", "visibility": "enable"}"ip_pools": [], "service_groups": [{
             "color":0, "comment": "", "explicit-proxy": "disable", "member": ["DNS","IMAP","IMAPS","POP3","POP3S",
             "SMTP","SMTPS"], "name": "Email Access"}, {"color":0, "comment": "", "explicit-proxy": "disable", "member":
             ["DNS","HTTP","HTTPS"], "name": "Web Access"}, {"color":0, "comment": "", "explicit-proxy": "disable",
             "member": ["DCE-RPC","DNS","KERBEROS","LDAP","LDAP_UDP","SAMBA","SMB"], "name": "Windows AD"}, {"color":0,
             "comment": "", "explicit-proxy": "disable", "member": ["DCE-RPC","DNS","HTTPS"], "name": "Exchange Server"}
             ]}}
'''

import time
import requests
from ansible.module_utils.basic import AnsibleModule, env_fallback, return_values

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
        self.dvmdb_url = "/dvmdb/adom/{}/".format(self.adom)
        self.obj_url = "/pm/config/adom/{}/obj/firewall/{}".format(self.adom, self.api_endpoint)
        self.pkg_url = "/pm/config/adom/{}/pkg/{}/firewall/{}".format(self.adom, self.package, self.api_endpoint)
        self.wsp_url = "/dvmdb/adom/{}/workspace/".format(self.adom)
        self.headers = {"Content-Type": "application/json"}
        self.port = kwargs.get("port", "")

        if use_ssl:
            self.url = "https:{port}//{fw}/jsonrpc".format(port=self.port, fw=self.host)
        else:
            self.url = "http:{port}//{fw}/jsonrpc".format(port=self.port, fw=self.host)

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

        return {"method": "delete", "params": [{"url": self.obj_url + "/{}".format(name)}]}

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
            module.fail_json(msg=msg, locked=False, saved=False, unlocked=False)

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
        if json_response["result"][0]["status"]["code"] == 0 and lock:
            self.config_save(module)
            self.config_unlock(module)
        # attempt to unlock if config unsuccessful
        elif json_response["result"][0]["status"]["code"] != 0 and lock:
            self.config_unlock(module, msg=json_response, saved=False)
            module.fail_json(msg=json_response, locked=True, saved=False, unlocked=True)
        # fail if not using lock mode and config unsuccessful
        elif json_response["result"][0]["status"]["code"] != 0:
            module.fail_json(msg=json_response)

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
            module.fail_json(msg=msg, locked=True, saved=False, unlocked=True)

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
            module.fail_json(msg=msg, locked=True, saved=saved, unlocked=False)

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
        item_url = self.obj_url + "/{}".format(name)
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

    def get_device_config(self, device, vdom, config_url, fields=[]):
        """
        This method is used to retrieve the static routes configured on the managed device.

        :param device: Type str.
                       The device to retrieve the static route configuration from.
        :param vdom: Type str.
                     The vdom to retrieve the static route configuration from.
        :param config_url: Type str.
                           The url associated with the configuration section to retrieve.
        :param fields: Type list.
                       A list of fields to retrieve for the device.
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
            dev_url = "/dvmdb/device/{}/ha_slave".format(self.adom, device)
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
            if field in existing and proposed[field] != existing[field]:
                if type(existing[field]) is list:
                    diff = list(set(proposed[field]).union(existing[field]))
                    if diff != existing[field]:
                        config[field] = diff
                elif type(existing[field]) is dict:
                    config[field] = dict(set(proposed[field].items()).union(existing[field].items()))
                elif type(existing[field]) is str or type(existing[field]) is unicode:
                    config[field] = proposed[field]
            elif field not in existing:
                config[field] = proposed[field]

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
        existing_map = existing.get("dynamic_mapping", [])
        config = dict(name=name, dynamic_mapping=[])
        present = False

        # check if mapping already exists and make necessary updates to config
        for mapping in existing_map:
            if proposed_scope in mapping["_scope"]:
                present = True
                updated_map = {}
                for field in proposed_map.keys():
                    # only consider relevant fields that have a difference
                    if field in mapping and proposed_map[field] != mapping[field]:
                        if type(mapping[field]) is list:
                            diff = list(set(proposed_map[field]).union(mapping[field]))
                            if diff != mapping[field]:
                                updated_map[field] = diff
                        elif type(mapping[field]) is dict:
                            updated_map[field] = dict(set(proposed_map[field].items()).union(mapping[field].items()))
                        elif type(mapping[field]) is str or type(mapping[field]) is unicode:
                            updated_map[field] = proposed_map[field]
                    elif field not in mapping:
                        updated_map[field] = proposed_map[field]
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
        for mapping in existing.get("dynamic_mapping", []):
            if mapping["_scope"] != proposed["dynamic_mapping"][0]["_scope"]:
                config["dynamic_mapping"].append(dict(_scope=mapping["_scope"]))

        if len(config["dynamic_mapping"]) == len(existing.get("dynamic_mapping", [])):
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
            if field in existing and type(existing[field]) is list:
                diff = list(set(existing[field]).difference(proposed[field]))
                if diff != existing[field]:
                    config[field] = diff
            elif field in existing and type(existing[field]) is dict:
                diff = dict(set(proposed.items()).difference(existing.items()))
                if diff != existing[field]:
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
        existing_map = existing.get("dynamic_mapping", [])
        config = dict(name=name, dynamic_mapping=[])
        present = False

        # check if mapping already exists and make necessary updates to config
        for mapping in existing_map:
            if proposed_scope in mapping["_scope"]:
                present = True
                updated_map = {}
                for field in proposed_map.keys():
                    if field in mapping and type(mapping[field]) is list:
                        diff = list(set(mapping[field]).difference(proposed_map[field]))
                        if diff != mapping[field]:
                            updated_map[field] = diff
                    elif field in mapping and type(mapping[field]) is dict:
                        diff = dict(set(proposed_map.items()).difference(mapping.items()))
                        if diff != mapping[field]:
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

        # set config to dict with name only if mapping does not exist representing no change
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
        item_url = self.obj_url + "/{}".format(name)
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


def main():
    argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=True, type="str"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        provider=dict(required=False, type="dict"),
        session_id=dict(required=False, type="str"),
        use_ssl=dict(default=True, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(default=False, type="bool"),
        fortigates=dict(required=False, type="list"),
        config_filter=dict(required=False, type="list")
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    provider = module.params["provider"] or {}

    # prevent secret params in provider from logging
    no_log = ["password"]
    for param in no_log:
        if provider.get(param):
            module.no_log_values.update(return_values(provider[param]))

    # allow local params to override provider
    for param, pvalue in provider.items():
        if module.params.get(param) is None:
            module.params[param] = pvalue

    adom = module.params["adom"]
    host = module.params["host"]
    password = module.params["password"]
    port = module.params["port"]
    session_id = module.params["session_id"]
    use_ssl = module.params["use_ssl"]
    username = module.params["username"]
    validate_certs = module.params["validate_certs"]
    fortigates = module.params["fortigates"]
    config_filter = module.params["config_filter"]

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FortiManager(host, username, password, use_ssl, validate_certs, adom)
    if not session_id:
        session_login = session.login()
        if not session_login.json()["result"][0]["status"]["code"] == 0:
            module.fail_json(msg="Unable to login")
    else:
        session.session_id = session_id

    # collect and normalize fortimanager high availability info
    fm_ha_status = session.get_ha()
    fm_ha = dict(cluster_id=fm_ha_status.get("clusterid"), heartbeat_int=fm_ha_status.get("hb-interval"),
                 hearbeat_threshold=fm_ha_status.get("hb-lost-threshold"), mode=fm_ha_status.get("mode"))

    # collect and normalize fortimanager adom info
    fm_adoms = session.get_adoms_fields(["desc", "flags", "mode", "name", "os_ver"])
    adoms = []
    for adom in fm_adoms:
        if type(adom.get("flags")) is str:
            # convert single entry flags to match multi-entry flags by putting single in a list
            adom["flags"] = [adom["flags"]]

        adoms.append(adom)

    # collect fortimanager status, normalize data, and append ha and adom info
    fm_status = session.get_status()
    fortimanager = dict(name=fm_status.get("Hostname"), adom=fm_status.get("Admin Domain Configuration"),
                        high_availabilty=fm_ha, license_status=fm_status.get("License Status"),
                        platform=fm_status.get("Platform Type"), serial_num=fm_status.get("Serial Number"),
                        version=fm_status.get("Version"), adoms=adoms)

    # collect fortigate information and config if specified
    if fortigates:
        device_fields = ["app_ver", "av_ver", "build", "conf_status", "conn_mode", "conn_status", "db_status", "desc",
                         "dev_status", "ha_group_id", "ha_group_name", "ha_mode", "hostname", "ip", "ips_ver", "flags",
                         "last_checked", "last_resync", "mgmt_if", "mgmt_mode", "mgt_vdom", "os_type", "os_ver",
                         "patch", "platform_str", "sn", "source", "vdom"]

        if "all" in fortigates:
            devices = session.get_devices_fields(device_fields)
        # catch string input that ansible module converts to a list
        elif len(fortigates) == 1 and type(fortigates[0]) is str:
            devices = session.get_device_fields(fortigates, device_fields)
        # capture data for list of devices
        elif type(fortigates[0]) is str:
            device_filter = ["hostname", "in", ""]
            for device in fortigates:
                # add fortigate and , to all but last device to string
                if device != fortigates[-1]:
                    device_filter[2] += "{}, ".format(device)
                else:
                    device_filter[2] += device
            devices = session.get_devices_fields(device_fields, device_filter)
        # capture data for list of devices as a dict
        elif type(fortigates[0]) is dict:
            device_filter = ["hostname", "in", ""]
            for device in fortigates:
                # add fortigate and , to all but last device to string
                if device["name"] != fortigates[-1]["name"]:
                    device_filter[2] += "{}, ".format(device["name"])
                else:
                    device_filter[2] += device["name"]
            devices = session.get_devices_fields(device_fields, device_filter)
    else:
        devices = {}

    configs = {}

    # build list of all devices and vdom mappings if all is used for devices
    if config_filter and "all" in fortigates:
        fortigates = []
        for device in devices:
            for vdom in device["vdom"]:
                fortigates.append(dict(name=device["hostname"], vdom=vdom["name"]))

    if "all" in config_filter:
        # iterate through each fortigate and append a dictionary of configuration items
        for device in fortigates:
            config_dict = {"static_routes": session.get_device_config(device["name"], device["vdom"], "router/static"),
                           "addresses": session.get_device_config(device["name"], device["vdom"], "firewall/address"),
                           "address_groups": session.get_device_config(device["name"], device["vdom"],
                                                                       "firewall/addrgrp"),
                           "services": session.get_device_config(device["name"], device["vdom"],
                                                                 "firewall/service/custom"),
                           "service_groups": session.get_device_config(device["name"], device["vdom"],
                                                                       "firewall/service/group"),
                           "ip_pools": session.get_device_config(device["name"], device["vdom"], "firewall/ippool"),
                           "vips": session.get_device_config(device["name"], device["vdom"], "firewall/vip"),
                           "vip_groups": session.get_device_config(device["name"], device["vdom"], "firewall/vipgrp"),
                           "policies": session.get_device_config(device["name"], device["vdom"], "firewall/policy")}

            configs.update({device["name"]: config_dict})
    elif config_filter:
        # iterate through each fortigate and append a dictionary of requested configuration items
        for device in fortigates:
            config_dict = {}
            if "route" in config_filter:
                config_dict["static_routes"] = session.get_device_config(device["name"], device["vdom"],
                                                                         "router/static")

            if "address" in config_filter:
                config_dict["addresses"] = session.get_device_config(device["name"], device["vdom"],
                                                                     "firewall/address")

            if "address_group" in config_filter:
                config_dict["address_groups"] = session.get_device_config(device["name"], device["vdom"],
                                                                          "firewall/addrgrp")

            if "service" in config_filter:
                config_dict["services"] = session.get_device_config(device["name"], device["vdom"],
                                                                    "firewall/service/custom")

            if "service_group" in config_filter:
                config_dict["service_groups"] = session.get_device_config(device["name"], device["vdom"],
                                                                          "firewall/service/group")

            if "ip_pool" in config_filter:
                config_dict["ip_pools"] = session.get_device_config(device["name"], device["vdom"], "firewall/ippool")

            if "vip" in config_filter:
                config_dict["vips"] = session.get_device_config(device["name"], device["vdom"], "firewall/vip")

            if "vip_group" in config_filter:
                config_dict["vip_groups"] = session.get_device_config(device["name"], device["vdom"],
                                                                      "firewall/vipgrp")

            if "policy" in config_filter:
                config_dict["policies"] = session.get_device_config(device["name"], device["vdom"], "firewall/policy")

        configs.update({device["name"]: config_dict})

    results = dict(fortimanager=fortimanager, devices=devices, configs=configs)

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(ansible_facts=results)


if __name__ == "__main__":
    main()
