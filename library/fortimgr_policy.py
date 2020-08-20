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
module: fortimgr_policy
version_added: "2.3"
short_description: Manages FW Policy resources and attributes
description:
  - Manages FortiManager FW Policy configurations using jsonrpc API
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
      - The desired state of the specified policy.
      - absent will delete the policy if it exists.
      - param_absent will remove passed params from the policy config if necessary and possible.
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
  action:
    description:
      - The action the end device should take when the policy is matched.
    required: false
    type: str
    choices: ["accept", "deny", "ipsec", "ssl-vpn"]
  comment:
    description:
      - A comment to add to the Policy.
    required: false
    type: str
  destination_address:
    description:
      - A list of destinations to use for policy matching.
    required: false
    type: list
  destination_intfc:
    description:
      - A list of interface destinations to use for policy matching.
    required: false
    type: list
  direction:
    description:
      - The direction the policy should be placed in reference to the reference_policy
    required: false
    type: str
    choices: ["before", "after"]
  global_label:
    description:
      - A section label for policy grouping.
    required: false
    type: str
  ip_pool:
    description:
      - Setting the IP Pool Nat feature to enable or disable.
    required: false
    type: str
    choices: ["enable", "disable"]
  label:
    description:
      - A label for policy grouping.
    required: false
    type: str
  log_traffic:
    description:
      - Setting the Log Traffic to disable, all, or utm(log security events).
    required: false
    type:
    choices: ["disable", "all", "utm"]
  log_traffic_start:
    description:
      - Setting the Log Traffic Start to enable or disable.
    required: false
    type:
    choices: ["enable", "disable"]
  match_filter:
    description:
      - Determines whether to use match_filters to retrieve existing policies.
      - True will use match_filters to retrieve a matching policy.
      - False will not use match_filters to retrieve a matching policy.
    type: bool
    default: false
  match_filters:
    description:
      - This is an alternative means of matching an existing policy when not using policy_id or policy_name.
      - The config parameters to match existing policies against for comparing module parameters against existing configurations.
        All fields passed into the list will be used to retrieve an exact match from existing policies.
        If multiple policies match on the parameters, the module will fail with the list of matching policies.
      - C(all) can be used to match all parameters that are passed to the module.
    type: list
    default: ["source_address", "source_intfc", "destination_address", "destination_intfc", "service"]
    options: All policy config parameters accepted by the module and the word all
  nat:
    description:
      - Setting the NAT to enable or disable.
    required: false
    type: str
    choices: ["enable", "disable"]
  nat_ip:
    description:
      - The IP to use for NAT when enabled.
      - First IP in the list is beginning NAT range
      - Second IP in the list is the ending NAT range..
    required: false
    type: list
  package:
    description:
      - The policy package to add the policy to.
    required: true
    type: str
  permit_any_host:
    description:
      - Setting the Permit Any Host to enable or disable.
    required: false
    type: str
    choices: ["enable", "disable"]
  policy_id:
    description:
      - The ID associated with the Policy.
    required: false
    type: int
  policy_name:
    description:
      - The name of the Policy.
    required: false
    type: str
  pool_name:
    description:
      - The name of the IP Pool when enabled.
    required: false
    type: str
  reference_policy_id:
    description:
      - The policy id to use as a reference point for policy placement.
    required: false
    type: str
  reference_policy_name:
    description:
      - The policy name to use as a reference point for policy placement.
    required: false
    type: str
  schedule:
    description:
      - The schedule to use for when the policy should be enabled.
    required: false
    type: list
  service:
    description:
      - A list services used for policy matching.
    required: false
    type: list
  source_address:
    description:
      - A list of source addresses used for policy matching.
    required: false
    type: list
  source_intfc:
    description:
      - A list of source interfaces used for policy matching.
    required: false
    type: list
  status:
    description:
      - The desired status of the policy.
    required: false
    type: str
    choices: ["enable", "disable"]
'''

EXAMPLES = '''
- name: Add Policy
  fortimgr_policy:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "prod"
    package: "prod"
    action: "accept"
    destination_address: "Internet"
    destination_intfc: "port2"
    ip_pool: "enable"
    logtraffic: "all"
    policy_name: "Permit_Outbound_Web"
    nat: "enable"
    pool_name: "Internet_PATs"
    schedule: "always"
    service: "Web_Svcs"
    source_address: "Corp_Users"
    source_intfc: "port1"
    status: "enable"
- name: Modify Policy
  fortimgr_policy:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "prod"
    package: "prod"
    policy_name: "Permit_Outbound_Web"
    service: "File_Transfer_Services"
- name: Move Policy
  fortimgr_policy:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    use_ssl: False
    adom: "lab"
    package: "prod"
    policy_name: "Permit_Outbound_Web"
    direction: "after"
    reference_policy_id: "1"
- name: Delete Policy
  fortimgr_policy:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    use_ssl: False
    adom: "lab"
    package: "prod"
    policy_name: "Permit_Outbound_Web"
    state: "absent"
'''

RETURN = '''
existing:
    description: The existing configuration for the Policy (uses policy_name) before the task executed.
    returned: always
    type: dict
    sample: {"id": 1, "method": "update", "params": [{"data": {"action": "deny", "comments": "explicit deny",
             "dstaddr": ["lab"],"dstintf": ["any"], "global-label": "lab", "ippool": "enable", "logtraffic": "disable",
             "name": "lab_deny", "nat": "disable", "policyid": 6, "schedule": ["always"], "service": ["any"],
             "srcaddr": ["all"], "srcintf": ["any"], "status": "enable"},
             "url": "pm/config/adom/lab/pkg/lab/firewall/policy"}]}
config:
    description: The configuration that was pushed to the FortiManager.
    returned: always
    type: dict
    sample: {"id": 1, "method": "update", "params": [{"data": {"action": "accept", "comments": "lab access", "dstaddr":
             ["lab"], "dstintf": ["any"], "global-label": "lab", "logtraffic": "disable", "name": "lab_pol",
             "nat": "disable", "policyid": 5, "poolname": ["lab"], "schedule": ["always"], "service": ["lab"],
             "srcaddr": ["lab_admin"], "srcintf": ["any"], "status": "disable"},
             "url": "pm/config/adom/lab/pkg/lab/firewall/policy"}]}
moved:
    description: The movement of the policy if specified and required.
    returned always
    type: dict
    sample: {"id": 1, "method": "move", "params": [{"option": "before", "target": "4",
             "url": "pm/config/adom/lab/pkg/lab/firewall/policy/5"}]}
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
from ansible.module_utils.fortimgr_fortimanager import FortiManager


requests.packages.urllib3.disable_warnings()


class FMPolicy(FortiManager):
    """
    This is the class used for interacting with the "policy" API Endpoint. In addition to Policy specific
    methods, the api endpoint default value is set to "policy."
    """

    def __init__(self, host, user, passw, use_ssl=True, verify=False, adom="", package="", api_endpoint="policy",
                 **kwargs):
        super(FMPolicy, self).__init__(host, user, passw, use_ssl, verify, adom, package, api_endpoint, **kwargs)

    def add_config(self, new_config):
        """
        This method is used to submit a configuration request to the FortiManager. Only the object configuration details
        need to be provided; all other parameters that make up the API request body will be handled by the method.

        :param new_config: Type list.
                           The "data" portion of the configuration to be submitted to the FortiManager.
        :return: The response from the API request to add the configuration.
        """
        body = {"method": "add", "params": [{"url": self.pkg_url, "data": new_config, "session": self.session}]}
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
            config = self.config_delete(module, proposed["policyid"])
            changed = True

        return {"changed": changed, "config": config, "existing": existing}

    def config_delete(self, module, policy_id):
        """
        This method is used to handle the logic for Ansible modules when the "state" is set to "absent" and only the
        policy id is provided as input into the Ansible Module. The config_lock is used to lock the configuration if the
        lock param is set to True. The config_response method is used to handle the logic from the response to delete
        the policy.

        :param module: The Ansible Module instance started by the task.
        :param policy_id: Type int.
                          The policy id of the policy to retrieve.
        :return: A dictionary that corresponds to the configuration that was sent in the request body to the
                 FortiManager API. This dict will map to the "config" key returned by the Ansible Module.
        """
        # lock config if set and module not in check mode
        if module.params["lock"] and not module.check_mode:
            self.config_lock(module)

        # configure if not in check mode
        if not module.check_mode:
            response = self.delete_config(policy_id)
            self.config_response(module, response.json(), module.params["lock"])

        return {"method": "delete", "params": [{"url": self.pkg_url + "/{}".format(policy_id)}]}

    def config_move(self, module, policy_id, results):
        """
        This method is used to handle the logic for the Ansible module for moving a Policy. Our testing shows the
        global-label is lost when moving a policy sometimes, so checks are done before and after to ensure it persists
        via re-applying the global-label to the config.

        :param module: The Ansible Module instance started by the task.
        :param policy_id: Type int.
                          The policy id of the policy to retrieve.
        :param results: Type dict.
                        The current results for module exit.
        :return: A dictionary that corresponds to the configuration that was sent in the request body to the
                 FortiManager API. This dict will map to the "config" key returned by the Ansible Module.
        """
        if module.params["direction"]:
            if module.params["session_id"]:
                self.save()
            global_label = self.get_item_fields(policy_id, ["global-label"]).get("global-label", "")

            # retreive reference policies id if not passed to module
            direction = module.params["direction"]
            if module.params["reference_policy_name"]:
                reference_policy = self.get_item_from_name(module.params["reference_policy_name"], module)
                if reference_policy:
                    reference_id = str(reference_policy["policyid"])
                else:
                    # fail if unable to find reference policy on fortimanager
                    results["msg"] = "Unable to Find Reference Policy Name."
                    module.fail_json(**results)
            else:
                reference_id = module.params["reference_policy_id"]

            # validate both proposed and existing policies are found on fortimanager
            proposed_reference = self.get_item_fields(policy_id, ["policyid"])
            existing_reference = self.get_item_fields(int(reference_id), ["policyid"])
            if not proposed_reference or not existing_reference:
                results["msg"] = "Unable to Find the Policies; Please Verify the Policy Params."
                module.fail_json(**results)

            # retrieve proposed and existing policies' sequence number
            all_existing = self.get_all_fields(["policyid"])
            proposed_position = all_existing.index(proposed_reference)
            existing_position = all_existing.index(existing_reference)

            # check if policy is currently in the correct position for idempotency
            if proposed_position - existing_position == 0:
                return {}
            elif direction == "before" and existing_position - proposed_position == 1:
                return {}
            elif direction == "after" and proposed_position - existing_position == 1:
                return {}

            obj_url = self.pkg_url + "/{}".format(str(policy_id))
            move = {"method": "move", "params": [{"url": obj_url, "option": direction, "target": reference_id}]}

            if module.params["lock"]:
                self.config_lock(module)

            # configure if not in check mode
            if not module.check_mode:
                response = self.move_config(policy_id, direction, reference_id)
                status_code = response.json()["result"][0]["status"]["code"]
                if module.params["session_id"]:
                    self.save()

                # re-apply global label after move if it was lost on move
                post_global_label = self.get_item_fields(policy_id, ["global-label"]).get("global-label", "")
                if post_global_label != global_label:
                    self.update_config([{"policyid": policy_id, "global-label": global_label}])
                    if module.params["session_id"]:
                        self.save()

                if status_code == 0 and module.params["lock"]:
                    save_status = self.save()
                    if save_status["result"][0]["status"]["code"] == 0:
                        unlock_status = self.unlock()
                        # fail of unlock is unsuccessful
                        if unlock_status["result"][0]["status"]["code"] != 0:
                            results.update(dict(locked=True, saved=True, unlock=False, moved=move,
                                                msg="Config Updated and Saved, but Unable to Unlock",
                                                fortimanager_response=unlock_status))
                            module.fail_json(**results)
                    else:
                        # attempt to unlock before failing for unsuccessful save
                        unlock_status = self.unlock()
                        if unlock_status["result"][0]["status"]["code"] != 0:
                            # fail with save unsuccessful but unlock successful
                            results.update(dict(locked=True, saved=False, unlocked=False,
                                                msg="Config Updated, but Unable to Save or Unlock",
                                                fortimanager_response=unlock_status))
                            module.fail_json(**results)
                        else:
                            # fail with save and unlock unsuccessful
                            results.update(dict(locked=True, saved=False, unlocked=True,
                                                msg="Config Updated, Unable to Save, but Unlocked"))
                            module.fail_json(**results)
                # do not attempt to save if unsuccessful move, but try to unlock before failing
                elif status_code != 0 and module.params["lock"]:
                    unlock_status = self.unlock()
                    if unlock_status["result"][0]["status"]["code"] == 0:
                        results.update(dict(locked=True, saved=False, unlocked=True,
                                            msg="Policy Move Failed, Did not Save, but Unlocked",
                                            fortimanager_response=response.json(), request_body=response.request.body))
                        module.fail_json(**results)
                    else:
                        results.update(dict(locked=True, saved=False, unlocked=False,
                                            msg="Policy Move Failed, Did not Save and Unable to Unlock",
                                            fortimanager_response=response.json(), request_body=response.request.body))
                        module.fail_json(**results)
                # fail module when move unsuccessful and not in lock mode
                elif status_code != 0:
                    results.update(dict(msg="Policy Move Failed", fortimanager_response=response.json(),
                                        request_body=response.request.body))
                    module.fail_json(**results)

            return move

        else:
            return {}

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
        # fail if policy action is deny and logtraffic is not set to disable or all
        log = module.params.get("log_traffic")
        if module.params["action"] == "deny":
            if log == "utm" or not log:
                module.fail_json(msg="Configuring a new deny policy requires the log_traffic parameter to be set to either"
                                     " disable or all")

        # lock config if set and module not in check mode
        if module.params["lock"] and not module.check_mode:
            self.config_lock(module)

        # configure if not in check mode
        if not module.check_mode:
            response = self.add_config(new_config)
            self.config_response(module, response.json(), module.params["lock"])

            # ensures the policy id is part of the config data for cases where only name is provided.
            new_config.update(response.json()["result"][0]["data"])

        return {"method": "add", "params": [{"url": self.pkg_url, "data": new_config}]}

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

        return {"method": "update", "params": [{"url": self.pkg_url, "data": update_config}]}

    def delete_config(self, policy_id):
        """
        This method is used to submit a configuration request to delete a policy from the FortiManager.

        :param policy_id: Type int.
                          The policy ID of the policy to be removed from the FortiManager.
        :return: The response from the API request to add the configuration.
        """
        item_url = self.pkg_url + "/{}".format(str(policy_id))
        body = {"method": "delete", "params": [{"url": item_url, "session": self.session}]}
        response = self.make_request(body)

        return response

    def get_all(self):
        """
        This method is used to get all objects currently configured on the FortiManager for the ADOM and API Endpoint.

        :return: The list of configuration dictionaries for each object. An empty list is returned if the request does
                 not return any data.
        """
        body = {"method": "get", "params": [{"url": self.pkg_url}], "verbose": 1, "session": self.session}
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
        params = [{"url": self.pkg_url, "fields": fields}]
        body = {"method": "get", "params": params, "verbose": 1, "session": self.session}
        response = self.make_request(body)

        return response.json()["result"][0].get("data", [])

    def get_all_filters(self, filters):
        """
        This method is used to get all polices currently configured on the FortiManager that have configurations
        matching the values provided in filters.

        :param filters: Type dict.
                        A dictionary where the keys match the config parameter from fortimanager, and the
                        values match the value of the configured parameter.
        :return: The list of matching policies. If no policies are matched, an empty list is returned.
        """
        # generate filter list (list of lists with "&&" between them) from match_filters dict, and pop the last "&&"
        filter_list = []
        for k, v in filters.items():
            filter_list.append([k, "==", v])
            filter_list.append("&&")

        filter_list.pop()

        body = dict(method="get", params=[{"url": self.pkg_url, "filter": filter_list}], verbose=1, session=self.session)
        response = self.make_request(body)
        response_data = response.json()["result"][0].get("data")

        if response_data:
            return response_data
        else:
            return []


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
        replace = ["natip", "schedule"]
        ignore = ["name"]
        absent_if_deny = ["ippool", "nat"]
        absent_if_disable = ["ippool", "poolname"]
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            if existing_field and proposed_field != existing_field:
                if field in replace:
                    config[field] = proposed_field
                elif field in ignore:
                    pass
                elif isinstance(existing_field, list):
                    proposed_field = set(proposed_field)
                    if not proposed_field.issubset(existing_field):
                        config[field] = list(proposed_field.union(existing_field))
                elif isinstance(existing_field, dict):
                    config[field] = dict(set(proposed_field.items()).union(existing_field.items()))
                elif isinstance(existing_field, int) or isinstance(existing_field, string_types):
                    config[field] = proposed_field
            elif field not in existing:
                # ignore fields that are not present when action is deny
                if field in absent_if_deny and proposed.get("action", "deny") == "deny":
                    pass
                # ignore fields that are not present when nat is disable
                elif field in absent_if_disable and proposed.get("nat", "disable") == "disable":
                    pass
                else:
                    config[field] = proposed_field

        if config:
            config["policyid"] = proposed["policyid"]

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
        ignore = ["natip", "schedule"]
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
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
            config["policyid"] = proposed["policyid"]

        return config

    def get_item(self, policy_id):
        """
        This method is used to get a specific object currently configured on the FortiManager for the ADOM and API
        Endpoint.

        :param policy_id: Type int.
                          The policy id of the policy to retrieve.
        :return: The configuration dictionary for the object. An empty dict is returned if the request does
                 not return any data.
        """
        object_url = self.pkg_url + "/{}".format(policy_id)
        body = {"method": "get", "params": [{"url": object_url}], "verbose": 1, "session": self.session}

        response = self.make_request(body)

        return response.json()["result"][0].get("data", {})

    def get_item_fields(self, policy_id, fields):
        """
        This method is used to get a specific object currently configured on the FortiManager for the ADOM and API
        Endpoint. The configuration fields retrieved are limited to the list defined in the fields variable.

        :param policy_id: Type str.
                          The policy id of the policy to retrieve.
        :param fields: Type list.
                       The list of fields to return for each object.
        :return: The list of configuration dictionaries for each object. An empty list is returned if the request does
                 not return any data.
        """
        params = [{"url": self.pkg_url, "filter": ["policyid", "==", policy_id], "fields": fields}]
        body = {"method": "get", "params": params, "verbose": 1, "session": self.session}
        response = self.make_request(body)
        response_data = response.json()["result"][0].get("data", [{}])

        if response_data:
            return response_data[0]
        else:
            return {}

    def get_item_from_name(self, name, module):
        """
        This method is used to get a specific policy configured on the FortiManager using the policy's name.

        :param name: Type str.
                     The name of the policy to retrieve.
        :param module: The Ansible Module instance started by the task.
        :return: Type dict
                 The policy that has a name matching the name argument. If no policies are found, then an empty
                 dict is returned.
        """
        body = dict(method="get", params=[{"url": self.pkg_url, "filter": ["name", "==", name]}],
                verbose=1, session=self.session)

        response = self.make_request(body)
        response_json = response.json()

        if response_json["result"][0]["status"]["code"] != 0:
            module.fail_json(msg="This Fortimanager does not support policy names, please remove the policy_name parameter from task")

        response_data = response_json["result"][0]["data"]

        if response_data:
            return response_data[0]
        else:
            return {}

    def move_config(self, policy_id, direction, target):
        """
        This method is used to move a policy either before or after the target.

        :param policy_id: Type int.
                          The policy ID that should be moved.
        :param direction: Type str.
                          Where the policy should be placed in reference to the target. Options are "before" or "after."
        :param target: Type str.
                       The policy ID used as a reference for moving the "policy_id"
        :return: The response from the API request ot move the policy.
        """
        object_url = self.pkg_url + "/{}".format(str(policy_id))
        body = {"method": "move", "params": [{"url": object_url, "option": direction, "target": target}],
                "session": self.session}

        response = self.make_request(body)

        return response

    @staticmethod
    def param_normalizer(params):
        """
        This method is used to take a list of Ansible module param namess and return the list of their equivalent
        fortimanager param names. This is useful for the get_all_filters() method.

        :param params: Type list.
                       The list of param names passed into the Ansible module.
        :return: A list of the equivalent FortiManager parameter names.
        """
        param_dict = dict(
            action="action",
            comment="comments",
            destination_address="dstaddr",
            destination_intfc="dstintf",
            global_label="global-label",
            ip_pool="ippool",
            label="label",
            log_traffic="logtraffic",
            log_traffic_start="logtraffic-start",
            policy_name="name",
            nat="nat",
            nat_ip="natip",
            permit_any_host="permit-any-host",
            policy_id="policyid",
            pool_name="poolname",
            schedule="schedule",
            service="service",
            source_address="srcaddr",
            source_intfc="srcintf",
            status="status"
        )
        fm_list = []
        for entry in params:
            fm_list.append(param_dict[entry])

        return fm_list

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
        body = {"method": "update", "params": [{"url": self.pkg_url, "data": update_config, "session": self.session}]}
        response = self.make_request(body)

        return response


VALID_MATCH_FILTERS = [
    "all",
    "action",
    "comment",
    "destination_address",
    "destination_intfc",
    "global_label",
    "ip_pool",
    "label",
    "log_traffic",
    "log_traffic_start",
    "nat",
    "nat_ip",
    "permit_any_host",
    "pool_name",
    "schedule",
    "service",
    "source_address",
    "source_intfc",
]


def main():
    base_argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        lock=dict(required=False, type="bool"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        session_id=dict(required=False, type="str"),
        state=dict(choices=["absent", "param_absent", "present"], default="present", type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        action=dict(choices=["accept", "deny", "ipsec", "ssl-vpn"], required=False, type="str"),
        comment=dict(required=False, type="str"),
        destination_address=dict(required=False, type="list"),
        destination_intfc=dict(required=False, type="list"),
        direction=dict(choices=["before", "after"], required=False, type="str"),
        global_label=dict(required=False, type="str"),
        ip_pool=dict(choices=["enable", "disable"], required=False, type="str"),
        label=dict(required=False, type="str"),
        log_traffic=dict(choices=["disable", "all", "utm"], required=False, type="str"),
        log_traffic_start=dict(choices=["enable", "disable"], required=False, type="str"),
        match_filter=dict(required=False, type="bool"),
        match_filters=dict(required=False, type="list"),
        nat=dict(choices=["enable", "disable"], required=False, type="str"),
        nat_ip=dict(required=False, type="list"),
        package=dict(required=False, type="str"),
        permit_any_host=dict(choices=["enable", "disable"], required=False, type="str"),
        policy_id=dict(required=False, type="int"),
        policy_name=dict(required=False, type="str"),
        pool_name=dict(required=False, type="list"),
        reference_policy_id=dict(required=False, type="str"),
        reference_policy_name=dict(required=False, type="str"),
        schedule=dict(required=False, type="list"),
        service=dict(required=False, type="list"),
        source_address=dict(required=False, type="list"),
        source_intfc=dict(required=False, type="list"),
        status=dict(choices=["enable", "disable"], required=False, type="str")
    )
    argument_spec = base_argument_spec
    argument_spec["provider"] = dict(required=False, type="dict", options=base_argument_spec)

    module = AnsibleModule(argument_spec, supports_check_mode=True)
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
    package = module.params["package"]
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
    destination_address = module.params["destination_address"]
    if isinstance(destination_address, str):
        destination_address = [destination_address]
    destination_intfc = module.params["destination_intfc"]
    if isinstance(destination_intfc, str):
        destination_intfc = [destination_intfc]
    direction = module.params["direction"]
    match_filter = module.params["match_filter"]
    match_filters = module.params["match_filters"]
    if match_filter and match_filters is None:
        match_filters = ["source_address", "source_intfc", "destination_address", "destination_intfc", "service"]
    elif isinstance(match_filters, str):
        match_filters = [match_filters]
    nat_ip = module.params["nat_ip"]
    if isinstance(nat_ip, str):
        nat_ip = [nat_ip]
    policy_id = module.params["policy_id"]
    if isinstance(policy_id, str):
        policy_id = int(policy_id)
    policy_name = module.params["policy_name"]
    pool_name = module.params["pool_name"]
    if isinstance(pool_name, str):
        pool_name = [pool_name]
    reference_policy_id = module.params["reference_policy_id"]
    if isinstance(reference_policy_id, int):
        reference_policy_id = str(reference_policy_id)
    reference_policy_name = module.params["reference_policy_name"]
    schedule = module.params["schedule"]
    if isinstance(schedule, str):
        schedule = [schedule]
    service = module.params["service"]
    if isinstance(service, str):
        service = [service]
    source_address = module.params["source_address"]
    if isinstance(source_address, str):
        source_address = [source_address]
    source_intfc = module.params["source_intfc"]
    if isinstance(source_intfc, str):
        source_intfc = [source_intfc]

    # validate match_filters is not used with policy_name or policy_id
    if match_filters and not match_filter:
        module.fail_json(msg="match_filter and match_filters must be used together; missing match_filter")
    elif match_filter and policy_id:
        module.fail_json(msg="match_filter and policy_id cannot be used together.")
    elif match_filter and policy_name:
        module.fail_json(msg="match_filter and policy_name cannot be used together.")

    # validate match_filters are valid
    if match_filters:
        for filt in match_filters:
            if filt not in VALID_MATCH_FILTERS:
                module.fail_json(msg="{} is not a valid filter option".format(filt), valid_filters=VALID_MATCH_FILTERS)

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, host=host, package=package)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    # check that required arguments are passed for policy move before making any changes.
    if reference_policy_id and not direction:
        module.fail_json(msg="passing the direction argument is required when passing reference_policy_id")
    elif reference_policy_name and not direction:
        module.fail_json(msg="passing the direction argument is required when passing reference_policy_name")

    args = {
        "action": module.params["action"],
        "comments": module.params["comment"],
        "dstaddr": destination_address,
        "dstintf": destination_intfc,
        "global-label": module.params["global_label"],
        "ippool": module.params["ip_pool"],
        "label": module.params["label"],
        "logtraffic": module.params["log_traffic"],
        "logtraffic-start": module.params["log_traffic_start"],
        "name": policy_name,
        "nat": module.params["nat"],
        "natip": nat_ip,
        "permit-any-host": module.params["permit_any_host"],
        "policyid": policy_id,
        "poolname": pool_name,
        "schedule": schedule,
        "service": service,
        "srcaddr": source_address,
        "srcintf": source_intfc,
        "status": module.params["status"]
    }

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FMPolicy(host, username, password, use_ssl, validate_certs, adom, package, **kwargs)
    if not session_id:
        session_login = session.login()
        if not session_login.json()["result"][0]["status"]["code"] == 0:
            module.fail_json(msg="Unable to login", fortimanager_response=session_login.json())
    else:
        session.session = session_id

    # add policy id if only name is provided in the module arguments or using match_filters
    if policy_name and not policy_id:
        policy = session.get_item_from_name(policy_name, module)
        if policy:
            proposed["policyid"] = policy["policyid"]
    elif match_filters:
        if "all" in match_filters:
            fortimanager_filters = proposed.keys()
        else:
            fortimanager_filters = FMPolicy.param_normalizer(match_filters)

        filters = {}
        for filt in fortimanager_filters:
            if filt not in proposed:
                module.fail_json(msg="All match_filters entries must have a value passed to the module; missing {}".format(filt))
            else:
                filters[filt] = proposed[filt]

        policies = session.get_all_filters(filters)

        if len(policies) == 1:
            proposed["policyid"] = policies[0]["policyid"]
        elif len(policies) > 1:
            module.fail_json(msg="Multiple polices were matched based on match_filters, please specify the policy_id or policy_name",
                             matched_policies=policies)

    # get existing configuration from fortimanager and make necessary changes
    if "policyid" in proposed:
        existing = session.get_item(proposed["policyid"])
    else:
        existing = {}

    # fail if name and policy id are both supplied and do not match existing.
    if "name" in proposed and existing and proposed["name"] != existing["name"]:
        module.fail_json(msg="When both policy_id and policy_name are supplied, they must match the existing"
                             " configuration. To rename a policy, create a task that will ensure the policy does not"
                             " existing, and re-create the policy.")

    if state == "present":
        results = session.config_present(module, proposed, existing)
    elif state == "absent":
        results = session.config_absent(module, proposed, existing)
    else:
        results = session.config_param_absent(module, proposed, existing)

    # if module has made it this far and lock set, then all related return values are true
    if lock and results["changed"]:
        locked = dict(locked=True, saved=True, unlocked=True)
        results.update(locked)


    if state != "absent":
        # get policy id to be used to move the policy to the correct order per module params
        if "policyid" in proposed:
            policy_id = proposed["policyid"]
        else:
            policy_id = results["config"]["id"]

        moved = session.config_move(module, policy_id, results)

        # if module has made it this far and lock set, then all related return values are true
        if moved and lock:
            results.update(dict(moved=moved, changed=True, locked=True, saved=True, unlocked=True))
        elif moved:
            results.update(dict(moved=moved, changed=True))
        else:
            results["moved"] = moved
    else:
        results["moved"] = {}

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)


if __name__ == "__main__":
    main()

