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
module: fortimgr_address_map
version_added: "2.3"
short_description: Manages Address mapped resources and attributes
description:
  - Manages FortiManager Address dynamic_mapping configurations using jsonrpc API
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
      - absent will delete the mapping from the object if it exists.
      - param_absent will remove passed params from the object config if necessary and possible.
      - present will create configuration for the mapping correlating to the fortigate specified if needed.
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
  vdom:
    description:
      - The vdom on the fortigate that the config should be associated to.
    required: true
    type: str
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
  fortimgr_address_map:
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
    fortigate: "lab_fortigate"
    vdom: "root"
- name: Modify iprange Address range
  fortimgr_address_map:
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
    fortigate: "lab_fortigate"
    vdom: "root"
- name: Add ipmask Address
  fortimgr_address_map:
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
    fortigate: "new_lab_fortigate"
    vdom: "root"
- name: Remove Fortigate Mapping
  fortimgr_address_map:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    use_ssl: False
    adom: "lab"
    address_name: "server01"
    fortigate: "lab_fortigate"
    vdom: "root"
    state: "absent"
'''

RETURN = '''
existing:
    description: The existing dynamic_mapping configuration for the Address (uses address_name) before the task
                 executed.
    returned: always
    type: dict
    sample: {"dynamic_mapping": [{"_scope": [{"name": "Prod_Fortigate", "vdom": "root"}],"allow-routing": "disable",
             "associated-interface": "any",  "color": 0,  "comment": "Web Servers", "subnet": ["10.20.35.0",
             "255.255.255.128"], "type": "ipmask", "uuid": "f81ef580-3f5e-51e7-c79b-c658a8f6b12e", "visibility":
             "enable"}, {"_scope": [{"name": "DR_Fortigate", "vdom": "root"}], "allow-routing": "disable",
             "associated-interface": "any", "color": 0, "comment": "Web Servers", "subnet": ["10.20.45.128",
             "255.255.255.128"], "type": "ipmask", "uuid": "99d6ed64-3fbf-51e7-72fb-6b3d28fb1b9d", "visibility":
             "enable"}], "name": "Web_Servers"}
config:
    description: The configuration that was pushed to the FortiManager. When an update is made to the configuration,
                 all mappings are included in the config sent to the FortiManager API in order to prevent the other
                 mappings from being removed from the configuration.
    returned: always
    type: dict
    sample: {"method": "update","params": [{ "data": {"dynamic_mapping": [{"_scope": [{"name": "Prod_Fortigate", "vdom":
             "root"}], "subnet": ["10.20.35.0", "255.255.255.128"]}, {"_scope": [{"name": "DR_Fortigate", "vdom": "root"
             }]}], "name": "Web_Servers"}, "id": 1, "url": "/pm/config/adom/lab/obj/firewall/address"}]}
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
                                if not porposed_field.issubset(existing_field):
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
        color=dict(required=False, type="int"),
        comment=dict(required=False, type="str"),
        end_ip=dict(required=False, type="str"),
        fortigate=dict(required=False, type="str"),
        fqdn=dict(required=False, type="str"),
        network_address=dict(required=False, type="str"),
        network_mask=dict(required=False, type="str"),
        start_ip=dict(required=False, type="str"),
        subnet=dict(required=False, type="list"),
        vdom=dict(required=False, type="str"),
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
    color = module.params["color"]
    if isinstance(color, str):
        color = int(color)
    fortigate = module.params["fortigate"]
    network_address = module.params["network_address"]
    network_mask = module.params["network_mask"]
    subnet = module.params["subnet"]
    if isinstance(subnet, str):
        subnet = [subnet]
    vdom = module.params["vdom"]
    wildcard = module.params["wildcard"]
    if isinstance(wildcard, str):
        wildcard = [wildcard]
    wildcard_address = module.params["wildcard_address"]
    wildcard_mask = module.params["wildcard_mask"]

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, host=host, address_name=address_name, fortigate=fortigate, vdom=vdom)
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
        "color": color,
        "comment": module.params["comment"],
        "end-ip": module.params["end_ip"],
        "fortigate": fortigate,
        "fqdn": module.params["fqdn"],
        "name": address_name,
        "start-ip": module.params["start_ip"],
        "subnet": subnet,
        "type": module.params["address_type"],
        "vdom": vdom,
        "wildcard": wildcard,
        "wildcard-fqdn": module.params["wildcard_fqdn"]
    }

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed_args = dict((k, v) for k, v in args.items() if v)

    proposed = dict(
        name=proposed_args.pop("name"),
        dynamic_mapping=[{
            "_scope": [{
                "name": proposed_args.pop("fortigate"),
                "vdom": proposed_args.pop("vdom")
            }],
        }]
    )

    for k, v in proposed_args.items():
        proposed["dynamic_mapping"][0][k] = v

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
    existing = session.get_item_fields(proposed["name"], ["name", "dynamic_mapping"])
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

