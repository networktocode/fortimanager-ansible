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
module: fortimgr_vip
version_added: "2.3"
short_description: Manages VIP resources and attributes
description:
  - Manages FortiManager VIP configurations using jsonrpc API
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
      - absent will delete the object if it exists.
      - param_absent will remove passed params from the object config if necessary and possible.
      - present will create the configuration if needed.
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
  arp_reply:
    description:
      - Allows the fortigate to reply to ARP requests.
    required: false
    type: str
    choices: ["enable", "disable"]
  color:
    description:
      - A tag that can be used to group objects.
    required: false
    type: int
  comment:
    description:
      - A comment to add to the VIP.
    required: false
    type: str
  external_intfc:
    description:
      - The associated external interface
    required: false
    type: list
  external_ip:
    description:
      - The external IP or IP range that will be NAT'ed to the internal mapped IP.
    required: false
    type: list
  mapped_ip:
    description:
      - The address or address range used that the external IP will be mapped to.
    required: false
    type: list
  source_filter:
    description:
      - The source IP addresses which will be used to filter when the NAT takes place.
    required: false
    type: list
  source_intfc:
    description:
      - The source interface which will be used to filter when the NAT takes place.
    required: false
    type: list
  type:
    description:
      - The type of service the VIP will offer.
    required: false
    type: str
    choices: ["static-nat", "fqdn", "dns-translation"]
  vip_name:
    description:
      - The name of the VIP.
    required: true
    type: str
'''

EXAMPLES = '''
- name: Add VIP Object
  fortimgr_vip:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    vip_name: "App01_VIP"
    type: "static-nat"
    external_ip: "100.10.10.10"
    mapped_ip: "10.10.10.10"
    comment: "App01 Web Services"
- name: Modify VIP
  fortimgr_vip:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    vip_name: "App01_VIP"
    external_intfc: "port2"
    validate_certs: True
    port: 8443
- name: Delete VIP Object
  fortimgr_vip:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    use_ssl: False
    adom: "lab"
    vip_name: "App01_VIP"
    state: "absent"
'''

RETURN = '''
existing:
    description: The existing configuration for the VIP (uses vip_name) before the task executed.
    returned: always
    type: dict
    sample: {"_if_no_default": 0, "arp-reply": "enable", "color": 0, "comment": "", "dns-mapping-ttl": 0, "extip":
             ["100.10.10.10"], "gratuitous-arp-interval": 0, "http-ip-header-name": "", "id": 0, "mappedip":
             ["10.10.10.10"], "name": "Service02",   "nat-source-vip": "disable", "portforward": "disable",
             "src-filter": [], "type": "static-nat", "uuid": "8391f9b0-4f80-51e7-d192-d83610282885"}
config:
    description: The configuration that was pushed to the FortiManager.
    returned: always
    type: dict
    sample: {"method": "add", "params": [{"data": "name": "Service02", "type": "static-nat", {"extip": ["100.10.10.11"],
             "mappedip": ["10..10.10.11"]}, "url": "/pm/config/adom/lab/obj/firewall/vip"}]}
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


class FMVIP(FortiManager):
    """
    This is the class used for interacting with the "vip" API Endpoint. In addition to service specific
    methods, the api endpoint default value is set to "vip."
    """

    def __init__(self, host, user, passw, use_ssl=True, verify=False, adom="", package="",
                 api_endpoint="vip", **kwargs):
        super(FMVIP, self).__init__(host, user, passw, use_ssl, verify, adom, package, api_endpoint, **kwargs)

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
        replace = ["extintf", "extip"]
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
                    replace = ["extintf", "extip"]
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
        ignore = ["extintf", "extip"]
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            if field in ignore:
                pass
            elif field == "mappedip" and len(existing.get("mappedip", [])) < 2:
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
                    ignore = ["extintf", "extip"]
                    present = True
                    updated_map = {}
                    for field in proposed_map.keys():
                        proposed_field = proposed_map[field]
                        existing_field = mapping.get(field)
                        if field in ignore:
                            pass
                        elif field == "mappedip" and len(mapping.get(field, [])) < 2:
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
        state=dict(choices=["absent", "param_absent", "present"], required=False, type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        arp_reply=dict(choices=["enable", "disable"], required=False, type="str"),
        color=dict(required=False, type="int"),
        comment=dict(required=False, type="str"),
        external_intfc=dict(required=False, type="list"),
        external_ip=dict(required=False, type="list"),
        mapped_ip=dict(required=False, type="list"),
        source_filter=dict(required=False, type="list"),
        source_intfc=dict(required=False, type="list"),
        type=dict(choices=["static-nat", "fqdn", "dns-translation"], type="str"),
        vip_name=dict(required=False, type="str")
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
    color = module.params["color"]
    if color:
        color = int(color)
    external_intfc = module.params["external_intfc"]
    if isinstance(external_intfc, str):
        external_intfc = [external_intfc]
    external_ip = module.params["external_ip"]
    if isinstance(external_ip, str):
        external_ip = [external_ip]
    mapped_ip = module.params["mapped_ip"]
    if isinstance(mapped_ip, str):
        mapped_ip = [mapped_ip]
    source_filter = module.params["source_filter"]
    if isinstance(source_filter, str):
        source_filter = [source_filter]
    source_intfc = module.params["source_intfc"]
    if isinstance(source_intfc, str):
        source_intfc = [source_intfc]
    vip_name = module.params["vip_name"]

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, host=host, vip_name=vip_name)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    args = {
        "arp-reply": module.params["arp_reply"],
        "color": color,
        "comment": module.params["comment"],
        "extintf": external_intfc,
        "extip": external_ip,
        "mappedip": mapped_ip,
        "name": vip_name,
        "src-filter": source_filter,
        "srcintf-filter": source_intfc,
        "type": module.params["type"]
    }

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FMVIP(host, username, password, use_ssl, validate_certs, adom, **kwargs)
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

