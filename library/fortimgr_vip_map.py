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
module: fortimgr_vip_mapping
version_added: "2.3"
short_description: Manages VIP mapped resources and attributes
description:
  - Manages FortiManager VIP dynamic_mapping configurations using jsonrpc API
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
    type: str
  external_ip:
    description:
      - The external IP or IP range that will be NAT'ed to the internal mapped IP.
    required: false
    type: list
  fortigate:
    description:
      - The name of the fortigate to map the configuration to.
    required: false
    type: str
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
  type:
    description:
      - The source interface which will be used to filter when the NAT takes place.
    required: false
    type: str
  vdom:
    description:
      - The vdom on the fortigate that the config should be associated to.
    required: true
    type: str
  vip_name:
    description:
      - The name of the VIP.
    required: true
    type: str
'''

EXAMPLES = '''
- name: Add VIP With Mapping
  fortimgr_vip_map:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    fortigate: "Prod"
    vdom: "root"
    vip_name: "App02_VIP"
    type: "static-nat"
    external_ip: "100.10.10.12"
    mapped_ip: "10.10.10.12"
    comment: "App02 VIP"
- name: Modify VIP
  fortimgr_vip_map:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    fortigate: "Prod"
    vdom: "root"
    vip_name: "App02_VIP"
    external_intfc: "port2"
    validate_certs: True
    port: 8443
- name: Add Mapping to VIP
  fortimgr_vip_map:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    fortigate: "DR"
    vdom: "lab"
    vip_name: "App02_VIP"
    type: "static-nat"
    external_ip: "100.10.10.12"
    mapped_ip: "10.10.10.12"
    external_intfc: "port2"
    internal_intfc: "port1"
    comment: "App02 VIP"
- name: Remove Mapping from VIP
  fortimgr_vip_map:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    use_ssl: False
    adom: "lab"
    fortigate: "DR"
    vdom: "lab"
    vip_name: "App02_VIP"
    state: "absent"
'''

RETURN = '''
existing:
    description: The existing dynamic_mapping configuration for the VIP (uses vip_name) before the task executed.
    returned: always
    type: dict
    sample: {"dynamic_mapping": [{"_if_no_default": 0, "_scope": [{"name": "Prod", "vdom": "root"}], "arp-reply":
             "enable", "color": 0, "comment": "", "dns-mapping-ttl": 0, "extintf": "", "extip": ["100.10.10.12"],
             "gratuitous-arp-interval": 0, "http-ip-header-name": "", "id": 0, "mappedip": ["10.10.10.12"],
             "nat-source-vip": "disable", "portforward": "disable", "type": "static-nat",
             "uuid": "037f79c6-4f82-51e7-ceb7-40422d221441"}], "name": "App02_VIP"}
config:
    description: The configuration that was pushed to the FortiManager.
    returned: always
    type: dict
    sample: {"method": "update", "params": [{"data": {"dynamic_mapping": [{"_scope": [{"name": "DR", "vdom": "root"}],
             "extip": ["100.10.20.12"], "mappedip": ["10.10.20.12"], "type": "static-nat"}, {"_scope": [{"name":
             "Prod", "vdom": "root"}]}], "name": "App02_VIP"}, "url": "/pm/config/adom/lab/obj/firewall/vip"}]}
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
from ansible.module_utils.fortimgr_fmvip import FMVIP


requests.packages.urllib3.disable_warnings()


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
        arp_reply=dict(choices=["enable", "disable"], required=False, type="str"),
        color=dict(required=False, type="int"),
        comment=dict(required=False, type="str"),
        external_intfc=dict(required=False, type="str"),
        external_ip=dict(required=False, type="list"),
        fortigate=dict(required=False, type="str"),
        mapped_ip=dict(required=False, type="list"),
        source_filter=dict(required=False, type="list"),
        type=dict(choices=["static-nat", "fqdn", "dns-translation"], type="str"),
        vdom=dict(required=False, type="str"),
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
    external_ip = module.params["external_ip"]
    if isinstance(external_ip, str):
        external_ip = [external_ip]
    fortigate = module.params["fortigate"]
    mapped_ip = module.params["mapped_ip"]
    if isinstance(mapped_ip, str):
        mapped_ip = [mapped_ip]
    source_filter = module.params["source_filter"]
    if isinstance(source_filter, str):
        source_filter = [source_filter]
    vdom = module.params["vdom"]
    vip_name = module.params["vip_name"]

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, fortigate=fortigate, host=host, vdom=vdom, vip_name=vip_name)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    args = {
        "arp-reply": module.params["arp_reply"],
        "color": color,
        "comment": module.params["comment"],
        "extintf": module.params["external_intfc"],
        "extip": external_ip,
        "fortigate": fortigate,
        "mappedip": mapped_ip,
        "name": vip_name,
        "src-filter": source_filter,
        "type": module.params["type"],
        "vdom": vdom
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
    session = FMVIP(host, username, password, use_ssl, validate_certs, adom, **kwargs)
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

