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
module: fortimgr_service
version_added: "2.3"
short_description: Manages Service resources and attributes
description:
  - Manages FortiManager Service configurations using jsonrpc API
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
  category:
    description:
      - The category of the service object.
    choices: ["Uncategorized", "Authentication", "Email", "File Access", "General", "Network Services", "Remote Access",
              "Tunneling", "VoIP, Messaging & Other Applications", "Web Access", "Web Proxy"]
    required: false
    type: list
  color:
    description:
      - A tag that can be used to group objects
    required: false
    type: int
  comment:
    description:
      - A comment to add to the Service
    required: false
    type: str
  explicit_proxy:
    description:
      - Used to set the explicit-proxy service for the Service object.
    required: false
    type: str
    options: ["enable", "disable"]
  icmp_code:
    description:
      - The ICMP code for when protocol is set to ICMP.
    required: false
    type: int
  icmp_type:
    description:
      - The ICMP type for when the protocol is set to ICMP.
    required: false
    type: int
  port_range:
    description:
      - The range of TCP or UDP ports associated with the service object.
    required: false
    type: list
  protocol:
    description:
      - Used to specify the service's protocol type.
    required: false
    type: str
    options: ["ICMP", "IP", "TCP", "UDP", "SCTP", "ICMP6", "HTTP", "FTP", "CONNECT", "ALL", "SOCKS-TCP", "SOCKS-UDP"]
  protocol_number:
    description:
      - Used to specify the IP protocol number when protocol is set to IP.
    required: false
    type: int
  service_name:
    description:
      - The name of the service.
    required: true
    type: str
'''

EXAMPLES = '''
- name: Add Service Object
  fortimgr_service:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    service_name: "App01_Web"
    protocol: "TCP"
    port_range:
      - "80"
      - "443"
      - "8443"
    comment: "App01 Web Services"
- name: Remove Port from Service
  fortimgr_service:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    service_name: "App01_Web"
    protocol: "TCP"
    port_range: "80"
    validate_certs: True
    state: "param_absent"
- name: Add ICMP Service Object
  fortimgr_service:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    service_name: "ICMP_Echo"
    protocol: "ICMP"
    icmp_code: 0
    icmp_type: 8
- name: Delete Service Object
  fortimgr_service:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    use_ssl: False
    adom: "lab"
    service_name: "App01_Web"
    state: "absent"
'''

RETURN = '''
existing:
    description: The existing configuration for the Service (uses service_name) before the task executed.
    returned: always
    type: dict
    sample: {"check-reset-range": "default", "color": 0, "comment": "", "explicit-proxy": "disable", "fqdn":"",
             "iprange": "0.0.0.0", "name": "SSL_443", "protocol": "TCP/UDP/SCTP", "session-ttl": 0,
             "tcp-halfclose-timer": 0, "tcp-halfopen-timer": 0, "tcp-portrange": "443", "tcp-timewait-timer": 0,
             "udp-idle-timer": 0, "visibility": "enable"}
config:
    description: The configuration that was pushed to the FortiManager.
    returned: always
    type: dict
    sample: {"method": "add", "params": [{"url: "/pm/config/adom/lab/obj/firewall/service", "data":[{"name": "HTTP_80",
             "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"}]}]}
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


class FMService(FortiManager):
    """
    This is the class used for interacting with the "service" API Endpoint. In addition to service specific
    methods, the api endpoint default value is set to "service/custom."
    """

    def __init__(self, host, user, passw, use_ssl=True, verify=False, adom="", package="",
                 api_endpoint="service/custom", **kwargs):
        super(FMService, self).__init__(host, user, passw, use_ssl, verify, adom, package, api_endpoint, **kwargs)

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
            # icmp type and code values can be 0, so check includes existing == 0
            if (existing_field or existing_field == 0) and proposed_field != existing_field:
                if field in ["tcp-portrange", "udp-portrange"]:
                    # ensure proposed port range is a list of strings
                    proposed_field = {str(entry) for entry in proposed_field}
                    if not isinstance(existing_field, list):
                        # port ranges with multiple port entries are in list format, where port ranges of one are in str format
                        existing_field = [existing_field]
                    if not proposed_field.issubset(existing_field):
                        config[field] = list(proposed_field.union(existing_field))
                elif isinstance(existing_field, list):
                    existing_field = set(existing_field)
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
            if field in ["tcp-portrange", "udp-portrange"]:
                # ensure proposed port range is a list of strings
                proposed_field = [str(entry) for entry in proposed_field]
                # port ranges with multiple port entries are in list format, where port ranges of one are in str format
                if not isinstance(existing_field, list):
                    # port ranges with multiple port entries are in list format, where port ranges of one are in str format
                    existing_field = {existing_field}
                else:
                    existing_field = set(existing_field)
                diff = existing_field.difference(proposed_field)
                if diff != existing_field:
                    config[field] = list(diff)
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


CATEGORY = [
    "Uncategorized",
    "Authentication",
    "Email",
    "File Access",
    "General",
    "Network Services",
    "Remote Access",
    "Tunneling",
    "VoIP, Messaging & Other Applications",
    "Web Access",
    "Web Proxy",
    "uncategorized",
    "authentication",
    "email",
    "file access",
    "general",
    "network services",
    "remote access",
    "tunneling",
    "voip,messaging & other applications",
    "web access",
    "web proxy",
]

PROTOCOL = [
    "ICMP",
    "IP",
    "TCP",
    "UDP",
    "SCTP",
    "ICMP6",
    "HTTP",
    "FTP",
    "CONNECT",
    "ALL",
    "SOCKS-TCP",
    "SOCKS-UDP",
    "icmp",
    "ip",
    "tcp",
    "udp",
    "sctp",
    "icmp6",
    "http",
    "ftp",
    "connect",
    "all",
    "socks-tcp",
    "socks-udp",
]


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
        category=dict(choices=CATEGORY, required=False, type="list"),
        color=dict(required=False, type="int"),
        comment=dict(required=False, type="str"),
        explicit_proxy=dict(choices=["enable", "disable"], required=False, type="str"),
        icmp_code=dict(required=False, type="int"),
        icmp_type=dict(required=False, type="int"),
        port_range=dict(required=False, type="list"),
        protocol=dict(choices=PROTOCOL, required=False, type="str"),
        protocol_number=dict(required=False, type="int"),
        service_name=dict(required=False, type="str")
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
    category = module.params["category"]
    if isinstance(category, list):
        category = [item.title() for item in category]
    elif isinstance(category, str):
        category = [category.title()]
    color = module.params["color"]
    if color:
        color = int(color)
    icmp_code = module.params["icmp_code"]
    if icmp_code:
        icmp_code = int(icmp_code)
    icmp_type = module.params["icmp_type"]
    if icmp_type:
        icmp_type = int(icmp_type)
    port_range = module.params["port_range"]
    if isinstance(port_range, str) or isinstance(port_range, int):
        port_range = [port_range]
    protocol_number = module.params["protocol_number"]
    if isinstance(protocol_number, str):
        protocol_number = str(protocol_number)
    service_name = module.params["service_name"]

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, host=host, service_name=service_name)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))
            
    args = {
        "category": category,
        "color": color,
        "comment": module.params["comment"],
        "explicit-proxy": module.params["explicit_proxy"],
        "icmpcode": icmp_code,
        "icmptype": icmp_type,
        "protocol-number": protocol_number,
        "name": service_name
    }

    # convert argument protocol inputs to fortimanager format
    if module.params["protocol"] in ["TCP", "SOCKS-TCP", "tcp", "socks-tcp"]:
        args["protocol"] = "TCP/UDP/SCTP"
        args["tcp-portrange"] = port_range
    elif module.params["protocol"] in ["UDP", "SOCKS-UDP", "udp", "socks-udp"]:
        args["protocol"] = "TCP/UDP/SCTP"
        args["udp-portrange"] = port_range
    elif module.params["protocol"] in ["SCTP", "sctp"]:
        args["protocol"] = "TCP/UDP/SCTP"
    elif module.params["protocol"]:
        args["protocol"] = module.params["protocol"].upper()

    # icmp_code and icmp_type can have value of 0, so check is made for 0 values.
    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v == 0 or v)

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FMService(host, username, password, use_ssl, validate_certs, adom, **kwargs)
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

