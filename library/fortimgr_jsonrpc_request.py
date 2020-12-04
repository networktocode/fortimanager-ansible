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
module: fortimgr_jsonrpc_request
version_added: "2.3"
short_description: Sends generic json-rpc request
description:
  - Sends generic FortiManager json-rpc API requests
author: JC Sicard (@jcsicard), derived from Jacob McGill (@jmcgill298) work
options:
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
    required: false
    type: str
  validate_certs:
    description:
      - Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)
    required: false
    default: False
    type: bool
  method:
    description:
      - The JSON-RPC request method
    required: true
    type: str
    choices: ["get", "add", "set", "update", "delete", "move", "clone", "replace", "exec"]    
  params:
    description:
      - JSON-RPC request parameters (as a JSON list).
    required: true
    type: list
'''

EXAMPLES = '''
    - name: GET STATUS
      fortimgr_jsonrpc_request:
        host: "{{ ansible_host }}"
        username: "{{ ansible_user }}"
        password: "{{ ansible_password }}"
        method: get
        params: [{url: "/sys/status/"}]
      register: 
    
    - name: CREATE ADOM
      fortimgr_jsonrpc_request:
        host: "{{ ansible_host }}"
        username: "{{ ansible_user }}"
        password: "{{ ansible_password }}"
        method: add
        params: [{
            url: "/dvmdb/adom",
            data: [{
              name: "lab",
              desc: "lab adom"
	        }]
          }]
'''

RETURN = '''
response:
    description: The json results from ADOM request.
    returned: Always
    type: list
    sample: [{"result": [{"status": {"code": 0, "message": "OK"}, "url": "/dvmdb/adom"}]}]
status:
    description: The json-rpc request's repsonse status code and message
    returned: Always
    type: dict
    sample: {"code": 0, "message": "OK"}  
'''

import time
import json

import requests
from ansible import __version__ as ansible_version
if float(ansible_version[:3]) < 2.4:
    raise ImportError("Ansible versions below 2.4 are not supported")
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.six import string_types
from ansible.module_utils.fortimgr_fortimanager import FortiManager

requests.packages.urllib3.disable_warnings()


def main():
    base_argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        lock=dict(required=False, type="bool"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        session_id=dict(required=False, type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        method=dict(required=True, type="str"),
        params=dict(required=True, type="list")
    )
    argument_spec = base_argument_spec
    argument_spec["provider"] = dict(required=False, type="dict", options=base_argument_spec)

    module = AnsibleModule(argument_spec, supports_check_mode=False)
    provider = module.params["provider"] or {}

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
    if use_ssl is None:
        use_ssl = True
    username = module.params["username"]
    validate_certs = module.params["validate_certs"]
    if validate_certs is None:
        validate_certs = False
    method = module.params["method"]
    params = module.params["params"]

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(host=host, method=method, params=params)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FortiManager(host, username, password, use_ssl, validate_certs, adom, **kwargs)

    if not session_id:
        session_login = session.login()
        if not session_login.json()["result"][0]["status"]["code"] == 0:
            module.fail_json(msg="Unable to login")
    else:
        session.session = session_id



    body = {"method": method, "params": params, "session": session.session}
    response = session.make_request(body).json()

    results = dict(changed=False, response=[response], status=response["result"][0]["status"])
     # build results
    if response["result"][0]["status"]["code"] == 0:    # OK
        if method in ["add", "set", "update", "delete", "move", "clone", "replace"]:
            results.update(changed=True)
            results.update(response=[response, params])
    else:
        module.fail_json(msg="JSON-RPC API Request failed", response=[response], status=response["result"][0]["status"] )


    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)


if __name__ == "__main__":
    main()

