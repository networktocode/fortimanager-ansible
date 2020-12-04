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
module: fortimgr_install
version_added: "2.3"
short_description: Manages ADOM package installs
description:
  - Manages FortiManager package installs using jsonrpc API
author: Jacob McGill (@jmcgill298)
options:
  adom:
    description:
      - The ADOM that should have package installed should belong to.
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
      - The desired state of the package.
      - Present will update the configuration if needed.
      - Preview (or check mode) will return a preview of what will be pushed to the end device.
    required: false
    default: present
    type: str
    choices: ["present", "preview"]
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
      - Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False).
    required: false
    default: False
    type: bool
  adom_revision_comments:
    description:
      - Comments to add to the ADOM revision if creating a revision.
    required: false
    type: str
  adom_revision_name:
    description:
      - The name to give the ADOM revision if creating a revision.
    required: false
    type: str
  check_install:
    description:
      - Determines if the install will only be committed if the FortiGate is in sync and connected with the FortManager.
      - True performs the check.
      - False attempts the install regardless of device status.
    required: false
    type: bool
  dst_file:
    description:
      - The file path/name where to write the install preview to.
    required: false
    type: str
  fortigate_name:
    description:
      - The name of FortiGate in consideration for package install.
    required: True
    type: str
  fortigate_revision_comments:
    description:
      - Comments to add to the FortiGate revision.
    required: false
    type: str
  install_flags:
    description:
      - Flags to send to the FortiManager identifying how the install should be done.
    required: false
    type: list
    choices: ["cp_all_objs", "generate_rev", "copy_assigned_pkg", "unassign", "ifpolicy_only", "no_ifpolicy",
             "objs_only", "copy_only"]
  package:
    description:
      - The policy package that should be pushed to the end devices.
    required: true
    type: str
  vdom:
    description:
      - The VDOM associated with the FortiGate and package.
    required: false
    type: str
'''

EXAMPLES = '''
- name: Preview Install
  fortimgr_install:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    state: "preview"
    adom: "lab"
    fortigate_name: "Lab_FortiGate"
    package: "lab"
    vdom: "lab"
    dst_file: "./preview.txt"
- name: Install
  fortimgr_install:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    state: "present"
    adom: "lab"
    adom_revision_comments: "Update Policy for Lab"
    adom_revision_name: "Lab_Update_20"
    check_install: True
    fortigate_name: "Lab_FortiGate"
    fortigate_revision_comments: "Update Lab Policy"
    install_flags: "generate_rev"
    package: "lab"
    vdom: "lab"
'''

RETURN = '''
install:
    description: The json results from install request.
    returned: Always
    type: dict
    sample: {"id": 4, "result": [{"data": {"message": "next\nend\nconfig firewall address\nedit \"newer_iprange\"\nset
             uuid 0ce2d578-48af-51e7-3247-9fff5f6f32ee\nset type iprange\nset comment \"create new_obj\"\nset start-ip
             10.10.10.31\nset end-ip 10.10.10.35\nnext\nend\nconfig endpoint-control profile\nedit \"default\"\nconfig
             forticlient-winmac-settings\nset forticlient-wf-profile \"default\"\nend\nnext\nend\nconfig firewall policy
             \nedit 2\nset name \"v\"\nset uuid 88957e6c-48b1-51e7-6531-42a5e4339bd1\nset srcintf \"any\"\nset dstintf
             \"any\"\nset srcaddr \"all\"\nset dstaddr \"newer_iprange\"\nset schedule \"always\"\nset service \"ALL\"\n
             set logtraffic all\nnext\nend\n"}, "status": {"code": 0, "message": "OK"},
             "url": "/securityconsole/preview/result"}]}
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


INSTALL_FLAGS = [
    "cp_all_objs",
    "generate_rev",
    "copy_assigned_pkg",
    "unassign",
    "ifpolicy_only",
    "no_ifpolicy",
    "objs_only",
    "copy_only",
]


def main():
    base_argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        lock=dict(required=False, type="bool"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        session_id=dict(required=False, type="str"),
        state=dict(choices=["present", "preview"], type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        adom_revision_comments=dict(required=False, type="str"),
        adom_revision_name=dict(required=False, type="str"),
        check_install=dict(required=False, type="bool"),
        dst_file=dict(required=False, type="str"),
        fortigate_name=dict(required=False, type="str"),
        fortigate_revision_comments=dict(required=False, type="str"),
        install_flags=dict(required=False, type="list"),
        package=dict(required=False, type="str"),
        vdom=dict(required=False, type="str")
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
        lock = True
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
    check_install = module.params["check_install"]
    dst = module.params["dst_file"]
    fortigate = module.params["fortigate_name"]
    vdom = module.params["vdom"]
    package = module.params["package"]

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, fortigate_name=fortigate, host=host, package=package)
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
            module.fail_json(msg="Unable to login", fortimanager_response=session_login.json())
    else:
        session.session = session_id

    # generate install preview if specified or module ran in check mode
    if state == "preview" or module.check_mode:
        install = session.preview_install(package, fortigate, [vdom], lock)
        if install["result"][0]["status"]["code"] == 0 and "message" in install["result"][0]["data"]:
            # write preview to file if destination file specified
            if dst:
                with open(dst, "w") as preview:
                    preview.write("\n{}\n\n".format(time.asctime().upper()))
                    for line in install["result"][0]["data"]["message"]:
                        preview.write(line)
            results = dict(changed=True, install=install)
        else:
            # fail if install preview had issues
            if install["id"] == 1:
                install["fail_state"] = "install_preview"
                results = dict(status=install, msg="Module Failed Issuing Install with Preview Flag")
                module.fail_json(**results)
            # fail if generating the preview had issues
            elif install["id"] == 2:
                install["fail_state"] = "generate_preview"
                results = dict(status=install, msg="Module Failed Generating a Preview")
                module.fail_json(**results)
            # fail if cancelling the install had issues
            elif install["id"] == 3:
                install["fail_state"] = "cancel_install"
                results = dict(status=install, msg="Module Failed Cancelling the Install Task")
                module.fail_json(**results)
            # fail if retrieving the preview results had issues
            elif install["id"] == 4:
                install["fail_state"] = "retrieving_preview"
                results = dict(status=install, msg="Module Failed Retrieving the Preview Message")
                module.fail_json(**results)
    else:
        # verify fortigate health if check_install is True
        if check_install:
            status = session.get_install_status(fortigate)["result"][0]
            if status["data"] is None:
                module.fail_json(msg="Unable to find {} in ADOM {}".format(fortigate, adom))
            elif status["status"]["code"] != 0 or status["data"][0]["conf_status"] not in ["insync", "synchronized"] or status["data"][0]["conn_status"] != "up":
                results = dict(status=status, msg="Device Status did not Pass Checks")
                module.fail_json(**results)

        args = dict(
            adom=adom,
            adom_rev_comments=module.params["adom_revision_comments"],
            adom_rev_name=module.params["adom_revision_name"],
            dev_rev_comments=module.params["fortigate_revision_comments"],
            flags=module.params["install_flags"],
            pkg=package,
            scope=[fortigate]
        )

        # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
        proposed = dict((k, v) for k, v in args.items() if v)

        # let install handle locking and unlocking if lock is True
        if lock:
            proposed["flags"].append("auto_lock_ws")

        install = session.install_package(proposed)
        if install["result"][0]["status"]["code"] == 0 and install["result"][0]["data"]["state"] == "done":
            results = dict(install=install, changed=True)
        elif install["result"][0]["status"]["code"] == 0 and \
             install["result"][0]["data"]["state"] == "warning" and \
             install["result"][0]["data"]["line"][0]["detail"] == "no installing devices/no changes on package":
            results = dict(install=install, changed=False)
        else:
            # Log out of the session in case of failure to obtain lock
            session_logout = session.logout()
            module.fail_json(**dict(status=install, msg="Install was NOT Sucessful; Please Check FortiManager Logs"))

    # logout, build in check for future logging capabilities
    if not session_id:
        session_logout = session.logout()
        # if not session_logout.json()["result"][0]["status"]["code"] == 0:
        #     results["msg"] = "Completed tasks, but unable to logout of FortiManager"
        #     module.fail_json(**results)

    return module.exit_json(**results)


if __name__ == "__main__":
    main()

