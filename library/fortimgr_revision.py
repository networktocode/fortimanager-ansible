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
module: fortimgr_revision
version_added: "2.3"
short_description: Manages ADOM revisions
description:
  - Manages FortiManager revisions using jsonrpc API
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
      - The desired state of the revision.
      - Absent will ensure no revisions exist with the specified name.
      - Present will create a new revision.
      - Restore will restore the ADOM to the specified revision.
    required: false
    default: present
    type: str
    choices: ["absent", "present", "restore"]
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
  created_by:
    description:
      - The name of the user who created the revision.
    required: false
    type: str
  description:
    description:
      - A description to add to the revision.
    required: false
    type: str
  lock_revision:
    description:
      - The lock status of the revision.
      - 0 permits the revision to be automatically deleted per FortiManager settings.
      - 1 prevents the revision from being automatically deleted per FortiManager settings.
    required: false
    type: int
    choices: [0, 1]
  revision_name:
    description:
      - The name of the revision.
    required: true
    type: str
'''

EXAMPLES = '''
- name: Add Revision
  fortimgr_revision:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    created_by: "user"
    description: "ADOM Revision"
    revision_name: "Lab Revision"
- name: Delete Revision
  fortimgr_revision:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    revision_name: "Lab Revision"
    state: "absent"
- name: Restore Revision
  fortimgr_revision:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    adom: "lab"
    created_by: "user"
    description: "ADOM Revert"
    revision_name: "Good Revision"
    restore_name: "Rollback"
    state: "restore"
'''

RETURN = '''
revision:
    description: The json results from revision request. Multiple deletions might be required if duplicate names exist.
    returned: Always
    type: list
    sample: [{"result": [{"status": {"code": 0, "message": "OK"}, "url": "/dvmdb/adom/lab/revision/3"}]}]
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


def main():
    base_argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        lock=dict(required=False, type="bool"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        session_id=dict(required=False, type="str"),
        state=dict(choices=["absent", "present", "restore"], type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        created_by=dict(required=False, type="str"),
        description=dict(required=False, type="str"),
        lock_revision=dict(choices=[0, 1], required=False, type="int"),
        restore_name=dict(required=False, type="str"),
        revision_name=dict(required=False, type="list")
    )
    argument_spec = base_argument_spec
    argument_spec["provider"] = dict(required=False, type="dict", options=base_argument_spec)

    module = AnsibleModule(argument_spec, supports_check_mode=False,
                           required_if=[["state", "restore", ["restore_name"]]])
    provider = module.params["provider"] or {}

    # allow local params to override provider
    for param, pvalue in provider.items():
        if module.params.get(param) is None:
            module.params[param] = pvalue

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
    lock_revision = module.params["lock_revision"]
    if isinstance(lock_revision, str):
        lock_revision = int(lock_revision)
    revision_name = module.params["revision_name"]
    if isinstance(revision_name, str):
        revision_name = [revision_name]
    
    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(adom=adom, host=host)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    args = dict(
        created_by=module.params["created_by"],
        desc=module.params["description"],
        locked=lock_revision,
        name=revision_name
    )

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

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

    results = dict(changed=False, revision=[{}])
    if state == "present":
        # lock if config lock in use
        if module.params["lock"]:
            session.config_lock(module)

        revision = session.create_revision([proposed])
        # build results and handle locking if revision successful
        if revision["result"][0]["status"]["code"] == 0:
            results = dict(changed=True, revision=[revision])
            # handle locking needs if revision  successful
            session.config_response(module, revision, module.params["lock"])
        # try to unlock and fail if revision unsuccessful
        elif module.params["lock"]:
            session.config_unlock(module, "Unable to Create Revision", False)
            results.update(msg="Unlocked: {}".format(revision))
            module.fail_json(**results)
        # fail if revision unsuccessful and not locked
        else:
            results.update(msg=revision)
            module.fail_json(**results)
    elif state == "absent":
        existing = session.get_revision(proposed["name"])
        # remove revision(s) if existing
        if existing["result"][0]["data"]:
            # lock if config lock in use
            if module.params["lock"]:
                session.config_lock(module)

            curr_revisions = existing["result"][0]["data"]
            revision = []
            # append dictionary results to build module exit results
            for entry in curr_revisions:
                revision.append(session.delete_revision(entry["version"]))

            # see if any revisions still exist with the name parameter to validate deletion was successful
            still_existing = session.get_revision(proposed["name"])
            if not still_existing["result"][0]["data"]:
                results = dict(changed=True, revision=revision)
                # handle locking needs if revision  successful
                session.config_response(module, still_existing, module.params["lock"])
            # try to unlock and fail if revision unsuccessful
            elif module.params["lock"]:
                session.config_unlock(module, "Unable to Delete Revisions", False)
                results.update(msg="Unlocked: {}".format(revision))
                module.fail_json(**results)
            # fail if revision unsuccessful and not locked
            else:
                results.update(msg=revision)
                module.fail_json(**results)
    else:
        existing = session.get_revision(proposed["name"])
        # restore revision if existing
        if existing["result"][0]["data"]:
            # lock if config lock in use
            if module.params["lock"]:
                session.config_lock(module)

            version = existing["result"][0]["data"][0]["version"]
            proposed["name"] = module.params["restore_name"]
            revision = session.restore_revision(version, [proposed])
            # build results and handle locking if revision successful
            if revision["result"][0]["status"]["code"] == 0:
                results = dict(changed=True, revision=[revision])
                # handle locking needs if revision  successful
                session.config_response(module, revision, module.params["lock"])
            # try to unlock and fail if revision unsuccessful
            elif module.params["lock"]:
                session.config_unlock(module, "Unable to Create Revision", False)
                results.update(msg="Unlocked: {}".format(revision))
                module.fail_json(**results)
            # fail if revision unsuccessful and not locked
            else:
                results.update(msg=revision)
                module.fail_json(**results)
        else:
            module.fail_json(msg="Could not Find Specified Revision")

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

