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
module: fortimgr_route
version_added: "2.3"
short_description: Manages Route configurations for FortiGate devices
description:
  - Manages FortiGate route configurations using FortiManager's jsonrpc API
author: Jacob McGill (@jmcgill298)
options:
  adom:
    description:
      - The ADOM the configuration should belong to.
    required: false
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
      - Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.
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
      - The desired state of the route.
      - absent will remove the route if it exists.
      - present will update the configuration if needed.
    required: false
    default: present
    type: str
    choices: ["present", "absent"]
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
      - Determines whether to validate certs against a trusted certificate file C(True), or accept all certs C(False).
    required: false
    default: False
    type: bool
  comment:
    description:
      - A comment to add to the route.
    required: false
    type: str
  distance:
    description:
      - The distance metric to associate to the route.
    required: false
    type: int
  destination:
    description:
      - The destination subnet.
      - This supports sending a string as cidr notation or a two element list that
        would be returned from getting existing address objects.
      - Alternatively, the netmask and network params can be used.
    required: true
    type: list
  destination_netmask: 
    description:
      - The netmask to use for the destination address.
      - The network param must be used in conjuction with netmask.
      - Alternatively, the destination param can be used for cidr notation.
    required: false
    type: str
  destination_network: 
    description:
      - The network address to use destination address.
      - The netmask param must be used in conjuction with network.
      - Alternatively, the destination param can be used for cidr notation.
    required: false
    type: str
  destination_object:
    description:
      - The address or address-group object to use as the destination address
    required: false
    type: str
  fortigate:
    description:
      - The fortigate to apply the route to.
    required: true
    type: str
  gateway:
    description:
      - The gateway address for which the destination can be reached.
    required: true
    type: str
  intfc:
    description:
      - The interface used to reach the route.
    required: false
    type: list
  priority:
    description:
      - The priority to assign the route.
    required: false
    type: int
  sequence_number:
    description:
      - The sequence number of the route in FortiManager
      - This is required in order to modify an existing route's interface, destination, and gateway.
    required: false
    type: str
  vdom:
    description:
      - The vdom on the fortigate to add the route to.
    required: true
    type: str
  weight:
    description:
      - The weight to assign to the route.
    required: false
    type: int
'''

EXAMPLES = '''
- name: Add Route
  fortimgr_route:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    state: "present"
    adom: "lab"
    fortigate: "lab_fg"
    vdom: "root"
    destination: "10.2.1.0/24"
    gateway: "10.1.1.1"
    intfc: "port1"
- name: Remove Route
  fortimgr_route:
    host: "{{ ansible_host }}"
    username: "{{ ansible_user }}"
    password: "{{ ansible_password }}"
    state: "absent"
    adom: "lab"
    fortigate: "lab_fg"
    vdom: "root"
    destination: "10.2.1.0/24"
    gateway: "10.1.1.1"
'''

RETURN = '''
existing:
    description: The existing configuration for the Route (uses policy_name) before the task executed.
    returned: always
    type: dict
    sample: {"changed": false, "config": {}, "existing": {
             "blackhole": 0, "comment": "", "device": ["port1"], "distance": 10, "dst": ["10.0.0.0", "255.0.0.0"],
             "dynamic-gateway": 0, "gateway": "10.1.1.1", "internet-service": 0, "priority": 0, "seq-num": 4,
             "virtual-wan-link": 0, "weight": 17}
config:
    description: The configuration that was pushed to the FortiManager.
    returned: always
    type: dict
    sample: {"method": "update", "params": [{"data": {"device": ["port2"], "dst": ["7.7.7.7", "255.255.255.255"],
             "gateway": "2.2.2.3"}, "seq-num": 15, "url": "/pm/config/device/FortiGate-VM64-KVM/vdom/root/route/static"}]}
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


class FMRoute(FortiManager):
    """
    This is the class used for interacting with FortiGate devices and VDOMs.

    :param fortigate: Type str.
                      The particular fortigate to interact with.
    :param vdom: Type str.
                 The particular vdom on the fortigate to interact with.
    """

    def __init__(self, host, user, passw, fortigate, vdom, use_ssl=True, verify=False, adom="", package="",
                 api_endpoint="", **kwargs):
        super(FMRoute, self).__init__(host, user, passw, use_ssl, verify, adom, package, api_endpoint, **kwargs)

        self.fortigate = fortigate
        self.vdom = vdom
        self.dev_url = "/pm/config/device/{}/vdom/{}".format(self.fortigate, self.vdom)
        self.obj_url = "{}/router/static".format(self.dev_url)

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

        # proposed length of 1 is just the sequence number of the route
        if existing:
            config = self.config_delete(module, existing["seq-num"])
            changed = True
        else:
            existing = {}

        return {"changed": changed, "config": config, "existing": existing}

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
            sequence_number = response.json().get("result", [{}])[0].get("data", {}).get("seq-num", "None")
            new_config.update({"seq-num": sequence_number})

        return {"method": "add", "params": [{"url": self.obj_url, "data": new_config}]}

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
            diff = self.get_diff_add(proposed, existing)
            if diff and module.params["sequence_number"]:
                config = self.config_update(module, diff)
                changed = True
            elif diff and "device" in diff:
                module.fail_json(msg="This module does not support creating a route matching an existing destination"
                                     " prefix that points to a different interface. Modifying an existing route's"
                                     " interface can be done using the sequence_number parameter", existing=existing)
            elif diff and "gateway" in diff:
                diff.pop("seq-num")
                config = self.config_new(module, proposed)
                changed = True
            elif diff:
                config = self.config_update(module, diff)
                changed = True

        return {"changed": changed, "config": config, "existing": existing}

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
        replace = ["device"]
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            if existing_field and proposed_field != existing_field:
                if field in replace:
                    # replace the entries that are lists with fixed length of one
                    config[field] = proposed_field
                elif isinstance(existing_field, list):
                    existing_field = set(existing_field)
                    diff = proposed_field.union(existing_field)
                    if diff != existing_field:
                        config[field] = list(diff)
                elif isinstance(existing_field, dict):
                    config[field] = dict(set(proposed_field.items()).union(existing_field.items()))
                elif isinstance(existing_field, int) or isinstance(existing_field, string_types):
                    config[field] = proposed_field
            elif field not in existing:
                config[field] = proposed_field

        if config:
            config["seq-num"] = existing["seq-num"]

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
        ignore = ["device", "dst", "dstaddr"]
        for field in proposed.keys():
            proposed_field = proposed[field]
            existing_field = existing.get(field)
            # ignore lists that can only have a length of one
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
            config["seq-num"] = existing["seq-num"]

        return config

    def get_item(self, sequence_number):
        """
        This method is used to get a specific static route currently configured on the FortiGate and VDOM specified in
        the class instance. The destination and gateway are used to distinguish the route.

        :param sequence_number: Type: str.
                                The sequence number in FortiManager of an existing route.
        :return: The configuration for the object as a dictionary. An empty dict is returned if the request does not
                 return any data.
        """
        route_url = "{}/{}".format(self.obj_url, sequence_number)
        body = dict(method="get", params=[dict(url=route_url)], session=self.session)
        response = self.make_request(body).json()["result"][0].get("data", {})

        if not response:
            response = {}

        return response

    def get_item_destination(self, destination, gateway):
        """
        This method is used to get a specific static route currently configured on the FortiGate and VDOM specified in
        the class instance. The destination and gateway are used to distinguish the route.

        :param destination: Type: list,str.
                            The destination address to look up. Specifying the address should be a list in the format
                            of [destination, mask]. Using an address or address group object should be a string.
        :param gateway: Type str.
                        The gateway address used to reach the destination.
        :return: The configuration for the objects as a list with a dictionary. A list with an empty dict is returned if
                 the request does not return any data.
        """
        if isinstance(destination, list):
            dst = ["dst", "==", destination]
        else:
            dst = ["dstaddr", "==", destination]

        dst_filter = [dst, "&&", ["gateway", "==", gateway]]
        body = dict(method="get", params=[dict(url=self.obj_url, filter=dst_filter)], session=self.session)
        response = self.make_request(body).json()["result"][0].get("data", [{}])

        if not response:
            response = [{}]

        return response

    def get_item_fields(self, destination, gateway, fields):
        """
        This method is used to get a specific object currently configured on the FortiManager for the ADOM and API
        Endpoint. The configuration fields retrieved are limited to the list defined in the fields variable.

        :param destination: Type: list,str.
                            The destination address to look up. Specifying the address should be a list in the format
                            of [destination, mask]. Using an address or address group object should be a string.
        :param fields: Type list.
                       The list of fields to return for each object.
        :param gateway: Type str.
                        The gateway address used to reach the destination.
        :return: The list of configuration dictionaries for each object. An empty list is returned if the request does
                 not return any data.
        """
        if isinstance(destination, list):
            dst = ["dst", "==", destination]
        else:
            dst = ["dstaddr", "==", destination]

        dst_filter = [dst, "&&", ["gateway", "==", gateway]]
        params = [dict(url=self.obj_url, filter=dst_filter, fields=fields)]
        body = dict(method="get", params=params, verbose=1, session=self.session)
        response = self.make_request(body)
        response_data = response.json()["result"][0].get("data", [{}])

        if not response:
            response = [{}]

        return response


def main():
    base_argument_spec = dict(
        adom=dict(required=False, type="str"),
        host=dict(required=False, type="str"),
        lock=dict(required=False, type="bool"),
        password=dict(fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True),
        port=dict(required=False, type="int"),
        session_id=dict(required=False, type="str"),
        state=dict(choices=["absent", "present"], type="str"),
        use_ssl=dict(required=False, type="bool"),
        username=dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
        validate_certs=dict(required=False, type="bool"),
        comment=dict(required=False, type="str"),
        destination=dict(required=False, type="list"),
        destination_netmask=dict(required=False, type="str"),
        destination_network=dict(required=False, type="str"),
        destination_object=dict(required=False, type="str"),
        distance=dict(required=False, type="int"),
        fortigate=dict(required=False, type="str"),
        gateway=dict(required=False, type="str"),
        intfc=dict(required=False, type="list"),
        priority=dict(required=False, type="int"),
        sequence_number=dict(required=False, type="str"),
        vdom=dict(required=False, type="str"),
        weight=dict(required=False, type="int")
    )
    argument_spec = base_argument_spec
    argument_spec["provider"] = dict(required=False, type="dict", options=base_argument_spec)

    module = AnsibleModule(argument_spec, supports_check_mode=True,
                           required_together=[["destination_network", "destination_netmask"]],
                           mutually_exclusive=[["destination", "destination_network"]])
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
    destination = module.params["destination"]
    if isinstance(destination, str):
        destination = [destination]
    destination_netmask = module.params["destination_netmask"]
    destination_network = module.params["destination_network"]
    destination_object = module.params["destination_object"]
    distance = module.params["distance"]
    if isinstance(distance, str):
        distance = int(distance)
    fortigate = module.params["fortigate"]
    gateway = module.params["gateway"]
    intfc = module.params["intfc"]
    if isinstance(intfc, str):
        intfc = [intfc]
    priority = module.params["priority"]
    if isinstance(priority, str):
        priority = int(priority)
    seq_num = module.params["sequence_number"]
    if isinstance(seq_num, int):
        seq_num = str(seq_num)
    vdom = module.params["vdom"]
    weight = module.params["weight"]
    if isinstance(weight, str):
        weight = int(weight)

    # validate required arguments are passed; not used in argument_spec to allow params to be called from provider
    argument_check = dict(host=host, fortigate=fortigate, vdom=vdom)
    for key, val in argument_check.items():
        if not val:
            module.fail_json(msg="{} is required".format(key))

    # validate route parameters are passed correctly
    if destination and destination_object:
        module.fail_json(msg="Destination Addresses cannnot be both Network Addresses and Address Objects")
    elif destination and (destination_network or destination_netmask):
        module.fail_json(msg="The destination parameter cannot be used with the destination_network and destination_netmask parameters")
    elif (destination_netmask and not destination_network) or (destination_network and not destination_netmask):
        module.fail_json(msg="The destination_network and destination_netmask parameters must be provided together.")
    elif not seq_num:
        if not gateway:
            module.fail_json(msg="The gateway parameter is required when not specifying the sequence number"
                                 " of an existing route.")
        elif not (destination or destination_network) and not destination_object:
            module.fail_json(msg="Either the destination or destination_object parameter is required when"
                                 " not specifying the sequence number of an existing route.")

    # use destination variables to normalize dst into a list that fortimanager expects
    if destination and len(destination) == 1 and "/" in destination[0]:
        destination = FortiManager.cidr_to_network(destination[0])
    elif destination and len(destination) == 1:
        destination = [str(destination[0]), "255.255.255.255"]
    elif destination_network and destination_netmask:
        destination = [destination_network, destination_netmask]

    args = {
        "comment": module.params["comment"],
        "device": intfc,
        "distance": distance,
        "dst": destination,
        "dstaddr": destination_object,
        "gateway": gateway,
        "priority": priority,
        "seq-num": seq_num,
        "weight": weight
    }

    # "if isinstance(v, bool) or v" should be used if a bool variable is added to args
    proposed = dict((k, v) for k, v in args.items() if v)

    kwargs = dict()
    if port:
        kwargs["port"] = port

    # validate successful login or use established session id
    session = FMRoute(host, username, password, fortigate, vdom, use_ssl, validate_certs, adom, **kwargs)
    if not session_id:
        session_login = session.login()
        if not session_login.json()["result"][0]["status"]["code"] == 0:
            module.fail_json(msg="Unable to login", fortimanager_response=session_login.json())
    else:
        session.session = session_id

    # get existing configuration from fortimanager and make necessary changes
    if seq_num:
        existing = session.get_item(seq_num)
    else:
        destination = proposed.get("dst")
        if not destination:
            destination = proposed.get("dstaddr")
        existing = session.get_item_destination(destination, proposed["gateway"])[0]

    if state == "present":
        results = session.config_present(module, proposed, existing)
    else:
        results = session.config_absent(module, proposed, existing)

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

