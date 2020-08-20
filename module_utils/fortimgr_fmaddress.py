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
"""This is the class used for interacting with the "address" API Endpoint."""

from ansible.module_utils.six import string_types


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
