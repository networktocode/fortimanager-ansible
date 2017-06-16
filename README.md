
# Ansible Modules for FortiManager JSON-RPC API

* [Introduction](#introduction)
* [Module Summary](#modules)
* [Installation](#installation)
* [Detailed Module Documentation](#full-module-documentation)
* [Module Examples](#examples)
* [Contributing](#contributing)

# Introduction

This repository includes a number of Ansible modules to automate Fortinet FortiManager devices using the JSON-RPC API.

# Modules

Here is a brief overview of all modules included in this repository.

* **fortimgr_address**
  + Used to create, update, and delete address objects.
  + Returns the existing configuration for the address object and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_address_group**
  + Used to create, update, and delete address group objects.
  + Returns the existing configuration for the address group and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_address_map**
  + Used to create, update, and delete an address object's device mapping configuration.
  + Returns the existing configuration for the address object and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_ip_pool**
  + Used to create, update, and delete ip pools.
  + Returns the existing configuration for the ip pool and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_ip_pool_map**
  + Used to create, update, and delete an ip pool's device mapping configuration.
  + Returns the existing configuration for the ip pool and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_policy**
  + Used to create, update, and delete policy entries.
  + Returns the existing configuration for the policy entry and the configuration sent to the FortiManager API.
  + The API call sent to move the policy entry is returned when the policy is not in the location specefied by the optional policy placement params.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_route**
  + Used to create, update, and delete routes on devices managed by FortiManager.
  + Returns the existing configuration for the route and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_service**
  + Used to create, update, and delete service objects.
  + Returns the existing configuration for the service object and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_service_group**
  + Used to create, update, and delete service group objects.
  + Returns the existing configuration for the service group and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_vip**
  + Used to create, update, and delete VIPs.
  + Returns the existing configuration for the VIP and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_vip_group**
  + Used to create, update, and delete VIP group objects.
  + Returns the existing configuration for the VIP group and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_vip_map**
  + Used to create, update, and delete a VIP's device mapping configuration.
  + Returns the existing configuration for the VIP and the configuration sent to the FortiManager API.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.
* **fortimgr_facts**
  + Used to gather facts about the FortiManager system and managed devices.
  + Returns FortiManger system information, a list of managed devices with some basic information about them, and configurations for devices managed by the FortiManager.
* **fortimgr_install**
  + Used to install policy packages on the FortiManager to the managed devices.
  + Returns the results from the install request.
* **fortimgr_lock**
  + Used to lock, save, and unlock the FortiManager. This provides an alternative method for handle workspace session locking instead of using each module's lock parameter.
  + Returns the session ID when the module is set to lock the configuration.
  + Returns the lock, save, and unlock request status.
* **fortimgr_revision**
  + Used to create, delete, or restore ADOM revisions.
  + Returns the results from the revision request.
  + Lock, Save, and Unlock status are returned when locking the ADOM is set.

# Installation

You need to perform **two** steps to start using these modules.

1. Ensure this repository is in your Ansible module search path.
2. Install Dependencies.

### Locate your search path
Here is how you can locate your search path:
```
$ ansible --version
ansible 2.1.1.0
  config file = /etc/ansible/ansible.cfg
  configured module search path = ???
```

If you already have a search path configured, clone the repo (see options below) while you are in your search path.

If you have a "default" or No search path shown, open the config file that is shown in the output above, here that is `/etc/ansible/ansible.cfg`.  In that file, you'll see these first few lines:
```
[defaults]

# some basic default values...

inventory      = /etc/ansible/hosts
library        = /home/ntc/projects/
```

Add a path for `library` that exists in this repository - this will become your search path. Validate it with `ansible --version` after you make the change.

### Clone the repo in your search path

```
$ git clone https://github.com/networktocode/fortimgr-ansible
```

As a quick test and sanity use `ansible-doc` on one of the modules before trying to use them in a playbook.  For example, try this:
```
$ ansible-doc fortimgr_facts
```

If that works, Ansible can find the modules and you can proceed to installing the dependencies below.

## Install Dependencies
```
$ cd fortimgr-ansible
$ pip install -r requirements.txt
```


# Full Module Documentation

The following docs are the same type of docs you'd find on docs.ansible.com for modules that are found in Ansible core:

See [Module Documentation](Module_Docs/fortimgr_module_docs.md)

# Examples
See [Examples](examples.md)

# Contributing
See [Contributing](contributing.md)