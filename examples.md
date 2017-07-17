# EXAMPLES

### Inventory File
```
[all:vars]
username=user
password=secret

[fortimanager]
netscaler_lb01
```

### Playbook
```
---
- name: CONFIGURE FIREWALL POLICY
  hosts: all
  connection: local
  gather_facts: False

  tasks:
    - name: CONFIGURE ADDRESSES
      fortimgr_address:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        adom: "dmz"
        address_name: "{{ item.name }}"
        associated_intfc:
          - "{{ item.intfc }}"
      with_items:
        - name: "web01"
          intfc: "web"
        - name: "web02"
          intfc: "web"
        - name: "db01"
          intfc: "database"
        - name: "db02"
          intfc: "database"

  tasks:
    - name: CONFIGURE ADDRESS MAPPINGS
      fortimgr_address_map:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        adom: "dmz"
        fortigate: "{{ item.fg }}"
        vdom: "{{ item.vdom }}"
        address_name: "{{ item.name }}"
        address_type: "{{ item.type }}"
        subnet: "{{ item.subnet }}"
      with_items:
        - name: "web01"
          fg: "prod_dmz"
          vdom: "prod"
          type: "subnet"
          subnet: "10.10.10.10/32"
        - name: "web01"
          fg: "dr_dmz"
          vdom: "dr"
          type: "subnet"
          subnet: "10.20.10.10/32"
        - name: "web02"
          fg: "prod_dmz"
          vdom: "prod"
          type: "subnet"
          subnet: "10.10.20.10/32"
        - name: "web02"
          fg: "dr_dmz"
          vdom: "dr"
          type: "subnet"
          subnet: "10.20.20.10/32"
        - name: "db01"
          fg: "prod_dmz"
          vdom: "prod"
          type: "subnet"
          subnet: "10.10.100.10/32"
        - name: "db01"
          fg: "dr_dmz"
          vdom: "dr"
          type: "subnet"
          network: "10.20.100.10/32"
        - name: "db02"
          fg: "prod_dmz"
          vdom: "prod"
          type: "subnet"
          network: "10.10.120.10/32"
        - name: "db02"
          fg: "dr_dmz"
          vdom: "dr"
          type: "subnet"
          network: "10.20.120.10/32"

    - name: CONFIGURE ADDRESS GROUPS
      fortimgr_address_group:
        adom: "dmz"
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        address_group_name: "{{ item.name }}"
        members: "{{ item.members }}"
      with_items:
        - name: "web_app01_svrs"
          members:
            - "web01"
            - "web02"
        - name: "db_app01_svrs"
          members:
            - "db01"
            - "db02"

    - name: CONFIGURE SERVICIES
      fortimgr_service:
        adom: "dmz"
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        service_name: "{{ item.name }}"
        protocol: "{{ item.protocol }}"
        port_range: "{{ item.range }}"
      with_items:
        - name: "http"
          protocol: "TCP"
          port_range: "80"
        - name: "https"
          protocol: "TCP"
          port_range:
            - "443"
            - "8443"
        - name: "sql"
          protocol: "TCP"
          port_range: "1433"

    - name: CONFIGURE SERVICE GROUPS
      fortimgr_service_group:
        adom: "dmz"
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        service_group_name: "{{ item.name }}"
        members: "{{ item.members }}"
      with_items:
        - name: "web_app01_svcs"
          members:
            - "http"
            - "https"
        - name: "db_app01_svcs"
          members: "sql"

    - name: CONFIGURE IP POOL MAPS
      fortimgr_ip_pool_map:
        adom: "dmz"
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        fortigate: "{{ item.fg }}"
        vdom: "{{ item.vdom }}"
        pool_name: "{{ item.name }}"
        type: "overload"
        start_ip: "{{ item.start }}"
        end_ip: "{{ item.end }}"
      with_items:
        - name: "app01_pool"
          fg: "prod_dmz"
          vdom: "prod"
          start: "10.254.10.10"
          end: "10.254.10.20"
        - name: "app01_pool"
          fg: "dr_dmz"
          vdom: "dr"
          start: "10.255.10.10"
          end: "10.255.10.20"

    - name: CONFIGURE VIP MAPS
      fortimgr_ip_pool_map:
        adom: "dmz"
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        fortigate: "{{ item.fg }}"
        vdom: "{{ item.vdom }}"
        vip_name: "{{ item.name }}"
        type: "{{ item.type }}"
        external_ip: "{{ item.ext_ip }}"
        mapped_ip: "{{ item.mapped }}"
        external_intfc: "{{ item.ext_intfc }}"
      with_items:
        - name: "app01_vip01"
          fg: "prod_dmz"
          vdom: "prod"
          type: "static-nat"
          ext_ip: "100.10.10.10"
          mapped: "10.10.10.10"
          ext_intfc: "internet"
        - name: "app01_vip01"
          fg: "dr_dmz"
          vdom: "dr"
          type: "static-nat"
          ext_ip: "100.20.10.10"
          mapped: "10.20.10.10"
          ext_intfc: "internet"
        - name: "app01_vip02"
          fg: "prod_dmz"
          vdom: "prod"
          type: "static-nat"
          ext_ip: "100.10.10.11"
          mapped: "10.10.20.10"
          ext_intfc: "internet"
        - name: "app01_vip02"
          fg: "dr_dmz"
          vdom: "dr"
          type: "static-nat"
          ext_ip: "100.20.20.11"
          mapped: "10.20.20.10"
          ext_intfc: "internet"

    - name: CONFIGURE VIP GROUP
      fortimgr_vip_group:
        adom: "dmz"
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        vip_group_name: "app01_vipgrp"
        members:
          - "app01_vip01"
          - "app01_vip02"

    - name: CONFIGURE APP POLICIES
      fortimgr_policy:
        adom: "dmz"
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        policy_name: "{{ item.name }}"
        global_label: "app01"
        action: "accept"
        source_address: "{{ item.src_addr }}"
        source_interface: "{{ item.src_intfc }}"
        destination_address: "{{ item.dst_addr }}"
        destination_interface: "{{ item.dst_intfc }}"
        service: "{{ item.service }}"
        schedule: "always"
        log_traffic: "all"
        nat: "{{ item.nat | default('') }}"
        ip_pool: "{{ item.pool | default('') }}"
        pool_name: "{{ item.pool | default('') }}"
        direction: "before"
        reference_policy_name: "explicit_deny_all"
      with_items:
        - name: "internet_to_web"
          src_addr: "all"
          src_intfc: "internet"
          dst_addr: "app01_vipgrp"
          dst_intfc: "web"
          service: "web_app01_svcs"
          nat: "enable"
          ip_pool: "enable"
          pool_name: "app01_pool"
        - name: "web_to_database"
          src_addr: "web_app01_svrs"
          src_intfc: "web"
          dst_addr: "db_app01_svrs"
          dst_intfc: "database"
          service: "db_app01_svcs"
```

## FortiManager Revision
```
---
- name: CONFIGURE FIREWALL POLICY
  hosts: all
  connection: local
  gather_facts: False
  tasks:
    - name: CREATE ADOM REVISION
      fortimgr_revision:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        adom: "dmz"
        created_by: "automation"
        description: "Weekly ADOM Revision"
        revision_name: "Revision_MM/DD/YY"
    - name: RESTORE REVISION
      fortimgr_revision:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        adom: "dmz"
        created_by: "user"
        description: "ADOM Revert"
        revision_name: "Last Good Revision"
        restore_name" "Rollback"
        state: "restore"
```

## FortiManager Install
```
---
- name: CONFIGURE FIREWALL POLICY
  hosts: all
  connection: local
  gather_facts: False
  tasks:
    - name: PREVIEW INSTALL POLICY PACKAGE
      fortimgr_install:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        state: "preview"
        adom: "dmz"
        fortigate_name: "{{ item.fg }}"
        package: "dmz"
        vdom: "{{ item.vdom }}"
        dst_file: "{{ filename }}"
      with_items:
        - fg: "prod_dmz"
          vdom: "prod"
          filename: "/usr/fg/backup/prod_mm_dd_yyyy.txt"
        - fg: "dr_dmz"
          vdom: "dr"
          filename: "/usr/fg/backup/dr_mm_dd_yyyy.txt"
    - name: INSTALL POLICY PACKAGE
      fortimgr_install:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        adom: "dmz"
        adom_revision_comments: "Weekly Policy Update for DMZ"
        adom_revision_name: "Revision_MM/DD/YY"
        check_install: True
        fortigate_name: "{{ item.fg }}"
        fortigate_revision_comments: "Weekly Policy Update for DMZ"
        install_flags: "generate_rev"
        package: "dmz"
        vdom: "{{ item.vdom }}"
      with_items:
        - fg: "prod_dmz"
          vdom: "prod"
        - fg: "dr_dmz"
          vdom: "dr"
```

## FortiManager Facts
```
---
- name: SHOW DIFFERENT WAYS TO USE THE FACTS MODULE
  hosts: all
  connection: local
  gather_facts: False
  tasks:
    - name: GET ALL FACTS
      fortimgr_facts:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        adom: "dmz"
      fortigates: "all"
      config_filter: "all"

    - name: GET SOME FACTS METHOD
      fortimgr_facts:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
        adom: "dmz"
        fortigates:
          - name: "prod_dmz"
            vdom: "prod"
          - name: "dr_dmz"
            vdom: "dr"

    - name: GET ONLY SYSTEM FACTS
      fortimgr_facts:
        host: "{{ inventory_hostname }}"
        username: "{{ username }}"
        password: "{{ password }}"
```