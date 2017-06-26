# Fortinet FortiManager Modules

---
### Requirements
* Python requests
* Everything was tested with FortiManager 5.4

---
### Modules

  * [fortimgr_ip_pool - manages ip pool resources and attributes](#fortimgr_ip_pool)
  * [fortimgr_policy - manages fw policy resources and attributes](#fortimgr_policy)
  * [fortimgr_vip - manages vip resources and attributes](#fortimgr_vip)
  * [fortimgr_ip_pool_map - manages ip pool mapped resources and attributes](#fortimgr_ip_pool_map)
  * [fortimgr_revision - manages adom revisions](#fortimgr_revision)
  * [fortimgr_address_map - manages address mapped resources and attributes](#fortimgr_address_map)
  * [fortimgr_vip_group - manages the vip group resources and attributes](#fortimgr_vip_group)
  * [fortimgr_address - manages address resources and attributes](#fortimgr_address)
  * [fortimgr_lock - manages adom locking and unlocking](#fortimgr_lock)
  * [fortimgr_address_group - manages address group resources and attributes](#fortimgr_address_group)
  * [fortimgr_service_group - manages service group resources and attributes](#fortimgr_service_group)
  * [fortimgr_service - manages service resources and attributes](#fortimgr_service)
  * [fortimgr_install - manages adom package installs](#fortimgr_install)
  * [fortimgr_vip_mapping - manages vip mapped resources and attributes](#fortimgr_vip_mapping)
  * [fortimgr_route - manages route configurations for fortigate devices](#fortimgr_route)
  * [fortimgr_facts - gathers facts from the fortimanager](#fortimgr_facts)

---

## fortimgr_ip_pool
Manages IP Pool resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager IP Pool configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| comment  |   no  |  | |  A comment to add to the IP Pool.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create the configuration if needed.  |
| type  |   no  |  | <ul> <li>overload</li>  <li>one-to-one</li>  <li>fixed-port-range</li>  <li>port-block-allocation</li> </ul> |  The type of NAT the IP Pool will perform  |
| end_ip  |   no  |  | |  The last address in the range of external addresses used to NAT internal addresses to.  |
| pool_name  |   yes  |  | |  The name of the IP Pool.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| source_end_ip  |   no  |  | |  The last address in the range of internal addresses which will be NAT'ed to an address in the external range.  |
| arp_intfc  |   no  |  | |  Sets the interface which should reply for ARP if arp_reply is enabled.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| permit_any_host  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Allows for the use fo full cone NAT.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| arp_reply  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Allows the fortigate to reply to ARP requests.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| start_ip  |   no  |  | |  The first address in the range of external addresses used to NAT internal addresses to.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| source_start_ip  |   no  |  | |  The first address in the range of internal addresses which will be NAT'ed to an address in the external range.  |


 


---


## fortimgr_policy
Manages FW Policy resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager FW Policy configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| comment  |   no  |  | |  A comment to add to the Policy.  |
| status  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  The desired status of the policy.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| nat_ip  |   no  |  | |  The IP to use for NAT when enabled.  First IP in the list is beginning NAT range  Second IP in the list is the ending NAT range..  |
| policy_name  |   no  |  | |  The name of the Policy.  |
| reference_policy_id  |   no  |  | |  The policy id to use as a reference point for policy placement.  |
| source_intfc  |   no  |  | |  A list of source interfaces used for policy matching.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| destination_address  |   no  |  | |  A list of destinations to use for policy matching.  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| service  |   no  |  | |  A list services used for policy matching.  |
| schedule  |   no  |  | |  The schedule to use for when the policy should be enabled.  |
| label  |   no  |  | |  A label for policy grouping.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified policy.  absent will delete the policy if it exists.  param_absent will remove passed params from the policy config if necessary and possible.  present will update the configuration if needed.  |
| nat  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Setting the NAT to enable or disable.  |
| reference_policy_name  |   no  |  | |  The policy name to use as a reference point for policy placement.  |
| source_address  |   no  |  | |  A list of source addresses used for policy matching.  |
| global_label  |   no  |  | |  A section label for policy grouping.  |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| pool_name  |   no  |  | |  The name of the IP Pool when enabled.  |
| direction  |   no  |  | <ul> <li>before</li>  <li>after</li> </ul> |  The direction the policy should be placed in reference to the reference_policy  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| log_traffic  |   no  |  | <ul> <li>disable</li>  <li>all</li>  <li>utm</li> </ul> |  Setting the Log Traffic to disable, all, or utm(log security events).  |
| log_traffic_start  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Setting the Log Traffic Start to enable or disable.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| password  |   no  |  | |  The password associated with the username account.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| ip_pool  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Setting the IP Pool Nat feature to enable or disable.  |
| permit_any_host  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Setting the Permit Any Host to enable or disable.  |
| package  |   yes  |  | |  The policy package to add the policy to.  |
| destination_intfc  |   no  |  | |  A list of interface destinations to use for policy matching.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| action  |   no  |  | <ul> <li>accept</li>  <li>deny</li>  <li>ipsec</li>  <li>ssl-vpn</li> </ul> |  The action the end device should take when the policy is matched.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| policy_id  |   no  |  | |  The ID associated with the Policy.  |


 


---


## fortimgr_vip
Manages VIP resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager VIP configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| comment  |   no  |  | |  A comment to add to the VIP.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create the configuration if needed.  |
| type  |   no  |  | <ul> <li>static-nat</li>  <li>fqdn</li>  <li>dns-translation</li> </ul> |  The type of service the VIP will offer.  |
| source_filter  |   no  |  | |  The source IP addresses which will be used to filter when the NAT takes place.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| color  |   no  |  | |  A tag that can be used to group objects.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| external_intfc  |   no  |  | |  The associated external interface  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| vip_name  |   yes  |  | |  The name of the VIP.  |
| external_ip  |   no  |  | |  The external IP or IP range that will be NAT'ed to the internal mapped IP.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| arp_reply  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Allows the fortigate to reply to ARP requests.  |
| source_intfc  |   no  |  | |  The source interface which will be used to filter when the NAT takes place.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| mapped_ip  |   no  |  | |  The address or address range used that the external IP will be mapped to.  |


 


---


## fortimgr_ip_pool_map
Manages IP Pool mapped resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager IP Pool dynamic_mapping configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| comment  |   no  |  | |  A comment to add to the IP Pool.  |
| source_start_ip  |   no  |  | |  The first address in the range of internal addresses which will be NAT'ed to an address in the external range.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| arp_intfc  |   no  |  | |  Sets the interface which should reply for ARP if arp_reply is enabled.  |
| arp_reply  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Allows the fortigate to reply to ARP requests.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the mapping from the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create configuration for the mapping correlating to the fortigate specified if needed.  |
| end_ip  |   no  |  | |  The last address in the range of external addresses used to NAT internal addresses to.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| type  |   no  |  | <ul> <li>overload</li>  <li>one-to-one</li>  <li>fixed-port-range</li>  <li>port-block-allocation</li> </ul> |  The type of NAT the IP Pool will perform  |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| pool_name  |   yes  |  | |  The name of the IP Pool.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| source_end_ip  |   no  |  | |  The last address in the range of internal addresses which will be NAT'ed to an address in the external range.  |
| start_ip  |   no  |  | |  The first address in the range of external addresses used to NAT internal addresses to.  |
| password  |   no  |  | |  The password associated with the username account.  |
| fortigate  |   no  |  | |  The name of the fortigate to map the configuration to.  |
| vdom  |   no  |  root  | |  The vdom on the fortigate that the config should be associated to.  |
| permit_any_host  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Allows for the use fo full cone NAT.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |


 


---


## fortimgr_revision
Manages ADOM revisions

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager revisions using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| lock_revision  |   no  |  | <ul> <li>0</li>  <li>1</li> </ul> |  The lock status of the revision.  0 permits the revision to be automatically deleted per FortiManager settings.  1 prevents the revision from being automatically deleted per FortiManager settings.  |
| description  |   no  |  | |  A description to add to the revision.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>present</li>  <li>restore</li> </ul> |  The desired state of the revision.  Absent will ensure no revisions exist with the specified name.  Present will create a new revision.  Restore will restore the ADOM to the specified revision.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| created_by  |   no  |  | |  The name of the user who created the revision.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| revision_name  |   yes  |  | |  The name of the revision.  |


 


---


## fortimgr_address_map
Manages Address mapped resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager Address dynamic_mapping configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| comment  |   no  |  | |  A comment to add to the Address  |
| allow_routing  |   no  |  | |  Determines if the address can be used in static routing configuration.  |
| color  |   no  |  | |  A tag that can be used to group objects  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| fqdn  |   no  |  | |  The fully qualified domain name associated with an Address when the type is fqdn.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| subnet  |   no  |  | |  The subnet associated with an Address when the type is ipmask or wildcard.  The first string in the list is the Network IP.  The last string in the list is the Subnet or Wildcard Mask.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the mapping from the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create configuration for the mapping correlating to the fortigate specified if needed.  |
| end_ip  |   no  |  | |  The last IP associated with an Address when the type is iprange.  |
| address_name  |   yes  |  | |  The name of the Address object.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| address_type  |   no  |  | <ul> <li>ipmask</li>  <li>iprange</li>  <li>fqdn</li>  <li>wildcard</li>  <li>wildcard-fqdn</li> </ul> |  The type of address the Address object is.  |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| start_ip  |   no  |  | |  The first IP associated with an Address when the type is iprange.  |
| password  |   no  |  | |  The password associated with the username account.  |
| vdom  |   no  |  root  | |  The vdom on the fortigate that the config should be associated to.  |
| wildcard_fqdn  |   no  |  | |  The wildcard FQDN associated with an Address when the type is wildcard-fqdn.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |


 


---


## fortimgr_vip_group
Manages the VIP Group resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager VIP Group configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| comment  |   no  |  | |  A comment to add to the VIP.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| color  |   no  |  | |  A tag that can be used to group objects.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| vip_group_name  |   yes  |  | |  The name of the VIP Group.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create the configuration if needed.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| member  |   no  |  | |  The list of VIP objects that should be associated to the VIP Group.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| interface  |   no  |  | |  The list of interfaces/zones associated with the VIP Group  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |


 


---


## fortimgr_address
Manages Address resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager Address configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| comment  |   no  |  | |  A comment to add to the Address  |
| allow_routing  |   no  |  | |  Determines if the address can be used in static routing configuration.  |
| color  |   no  |  | |  A tag that can be used to group objects  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| fqdn  |   no  |  | |  The fully qualified domain name associated with an Address when the type is fqdn.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| subnet  |   no  |  | |  The subnet associated with an Address when the type is ipmask or wildcard.  The first string in the list is the Network IP.  The last string in the list is the Subnet or Wildcard Mask.  |
| associated_intfc  |   no  |  | |  The interface associated with the Address.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete resource if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will update the configuration if needed.  |
| end_ip  |   no  |  | |  The last IP associated with an Address when the type is iprange.  |
| address_name  |   yes  |  | |  The name of the Address object.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| address_type  |   no  |  | <ul> <li>ipmask</li>  <li>iprange</li>  <li>fqdn</li>  <li>wildcard</li>  <li>wildcard-fqdn</li> </ul> |  The type of address the Address object is.  |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| start_ip  |   no  |  | |  The first IP associated with an Address when the type is iprange.  |
| password  |   no  |  | |  The password associated with the username account.  |
| wildcard_fqdn  |   no  |  | |  The wildcard FQDN associated with an Address when the type is wildcard-fqdn.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |


 


---


## fortimgr_lock
Manages ADOM locking and unlocking

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager ADOM locking and unlocking using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| lock  |   no  |  True  | |  Locks or Unlocks the ADOM in the FortiManager.  True ensures the ADOM is locked.  |
| save_config  |   no  |  False  | |  Saves the config before unlocking a session.  True saves the configuration.  False does not save the configuration and all changes in the session will be lost if unlocked.  |
| unlock  |   no  |  False  | |  Locks or Unlocks the ADOM in the FortiManager.  True ensures the ADOM is unlocked.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |


 


---


## fortimgr_address_group
Manages Address Group resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager Address Group configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| allow_routing  |   no  |  | |  Determines if the address can be used in static routing configuration.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| color  |   no  |  | |  A tag that can be used to group objects  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create the configuration if needed.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| address_group_name  |   yes  |  | |  The name of the Address Group object.  |
| members  |   no  |  | |  A list of members associated with the Address Group object.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| comment  |   no  |  | |  A comment to add to the Address  |


 


---


## fortimgr_service_group
Manages Service Group resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager Service Group configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| comment  |   no  |  | |  A comment to add to the Service Group  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| color  |   no  |  | |  A tag that can be used to group objects  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| service_group_name  |   yes  |  | |  The name of the Service Group object.  |
| explicit-proxy  |   no  |  | |  Used to set the explicit-proxy service for the Service Group object.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create the configuration if needed.  |
| members  |   no  |  | |  A list of members associated with the Service Group object.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |


 


---


## fortimgr_service
Manages Service resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager Service configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| icmp_code  |   no  |  | |  The ICMP code for when protocol is set to ICMP.  |
| password  |   no  |  | |  The password associated with the username account.  |
| protocol  |   no  |  | |  Used to specify the service's protocol type.  |
| icmp_type  |   no  |  | |  The ICMP type for when the protocol is set to ICMP.  |
| category  |   no  |  | <ul> <li>Uncategorized</li>  <li>Authentication</li>  <li>Email</li>  <li>File Access</li>  <li>General</li>  <li>Network Services</li>  <li>Remote Access</li>  <li>Tunneling</li>  <li>VoIP, Messaging & Other Applications</li>  <li>Web Access</li>  <li>Web Proxy</li> </ul> |  The category of the service object.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| color  |   no  |  | |  A tag that can be used to group objects  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| protocol_number  |   no  |  | |  Used to specify the IP protocol number when protocol is set to IP.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create the configuration if needed.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| port_range  |   no  |  | |  The range of TCP or UDP ports associated with the service object.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| service_name  |   yes  |  | |  The name of the service.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| explicit_proxy  |   no  |  | |  Used to set the explicit-proxy service for the Service object.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| comment  |   no  |  | |  A comment to add to the Service  |


 


---


## fortimgr_install
Manages ADOM package installs

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager package installs using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| adom_revision_name  |   no  |  | |  The name to give the ADOM revision if creating a revision.  |
| fortigate_revision_comments  |   no  |  | |  Comments to add to the FortiGate revision.  |
| adom  |   yes  |  | |  The ADOM that should have package installed should belong to.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| package  |   yes  |  | |  The policy package that should be pushed to the end devices.  |
| adom_revision_comments  |   no  |  | |  Comments to add to the ADOM revision if creating a revision.  |
| check_install  |   no  |  False  | |  Determines if the install will only be committed if the FortiGate is in sync and connected with the FortManager.  True performs the check.  False attempts the install regardless of device status.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| fortigate_name  |   yes  |  | |  The name of FortiGate in consideration for package install.  |
| install_flags  |   no  |  | <ul> <li>cp_all_objs</li>  <li>generate_rev</li>  <li>copy_assigned_pkg</li>  <li>unassign</li>  <li>ifpolicy_only</li>  <li>no_ifpolicy</li>  <li>objs_only</li>  <li>copy_only</li> </ul> |  Flags to send to the FortiManager identifying how the install should be done.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| state  |   no  |  present  | <ul> <li>present</li>  <li>preview</li> </ul> |  The desired state of the package.  Present will update the configuration if needed.  Preview (or check mode) will return a preview of what will be pushed to the end device.  |
| dst_file  |   no  |  | |  The file path/name where to write the install preview to.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False).  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| vdom  |   no  |  | |  The VDOM associated with the FortiGate and package.  |


 


---


## fortimgr_vip_mapping
Manages VIP mapped resources and attributes

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiManager VIP dynamic_mapping configurations using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| comment  |   no  |  | |  A comment to add to the VIP.  |
| color  |   no  |  | |  A tag that can be used to group objects.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| arp_reply  |   no  |  | <ul> <li>enable</li>  <li>disable</li> </ul> |  Allows the fortigate to reply to ARP requests.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| mapped_ip  |   no  |  | |  The address or address range used that the external IP will be mapped to.  |
| state  |   no  |  present  | <ul> <li>absent</li>  <li>param_absent</li>  <li>present</li> </ul> |  The desired state of the specified object.  absent will delete the mapping from the object if it exists.  param_absent will remove passed params from the object config if necessary and possible.  present will create configuration for the mapping correlating to the fortigate specified if needed.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| type  |   no  |  | |  The source interface which will be used to filter when the NAT takes place.  |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| source_filter  |   no  |  | |  The source IP addresses which will be used to filter when the NAT takes place.  |
| adom  |   yes  |  | |  The ADOM the configuration should belong to.  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| password  |   no  |  | |  The password associated with the username account.  |
| fortigate  |   no  |  | |  The name of the fortigate to map the configuration to.  |
| vdom  |   no  |  root  | |  The vdom on the fortigate that the config should be associated to.  |
| external_intfc  |   no  |  | |  The associated external interface  |
| external_ip  |   no  |  | |  The external IP or IP range that will be NAT'ed to the internal mapped IP.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False)  |
| vip_name  |   yes  |  | |  The name of the VIP.  |


 


---


## fortimgr_route
Manages Route configurations for FortiGate devices

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Manages FortiGate route configurations using FortiManager's jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| comment  |   no  |  | |  A comment to add to the route.  |
| weight  |   no  |  | |  The weight to assign to the route.  |
| adom  |   no  |  | |  The ADOM the configuration should belong to.  |
| lock  |   no  |  True  | |  True locks the ADOM, makes necessary configuration updates, saves the config, and unlocks the ADOM  |
| destination  |   yes  |  | |  The destination subnet.  {u'List item of two': u'first item is the network address and the second is subnet mask'}  |
| state  |   no  |  present  | <ul> <li>present</li>  <li>absent</li> </ul> |  The desired state of the route.  absent will remove the route if it exists.  present will update the configuration if needed.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| gateway  |   yes  |  | |  The gateway address for which the destination can be reached.  |
| priority  |   no  |  | |  The priority to assign the route.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False).  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| intfc  |   no  |  | |  The interface used to reach the route.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| fortigate  |   yes  |  | |  The fortigate to apply the route to.  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |
| vdom  |   |  root  | |  The vdom on the fortigate to add the route to.  |
| distance  |   no  |  | |  The distance metric to associate to the route.  |


 


---


## fortimgr_facts
Gathers facts from the FortiManager

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Gathers facts from the FortiManager using jsonrpc API

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| username  |   no  |  | |  The username used to authenticate with the FortiManager.  |
| config_filter  |   no  |  | <ul> <li>all</li>  <li>route</li>  <li>address</li>  <li>address_group</li>  <li>service</li>  <li>service_group</li>  <li>ip_pool</li>  <li>vip</li>  <li>vip_group</li>  <li>policy</li> </ul> |  The list of configuration items to retrieve from the list of FortiGates managed by the FortiManager.  |
| fortigates  |   no  |  | |  A list of FortiGates to retrieve device information for; "all" can be used to retrieve all devices managed by the FortiManger.  If config_filter is defined, this list will be used to determine what devices to retrieve configuration from.  If config_filter is defined, this list should be a list of dictionaries with "name" and "vdom" keys defining the mapping for fortigate and vdom.  |
| adom  |   no  |  | |  The ADOM that should have package installed should belong to.  |
| session_id  |   no  |  | |  The session_id of an established and active session  |
| host  |   yes  |  | |  The FortiManager's Address.  |
| provider  |   no  |  | |  Dictionary which acts as a collection of arguments used to define the characteristics of how to connect to the device.  Arguments hostname, username, and password must be specified in either provider or local param.  Local params take precedence, e.g. hostname is preferred to provider["hostname"] when both are specified.  |
| use_ssl  |   no  |  True  | |  Determines whether to use HTTPS(True) or HTTP(False).  |
| password  |   no  |  | |  The password associated with the username account.  |
| validate_certs  |   no  |  False  | |  Determines whether to validate certs against a trusted certificate file (True), or accept all certs (False).  |
| port  |   no  |  | |  The TCP port used to connect to the FortiManager if other than the default used by the transport method(http=80, https=443).  |


 


---


---
Created by Network to Code, LLC
For:
2017
