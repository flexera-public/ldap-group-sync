# RightScale LDAP Group Sync Tool

This group sync script is designed to sync groups from an LDAP provider to RightScale Governance.
It uses ldapsearch(Part of [openldap](https://www.openldap.org/software/download/) tools) and [PowerShell core](https://github.com/PowerShell/PowerShell).

## Important Considerations
1. The tool will not follow memberships for nested groups. Users must be direct members of the LDAP groups to be synchronized.
1. Groups must already exist in RightScale with the proper roles assigned. This tool will not create groups.
1. Once a group is managed by this tool, you will no longer be able to manually make modifications to its members in RightScale Governance. Any changes you make to the group in Governance will be removed once the next group sync is run. Manage the group in your directory service
1. The time it takes to do a full sync is directly related to the number of groups and users you are synchronizing. We recommend running it a few times manually to get a good baseline before scheduling it to run on a reoccurring basis. Remember to add a buffer to the schedule to account for latency and additional users and groups that may be added in the future.

## How It Works
1. The tool gathers groups from an LDAP directory service based on either a list of groups, or a search string.  
1. Once the groups are discovered, it collects the necessary details from each member of that group(givenname, surname, mail, phone and principal_uid).  
1. A query is run against your Organization in RightScale to collect all users and determine what users need to be created and removed.  
1. All new users are created based on the attributes collected from LDAP.  
1. A query is run against your Organization in RightScale to collect the groups that match your LDAP groups and adjust their membership to match your LDAP groups membership.  
1. (Optional) And finally, users that are no longer members of your LDAP groups are removed from your RightScale Organization.  

## Script Differences
RightScale_Group_Sync-PerUserLookup.ps1 - Performs a single LDAP query per user to collect details.
RightScale_Group_Sync-PerGroupLookup.ps1 - Performs an LDAP query using a filter of `isMemberOf` scoped to the discovered groups.

## Parameter Includes File
As opposed to passing all the parameters in during script execution, you can optionally create a file called `groupsync.config.ps1` in the same path as the group sync script and set some or all of the parameters there.
```powershell
# LDAP Connection Details
$LDAP_HOST = "ldap://ldapserver.acme.com"
$START_TLS = "true"
$LDAP_USER = "cn=Directory Manager"
$LDAP_USER_PASSWORD = "OpenSesame1"
$BASE_GROUP_DN = "OU=Groups,DC=acme,DC=com"
$BASE_USER_DN = "OU=People,DC=acme,DC=com"

# LDAP Info
$COMPANY_NAME = "ACME Corp."
$DEFAULT_PHONE_NUMBER = "555-867-5309"
$GROUP_CLASS = "groupOfNames"
$USER_CLASS = "person"
$PRINCIPAL_UID_ATTRIBUTE = "entryUUID"
$EMAIL_DOMAIN = "acme.com"
$GROUP_SEARCH_STRING = "RightScaleGroup*" # Partial wild card search
#$LIST_OF_GROUPS = "RightScaleGroup_Dev_Admins,RightScaleGroup_Dev_Observers" # List of groups to sync

#RightScale Details
$RS_HOST = "us-3.rightscale.com"
$CM_SSO_ACCOUNT = "12345"
$GRS_ACCOUNT = "54321"
$REFRESH_TOKEN = "abc...123"
$IDP_HREF = "/api/identity_providers/123"
$PURGE_USERS = "true"
```

## Script Parameters
`LDAP_HOST` : Connection string for LDAP host.  
ldap:// for non-secure and ldaps:// for secure.  
Port number can optionally bet set at the end if using a non-standard port for ldap(389) or ldaps(636).  
Example: ldap://ldap.acme.com:1389 or ldaps://ldap.acme.com:1636

`START_TLS` : Set to true to use StartTLS when connecting to your LDAP server.  
Possible Values: true, false  
Default Value: false

`LDAP_USER` : User to bind to the Directory Service as.  
Example: cn=Directory Manager

`LDAP_USER_PASSWORD` : Password for the LDAP_USER bind account.  

`BASE_GROUP_DN` : The base dn for groups in the Directory Service.  
Example: ou=Groups,DC=acme,DC=com

`BASE_USER_DN` : The base dn for users in the Directory Service.  
Example: ou=Users,DC=acme,DC=com

`GROUP_CLASS` : The Directory Services Object Class for groups of users.   
Example: groupOfNames

`USER_CLASS` : The Directory Services Object Class for users.  
Example: person

`PRINCIPAL_UID_ATTRIBUTE` : The name of the LDAP attribute to use for the RightScale principal_uid.  
Example: entryUUID

`GROUP_SEARCH_STRING` : LDAP search string used to filter groups to sync. Wildcard use is supported.  
Example: RightScaleGroup*  
Note: Cannot be used with `LIST_OF_GROUPS`

`LIST_OF_GROUPS` : Comma separated list of Groups to sync.  
Example: RightScale_Admins,RightScale_Observers  
Note: Cannot be used with `GROUP_SEARCH_STRING`

`EMAIL_DOMAIN` : The email domain to filter RightScale users on.  
Example: acme.com

`COMPANY_NAME` : Used to populate the company attribute when creating new users in RightScale.

`DEFAULT_PHONE_NUMBER` : Used when creating a new user in RightScale and their phone number in the LDAP directory is not defined.  
Recommend setting to the main company phone number.  
Example: 111-555-1212

`CM_SSO_ACCOUNT` : The RightScale account number the Single Sign-On(SSO) Identity Provider(IDP) is configured under.  
Example:12345

`GRS_ACCOUNT` : The account number for the RightScale Organization.  
Example:12345

`RS_HOST` : The RightScale host.  
Example: us-3.rightscale.com or us-4.rightscale.com

`REFRESH_TOKEN` : Refresh token for a RightScale user account that has the Enterprise Manager role.  
Used to create new users, add affiliations to the organization, remove affiliations to the organization, and modify group memberships.

`IDP_HREF` : The href of the IdP associated with the users of the Groups.  
Example: /api/identity_providers/123

`PURGE_USERS` : Set to 'true' to remove user affiliations from RightScale for users that are no longer members of an LDAP group.  
Possible Values: true, false  
Default Value: false