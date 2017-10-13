# RightScale LDAP Group Sync Tool

This group sync script is designed to sync groups from an LDAP provider to RightScale Governance.
It uses ldapsearch(Part of [openldap](https://www.openldap.org/software/download/) tools) and [PowerShell core](https://github.com/PowerShell/PowerShell).

## Important Considerations
The tool will not follow memberships for nested groups. Users must be direct members of the ldap groups to be synchronized.

## Script Parameters

`COMPANY_NAME`
Used to populate the company attribute when creating new users in RightScale.

`DEFAULT_PHONE_NUMBER`
Used when creating a new user in RightScale and their phone number in the ldap directory is not defined.
Recommend setting to the main company phone number.
Example: 111-555-1212

`CM_SSO_ACCOUNT`
The RightScale account number the Single Sign-On(SSO) Identity Provider(IDP) is configured under.
Example:12345

`GRS_ACCOUNT`
The account number for the RightScale Organization
Example:12345

`RS_HOST`
The RightScale host.
Example: us-3.rightscale.com or us-4.rightscale.com

`REFRESH_TOKEN`
Refresh token for a RightScale user account that has the Enterprise Manager role.
Used to create new users, add affiliations to the organization, remove affiliations to the organization, and modify group memberships.

`IDP_HREF`
The href of the IdP associated with the users of the Groups.
Example: /api/identity_providers/123

`LDAP_HOST`
Connection string for ldap host.
ldap:// for non-secure and ldaps:// for secure.
Port number can optionally bet set at the end if using a non-standard port for ldap(389) or ldaps(636).
Example: ldap://ldap.server:1389 or ldaps://ldap.server:1636"

`LDAP_USER`
User to bind to the Directory Service as.
Example: cn=Directory Manager

`LDAP_USER_PASSWORD`
Password for the LDAP_USER bind account.

`START_TLS`
Set to true to use StartTLS with ldapsearch command
Possible Values: true, false
Default Value: false

`BASE_GROUP_DN`
The base dn for groups in the Directory Service.
Example: ou=Groups,DC=some,DC=domain

`GROUP_CLASS`
The Directory Services Object Class for groups of users. 
Example: groupOfNames

`USER_CLASS`
The Directory Services Object Class for users.
Example: person

`GROUP_SEARCH_STRING`
LDAP search string to use to filter groups to sync. Wildcard must be added if required.
Example: RightScaleGroup*

`LIST_OF_GROUPS`
Comma separated list of Groups to sync.
Example: RightScale_Admins,RightScale_Observers

`PRINCIPAL_UID_ATTRIBUTE`
The name of the LDAP attribute to use for the RightScale principal_uid.
Example: entryUUID

`EMAIL_DOMAIN`
The email domain to filter RightScale users on.
Example: email.com

`PURGE_USERS`
Set to 'true' to remove user affiliations from RightScale that are no longer members of an LDAP group
Possible Values: true, false
Default Value: false
