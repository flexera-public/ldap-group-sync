# RightScale LDAP Group Sync Tool

:exclamation: *NOTE for Active Directory: This branch uses the distinguished name of each user to construct the FQDN of the domain to query with the `Get-ADObject` command. When using the FQDN of a domain as the the value for the `-Server` parameter, there is no guarantee which Domain Controller it will contact.*

This group sync script is designed to sync groups from an LDAP provider, or Active Directory, to RightScale Governance.
It uses native PowerShell on Windows or [PowerShell core](https://github.com/PowerShell/PowerShell) on Linux and ldapsearch(Part of [openldap](https://www.openldap.org/software/download/) tools) or the [Active Directory PowerShell Module](https://technet.microsoft.com/en-us/library/ee617195.aspx).

## Prerequisites
1. Native PowerShell on Windows or [PowerShell core](https://github.com/PowerShell/PowerShell) on Linux
1. For a non-Active Directory LDAP Directory Service, openldap tools are required:  
   * Linux: [https://www.openldap.org/software/download/](https://www.openldap.org/software/download/)
   * Windows: [https://www.userbooster.de/en/download/openldap-for-windows.aspx](https://www.userbooster.de/en/download/openldap-for-windows.aspx)
     * Ensure you add the **ClientTools** directory to your `PATH`
1. For Active Directory, installation of the Active Directory PowerShell module is recommended.

## Important Considerations
1. This tool will follow memberships for nested groups. All users of nested groups will be treated as members of the parent group.
1. Groups must already exist in RightScale with the proper roles assigned. This tool will not create groups.
1. Once a group is managed by this tool, you will no longer be able to manually make modifications to its members in RightScale Governance. Any changes you make to the group in RightScale Governance will be removed once the next group sync is run. Manage the group in your directory service
1. The time it takes to do a full sync is directly related to the number of groups and users you are synchronizing. We recommend running it a few times manually to get a good baseline before scheduling it to run on a reoccurring basis. Remember to add a buffer to the schedule to account for latency and additional users and groups that may be added in the future.
1. We recommend creating a group in RightScale Governance to manage users with the `enterprise_manager` role. It is important that this group is not synchronized from your directory service. This will ensure you have a fail-safe for gaining access to RightScale.

## Active Directory(AD)
1. If your directory service is Active Directory, and you will be running this script on a Microsoft Windows Server, please install the Active Directory PowerShell module.
1. When the Active Directory PowerShell module is installed on the Microsoft Windows Server running this script, the values of some parameters will automatically be overridden. Read the parameter details below carefully.  

## How It Works
1. The tool gathers groups from an LDAP directory service based on a comma separated list of groups. Wildcards are supported in the group names.
1. Once the groups are discovered, it collects the necessary details from each member of that group(Given name, Surname, Email Address, Phone Number and Principal UID).  
1. A query is run against your Organization in RightScale to collect all users and determine what users need to be created and removed.  
1. All new users are created based on the attributes collected from LDAP.  
1. A query is run against your Organization in RightScale to collect the groups that match your LDAP groups and adjust their membership to match your LDAP groups membership.  
1. (Optional) Users that are no longer members of your LDAP groups are removed from your RightScale Organization.  

## Parameter Includes File
As opposed to passing all the parameters in during script execution, you can optionally create a file called `groupsync.config.ps1` in the same path as the group sync script and set some or all of the parameters there.

LDAP Directory Example:
```powershell
# LDAP Connection Details
$LDAP_HOST = "ldap://ldapserver.acme.com"
$START_TLS = "true"
$LDAP_USER = "cn=Directory Manager"
$LDAP_USER_PASSWORD = "OpenSesame1"

# LDAP Info
$BASE_GROUP_DN = "OU=Groups,DC=acme,DC=com"
$GROUP_CLASS = "groupOfNames"
$USER_CLASS = "person"
$PRINCIPAL_UID_ATTRIBUTE = "entryUUID"
$GROUP_SEARCH_STRING = "RightScaleGroup_*,RS_Account_Admins"
$COMPANY_NAME = "ACME Corp."
$DEFAULT_PHONE_NUMBER = "555-867-5309"
$EMAIL_DOMAIN = "acme.com"

#RightScale Details
$RS_HOST = "us-3.rightscale.com"
$CM_SSO_ACCOUNT = "12345"
$GRS_ACCOUNT = "54321"
$REFRESH_TOKEN = "abc...123"
$IDP_HREF = "/api/identity_providers/123"
$PURGE_USERS = "true"
```

Active Directory Example:
```powershell
# AD Connection Details
$LDAP_HOST = "dc01.acme.com"
$LDAP_USER = "acme\directoryuser"
$LDAP_USER_PASSWORD = "OpenSesame1"

# AD Info
$BASE_GROUP_DN = "OU=Groups,DC=acme,DC=com"
$GROUP_SEARCH_STRING = "RightScaleGroup_*,RS_Account_Admins"
$COMPANY_NAME = "ACME Corp."
$DEFAULT_PHONE_NUMBER = "555-867-5309"
$EMAIL_DOMAIN = "acme.com"

#RightScale Details
$RS_HOST = "us-3.rightscale.com"
$CM_SSO_ACCOUNT = "12345"
$GRS_ACCOUNT = "54321"
$REFRESH_TOKEN = "abc...123"
$IDP_HREF = "/api/identity_providers/123"
$PURGE_USERS = "true"
```

## Executing as a RightScript
The script uses [RightScript metadata comments](http://docs.rightscale.com/cm/dashboard/design/rightscripts/rightscripts_metadata_comments.html) to define the parameters. This allows the script to be easily added to RightScale Cloud management for execution on a RightLink managed server.

Executing the script as RightScript on a RightLink managed server allows you to make use of RightScale [credentials](http://docs.rightscale.com/cm/dashboard/design/credentials/index.html) to safely store the value for the sensitive parameters referenced in executing this script.

You can also schedule the execution of the RightScript from the managed servers scheduling utility. Here is an example of some code that would setup a scheduled task on a Windows server to run the Per User Group Sync script, against Active Directory, every 15 minutes using RightScale credentials for the `LDAP_USER_PASSWORD` and `REFRESH_TOKEN` parameters.
```powershell
$jobname = "RightScale Group Sync"

## Define the arguments for RSC and the script
$script = "rl10 run_right_script /rll/run/right_script `"right_script_id=0123456789`" `"arguments=LDAP_HOST=text:dc01.acme.com`" `"arguments=LDAP_USER=text:directoryuser@acme.com`" `"arguments=LDAP_USER_PASSWORD=cred:Active_Directory_User_Password`" `"arguments=BASE_GROUP_DN=text:ou=Groups,DC=acme,DC=com`" `"arguments=GROUP_CLASS=text:group`" `"arguments=USER_CLASS=text:person`" `"arguments=PRINCIPAL_UID_ATTRIBUTE=text:objectSID`" `"arguments=GROUP_SEARCH_STRING=text:RightScaleGroup_* `" `"arguments=COMPANY_NAME=text:Acme Co.`" `"arguments=DEFAULT_PHONE_NUMBER=text:111-555-1212`" `"arguments=EMAIL_DOMAIN=text:acme.com`" `"arguments=RS_HOST=text:us-3.rightscale.com`" `"arguments=CM_SSO_ACCOUNT=text:54321`" `"arguments=GRS_ACCOUNT=text:12345`" `"arguments=REFRESH_TOKEN=cred:RightScale_Governance_Refresh_Token`" `"arguments=IDP_HREF=text:/api/identity_providers/123`" `"arguments=START_TLS=text:false`" `"arguments=PURGE_USERS=text:false`""

## Run every 'n' minutes
$repeat = (New-TimeSpan -Minutes 15)

$action = New-ScheduledTaskAction –Execute "C:\Program Files\RightScale\RightLink\rsc.exe" -Argument $script
$duration = New-TimeSpan -Days 3650
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
$task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -RunLevel Highest -User "NT AUTHORITY\SYSTEM" -Settings $settings
$task.Triggers.repetition.Duration = "" ## Setting duration to an empty string == 'indefinitely'
$task.Triggers.repetition.StopAtDurationEnd = "False"
$task | Set-ScheduledTask
```

## Executing as a standalone script via a cronjob in Linux
Assumptions:
* The script has the execute permission set
* `PATH` is available in crontab.
* A [parameter includes file](#parameter-includes-file) is stored in the same path 
as the script with all parameters defined.  

This example executes the Group Sync Script every 15 minutes:
```shell
*/15 * * * * /path/to/script/rightscale_group_sync.ps1
```

## Executing as a standalone script via a Scheduled Task in Windows
Assumptions:
* The downloaded script has been [unblocked](https://blogs.msdn.microsoft.com/delay/p/unblockingdownloadedfile/)
* A [parameter includes file](#parameter-includes-file) is stored in the same path 
as the script with all parameters defined.  

This example creates a scheduled task that executes the Group Sync Script every 15 minutes:
```powershell
$jobname = "RightScale Group Sync"

## Define PowerShell execution policy and path to the Group Sync Script
$script = "-ExecutionPolicy Bypass c:\path\to\script\rightscale_group_sync.ps1"

## Run every 'n' minutes
$repeat = (New-TimeSpan -Minutes 15)

$action = New-ScheduledTaskAction –Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $script
$duration = New-TimeSpan -Days 3650
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
$task = Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -RunLevel Highest -User "NT AUTHORITY\SYSTEM" -Settings $settings
$task.Triggers.repetition.Duration = "" ## Setting duration to an empty string == 'indefinitely'
$task.Triggers.repetition.StopAtDurationEnd = "False"
$task | Set-ScheduledTask
```

## Verified Against
* Windows Active Directory - 2012R2 Functional Level
* OpenDJ - Version 5.0.0

## Script Parameters
All parameters are required unless otherwise noted:  

`LDAP_HOST` **  
Connection string for LDAP host or FQDN of a Domain Controller for Active Directory.  
ldap:// for non-secure and ldaps:// for secure.  
Port number can optionally bet set at the end if using a non-standard port for ldap(389) or ldaps(636).  
**Example for LDAP:** ldap://ldap.acme.com:1389 or ldaps://ldap.acme.com:1636  
****Example for AD:** The FQDN of the DC you would like to use, dc01.acme.com

`START_TLS`  
Set to true to use StartTLS when connecting to your LDAP server.  
****Note:** Ignored for Active Directory module. Authentication is negotiated by default.  
**Possible Values:** true, false  
**Default Value:** false

`LDAP_USER` **  
User to bind to the Directory Service as.  
**Example for LDAP:** cn=Directory Manager  
****Example for AD:** directoryuser@acme.com

`LDAP_USER_PASSWORD`  
Password for the LDAP_USER account.  

`BASE_GROUP_DN`  
The base dn for groups in the Directory Service.  
**Example:** ou=Groups,DC=acme,DC=com

`GROUP_CLASS` **  
The Directory Services Object Class for groups of users.  
****Note:** Ignored for Active Directory module. The class 'group' is automatically used.  
**Example:** groupOfNames or group

`USER_CLASS` **  
The Directory Services Object Class for users.  
****Note:** Ignored for Active Directory module. The class 'person' is automatically used.  
**Example:** person

`PRINCIPAL_UID_ATTRIBUTE` **  
The name of the LDAP attribute to use for the RightScale principal_uid.  
****Note:** Ignored for Active Directory module. 'objectSID' is automatically used.  
**Reference:** [RightScale Docs - Configuring Single Sign-On (SSO)](http://docs.rightscale.com/platform/guides/configuring_sso/#detailed-instructions-step-2--set-up-attribute-mappings)  
**Example:** entryUUID or objectSID

`GROUP_SEARCH_STRING`  
LDAP search string used to filter groups to sync. Wildcard use is supported.  
**Example:** RightScaleGroup_*,RS_Account_Admins  

`EMAIL_DOMAIN`  
The email domain to filter RightScale users on.  
**Example:** acme.com

`COMPANY_NAME`  
Used to populate the company attribute when creating new users in RightScale.  
**Example:** Acme Co.

`DEFAULT_PHONE_NUMBER`  
Used when creating a new user in RightScale and their phone number in the LDAP directory is not defined.  
Recommend setting to the main company phone number.  
**Example:** 111-555-1212

`CM_SSO_ACCOUNT`  
The RightScale account number the Single Sign-On(SSO) Identity Provider(IDP) is configured under.  
**Reference:** Can be retrieved from the URL of the SSO configuration screen in RightScale Cloud Management: ht&#8203;tps://us-3.rightscale.com/global/enterprises/**54321**/sso  
**Example:** 54321

`GRS_ACCOUNT`  
The account number for the RightScale Organization.  
**Reference:** Can be retrieved from the RightScale Governance URL: ht&#8203;tps://governance.rightscale.com/org/**12345**/accounts/54321/users  
**Example:** 12345

`RS_HOST`  
The RightScale host.  
**Example:** us-3.rightscale.com or us-4.rightscale.com

`REFRESH_TOKEN`  
Refresh token for a RightScale user account that has the Enterprise Manager role.  
Used to create new users, add affiliations to the organization, remove affiliations to the organization, and modify group memberships.  
**Reference:** [RightScale Docs - Enable OAuth](http://docs.rightscale.com/cm/dashboard/settings/account/enable_oauth)  

`IDP_HREF`  
The href of the IdP associated with the users of the Groups.  
**Reference:** Can be retrieved by copying the link to edit your SSO: ht&#8203;tps://us-3.rightscale.com/global/enterprises/54321/edit_sso?identity_provider_id=**123** and grabbing the ID value at the end, or via the [RightScale Cloud Management API](http://reference.rightscale.com/api1.5/resources/ResourceIdentityProviders.html#index)  
**Example:** /api/identity_providers/123

`PURGE_USERS`  
Set to 'true' to remove user affiliations from RightScale for users that are no longer members of an LDAP group.  
**Possible Values:** true, false  
**Default Value:** false

## License
The LDAP Group Sync source code is subject to the MIT license, see the [LICENSE](./LICENSE) file.