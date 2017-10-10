#!/usr/bin/env powershell
# ---
# RightScript Name: RightScale Group Sync
# Description: >
#   Synchronizes members of a LDAP directory service with RightScale Governance Groups.
#   Requires: PowerShell Core, LDAPSEARCH
#   If a group is managed by this script, you will be unable to manually add/remove users via Governance.
# Inputs:
#   COMPANY_NAME:
#     Category: RIGHTSCALE
#     Description: "Used when creating a new user in RightScale."
#     Input Type: single
#     Required: true
#     Advanced: false
#   CM_SSO_ACCOUNT:
#     Category: RIGHTSCALE
#     Description: "The account number the SSO IdP is configured under."
#     Input Type: single
#     Required: true
#     Advanced: false
#   GRS_ACCOUNT:
#     Category: RIGHTSCALE
#     Description: "The account number for the RightScale Organization."
#     Input Type: single
#     Required: true
#     Advanced: false
#   RS_HOST:
#     Category: RIGHTSCALE
#     Description: "RightScale host. Example: us-3.rightscale.com or us-4.rightscale.com"
#     Input Type: single
#     Required: true
#     Advanced: false
#   REFRESH_TOKEN:
#     Category: RIGHTSCALE
#     Description: "Refresh token for a RightScale user account that has the Enterprise Manager role."
#     Input Type: single
#     Required: true
#     Advanced: false
#   IDP_HREF:
#     Category: RIGHTSCALE
#     Description: "The href of the IdP associated with the users of the Groups. Example: /api/identity_providers/123"
#     Input Type: single
#     Required: true
#     Advanced: false
#   LDAP_HOST:
#     Category: LDAP
#     Description: "Connection string for ldap host. Example: ldap://ldap.server:1389 or ldaps://ldap.server:1636"
#     Input Type: single
#     Required: true
#     Advanced: false
#   LDAP_USER:
#     Category: LDAP
#     Description: "User that has read access to the Directory Service. Example: cn=Directory Manager"
#     Input Type: single
#     Required: true
#     Advanced: false
#   LDAP_USER_PASSWORD:
#     Category: LDAP
#     Description: "Password for the LDAP user"
#     Input Type: single
#     Required: true
#     Advanced: false
#   BASE_DN:
#     Category: LDAP
#     Description: "The base dn of the Directory Service. Example: DC=some,DC=domain"
#     Input Type: single
#     Required: true
#     Advanced: false
#   GROUP_CLASS:
#     Category: LDAP
#     Description: "The Directory Services Object Class for groups of users. Example: groupOfNames"
#     Input Type: single
#     Required: true
#     Advanced: false
#   USER_CLASS:
#     Category: LDAP
#     Description: "The Directory Services Object Class for users. Example: person"
#     Input Type: single
#     Required: true
#     Advanced: false
#   GROUP_SEARCH_STRING:
#     Category: LDAP
#     Description: "LDAP search string to use to filter groups to sync. Wildcard must be added if required. Example: RightScaleGroup*"
#     Input Type: single
#     Required: false
#     Advanced: false
#   LIST_OF_GROUPS:
#     Category: LDAP
#     Description: "Comma seperated list of Groups to sync. Example: RightScale_Admins,RightScale_Observers"
#     Input Type: single
#     Required: false
#     Advanced: false
#   PRINCIPAL_UID_ATTRIBUTE:
#     Category: LDAP
#     Description: "The name of the LDAP attribute to use for the RightScale principal_uid"
#     Input Type: single
#     Required: true
#     Advanced: false
#   EMAIL_DOMAIN:
#     Category: LDAP
#     Description: "The email domain to filter RightScale users on. Example: email.com"
#     Input Type: single
#     Required: true
#     Advanced: false
#   PURGE_USERS:
#     Category: RIGHTSCALE
#     Description: "Set to 'true' to remove user affiliations from RightScale that are no longer members of an LDAP group"
#     Input Type: single
#     Required: true
#     Advanced: false
#     Possible Values: 
#       - text:true
#       - text:false
#     Default: text:false
# ...

# Present parameters to allow script be used outside of a RightScript
param(
    $COMPANY_NAME = $ENV:COMPANY_NAME, # Used when creating a new user in RightScale
    $CM_SSO_ACCOUNT = $ENV:CM_SSO_ACCOUNT, # The account number the SSO IdP is configured under
    $GRS_ACCOUNT = $ENV:GRS_ACCOUNT, # The account number for the RightScale Organization
    $RS_HOST = $ENV:RS_HOST, # RightScale host. Example: us-3.rightscale.com or us-4.rightscale.com
    $REFRESH_TOKEN = $ENV:REFRESH_TOKEN, # Refresh token for a RightScale user account that has the Enterprise Manager role
    $IDP_HREF = $ENV:IDP_HREF, # The href of the IdP associated with the users of the Groups. Example: /api/identity_providers/123
    $LDAP_HOST = $ENV:LDAP_HOST, # Connection string for ldap host. Example: ldap://ldap.server:1389 or ldaps://ldap.server:1636
    $LDAP_USER = $ENV:LDAP_USER, # User that has read access to the Directory Service. Example: cn=Directory Manager
    $LDAP_USER_PASSWORD = $ENV:LDAP_USER_PASSWORD, # Password for the LDAP user
    $BASE_DN = $ENV:BASE_DN, # The base dn of the Directory Service. Example: DC=some,DC=domain
    $GROUP_CLASS = $ENV:GROUP_CLASS, # The Directory Services Object Class for groups of users. Example: groupOfNames
    $USER_CLASS = $ENV:USER_CLASS, # The Directory Services Object Class for users. Example: person
    $GROUP_SEARCH_STRING = $ENV:GROUP_SEARCH_STRING, # LDAP search string to use to filter groups to sync. Wildcard must be added if required. Example: RightScaleGroup*
    $LIST_OF_GROUPS = $ENV:LIST_OF_GROUPS, # Comma seperated list of Groups to sync. Example: RightScale_Admins,RightScale_Observers
    $PRINCIPAL_UID_ATTRIBUTE = $ENV:PRINCIPAL_UID_ATTRIBUTE, # The name of the LDAP attribute to use for the RightScale principal_uid
    $EMAIL_DOMAIN = $ENV:EMAIL_DOMAIN, # The email domain to filter RightScale users on. Example: email.com
    $PURGE_USERS = $ENV:PURGE_USERS # Set to 'true' to remove user affiliations from RightScale that are no longer members of an LDAP group
)

$errorActionPreference = 'stop'

# crontab infomation
# ensure script has execute permission set
# ensure PATH is available in crontab
# use config file (groupsync.config.ps1), stored in the same path 
# as the script, to set the inputs and keep them out of crontab.
# to run every 15 minutes:
# */15 * * * * /path/to/script/rightscale_group_sync.ps1

#$currentTime = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-Date)).Ticks
#$logFilePath = Join-Path "/tmp" "rs_groupsync_$currentTime.log"
$logFilePath = "/tmp/rightscale_group_sync.log"

if(Test-Path $logFilePath) {
    Remove-Item -Path $logFilePath
}

## Functions
function Write-Log ($Message, [switch]$OutputToConsole) {
    if(-not(Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType "File" > $null
    }
    
    #$currentTime = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-Date)).Ticks #epoch time
    $currentTime = Get-Date -Format "dd-MM-yyyy HH:mm:ss z"
    $logMessage = "[$currentTime] $Message"
    $logMessage | Out-File -FilePath $logFilePath -Append -Encoding "UTF8"

    if($OutputToConsole) {
        Write-Host $logMessage
    }
}

function New-RSAuditEntry ($RSHost, $AccessToken, $Auditee, $Summary, $Detail) {
    try {
        #Write-Log -Message "Creating RightScale Audit Entry '$Summary'..." -OutputToConsole

        $contentType = "application/json"
        
        $auditHeader = @{
            "X_API_VERSION"="1.5";
            "Authorization"="Bearer $AccessToken"
        }

        $auditEntryBodyPayload = @{
            "audit_entry" = @{
                "auditee_href" = $Auditee
                "detail" = $Detail
                "summary" = $Summary
            }
        } | ConvertTo-Json
        
        $auditEntryResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RSHost/api/audit_entries" -Method Post -Headers $auditHeader -ContentType $contentType -Body $auditEntryBodyPayload
        if($auditEntryResult.StatusCode -ne "201") {
            Write-Log -Message "Error creating RightScale Audit Entry '$Summary'! Status Code: $($auditEntryResult.StatusCode)" -OutputToConsole
        }
    }
    catch {
        Write-Log -Message "Error creating RightScale Audit Entry! Error: $($_ | Out-String)" -OutputToConsole
    }
}

function New-RSUser ($RSHost, $AccessToken, $GRSAccount, $Email, $FirstName, $LastName, $Company, $Phone, $IdentityProvider, $PrincipalUID) {
    try {
        Write-Log -Message "Creating new RightScale user $Email..." -OutputToConsole

        $contentType = "application/json"

        $newUserHeader = @{
            "X_API_VERSION"="1.5";
            "Authorization"="Bearer $AccessToken"
        }

        $newUserBodyPayload = @{
            "user" = [ordered]@{
                "first_name" = $FirstName
                "last_name" = $LastName
                "company" = $Company
                "email" = $Email
                "phone" = $Phone
                "identity_provider_href" = $IdentityProvider
                "principal_uid" = $PrincipalUID
            }
        }
        
        $newUserResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RSHost/api/users" -Method Post -Headers $newUserHeader -ContentType $contentType -Body ($newUserBodyPayload | ConvertTo-Json)
        
        if($newUserResult.StatusCode -eq "201") {
            $newUserHref = $newUserResult.Headers.Get_Item('Location')
            Write-Log -Message "Successfully created new RightScale user: $Email! Href: $newUserHref" -OutputToConsole
            $newUserBodyPayload | Add-Member -MemberType NoteProperty -Name "rs_user_href" -Value $newUserHref
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Successfully created new RightScale user: $Email!" -Detail ($newUserBodyPayload | ConvertTo-Json)
            
            try {
                # Affiliate user with the org
                Write-Log -Message "Affiliating $Email with Organization..." -OutputToConsole
                $newUserId = $newUserHref | Split-Path -Leaf

                $contentType = "application/json"

                $grsHeader = @{
                    "X-API-Version"="2.0";
                    "Authorization"="Bearer $AccessToken"
                }

                $newUserAffiliationBodyPayload = [ordered]@{
                    "id" = $newUserId
                    "href" = "/grs/users/$newUserId"
                    "kind" = "user"
                } | ConvertTo-Json
            
                $newUserAffiliationResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RSHost/grs/orgs/$GRSAccount/users" -Method Post -Headers $grsHeader -ContentType $contentType -Body $newUserAffiliationBodyPayload
                
                if($newUserAffiliationResult.StatusCode -eq "201") {
                    Write-Log -Message "Sucessfully affiliated $Email with Organization!" -OutputToConsole
                    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Successfully affiliated $Email with Organization" -Detail $newUserAffiliationResult.RawContent
                }
                else {
                    Write-Log -Message "Error affiliating $Email with Organization! Status Code: $($newUserResult.StatusCode)" -OutputToConsole
                    New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error affiliating new RightScale user: $Email!" -Detail "Status Code: $($newUserAffiliationResult.StatusCode)`n`n$($newUserAffiliationBodyPayload | ConvertTo-Json)`n`n$($newUserAffiliationResult.RawContent)"
                }
            }
            catch {
                Write-Log -Message "Error affiliating $Email! $($_ | Out-String)" -OutputToConsole
                New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error affiliating user: $Email!" -Detail ($_ | Out-String)
            }
            RETURN $true
        }
        else {
            Write-Log -Message "Error creating new RightScale user: $Email! Status Code: $($newUserResult.StatusCode)" -OutputToConsole
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error creating new RightScale user: $Email!" -Detail "Status Code: $($newUserResult.StatusCode)`n`n$($newUserBodyPayload | ConvertTo-Json)`n`n$($newUserResult.RawContent)"
            RETURN $false
        }
    }
    catch {
        Write-Log -Message "Error creating $Email! $($_ | Out-String)" -OutputToConsole
        New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error creating user: $Email!" -Detail ($_ | Out-String)
    }
}

function Set-RSGroupMembership ($RSHost, $AccessToken, $GRSAccount, $GroupName, $GroupID, $UserPayload) {
    try {
        Write-Log -Message "Updating '$GroupName' membership..." -OutputToConsole
        
        $contentType = "application/json"
        
        $grsHeader = @{
            "X-API-Version"="2.0";
            "Authorization"="Bearer $AccessToken"
        }

        $membershipBodyPayload = [ordered]@{
            "group" = [ordered]@{
                "id" = $GroupID
                "href" = "/grs/orgs/$GRSAccount/groups/$GroupID"
                "kind" = "group"
            }
            "users" = @(
                $userPayload
            )
        } | ConvertTo-Json

        New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Updating Group: $GroupName" -Detail "Desired membership:`n$membershipBodyPayload"
        $membershipResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RSHost/grs/orgs/$GRSAccount/memberships" -Method Put -Headers $grsHeader -ContentType $contentType -Body $membershipBodyPayload
        
        if($membershipResult.StatusCode -eq "204") {
            Write-Log -Message "Successfully updated '$GroupName' membership!" -OutputToConsole
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Successfully Updated Group: $GroupName" -Detail $($membershipResult.RawContent)
        }
        else {
            Write-Log -Message "Error updating '$GroupName' membership!" -OutputToConsole
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error Updating Group: $GroupName" -Detail "Status Code: $($membershipResult.StatusCode)`n`n$($membershipResult.RawContent)"
        }
    }
    catch {
        Write-Log -Message "Error updating '$GroupName' membership! $($_ | Out-String)" -OutputToConsole
        New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error Updating Group: $GroupName" -Detail ($_ | Out-String)
    }
}

function Remove-RSUser ($RSHost, $AccessToken, $GRSAccount, $UserID, $Email) {
    try {
        Write-Log -Message "Removing $Email affiliation with organization... " -OutputToConsole
        
        $contentType = "application/json"

        $grsHeader = @{
            "X-API-Version"="2.0";
            "Authorization"="Bearer $AccessToken"
        }
        
        $deleteResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RSHost/grs/orgs/$GRSAccount/users/$UserID" -Method Delete -Headers $grsHeader -ContentType $contentType

        if ($deleteResult.StatusCode -eq 204) {
            Write-Log -Message "Successfully removed $Email affiliation!" -OutputToConsole
            RETURN $true
        }
        else {
            Write-Log -Message "Error removing $Email affiliation! Status Code: $($deleteResult.StatusCode)" -OutputToConsole
            RETURN $false
        }
    }
    catch {
        Write-Log -Message "Error removing $Email affiliation! $($_ | Out-String)" -OutputToConsole
        New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error removing $Email affiliation!" -Detail ($_ | Out-String)
    }
}


## Main
Write-Log -Message "Group Sync Starting..." -OutputToConsole

# Look for config file and if exists, use to set paramters
$parentPath = Split-Path -Parent $PSCommandPath
$configFile = Join-Path -Path $parentPath -ChildPath "groupsync.config.ps1"
if(Test-Path $configFile) {
    Write-Log -Message "Using config file to populate variables: $configFile" -OutputToConsole
    . $configFile
}

# Get access token from CM
Write-Log -Message  "Getting RightScale CM Access Token..." -OutputToConsole
$contentType = "application/json"
$oauthHeader = @{"X_API_VERSION"="1.5"}
$oauthBody = @{
    "grant_type"="refresh_token";
    "refresh_token"=$REFRESH_TOKEN
} | ConvertTo-Json
$oauthResult = Invoke-RestMethod -UseBasicParsing -Uri "https://$RS_HOST/api/oauth2" -Method Post -Headers $oauthHeader -ContentType $contentType -Body $oauthBody
$accessToken = $oauthResult.access_token

if (-not($accessToken)) {
    Write-Log -Message "Error retreiving access token!" -OutputToConsole
    EXIT 1
}

# Use access token as bearer for GRS api calls
$grsHeader = @{
    "X-API-Version"="2.0";
    "Authorization"="Bearer $accessToken"
}

$auditeeHref = "/api/accounts/$CM_SSO_ACCOUNT"

New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Starting" -Detail $null

# Validate parameters/inputs
$parameterErrors = 0
$failedParameters = ""
$sensitiveParameters = "REFRESH_TOKEN","LDAP_USER_PASSWORD"
$regularParameters = "COMPANY_NAME","CM_SSO_ACCOUNT","GRS_ACCOUNT","RS_HOST","IDP_HREF","LDAP_HOST","LDAP_USER","BASE_DN","GROUP_CLASS","USER_CLASS","PRINCIPAL_UID_ATTRIBUTE","EMAIL_DOMAIN"
$parametersToValidate = $regularParameters + $sensitiveParameters
foreach($parameterToValidate in $parametersToValidate) {
    if (((Get-Variable -Name $parameterToValidate -ValueOnly -ErrorAction SilentlyContinue) -eq "") -or ((Get-Variable -Name $parameterToValidate -ValueOnly -ErrorAction SilentlyContinue) -eq $null)) {
        Write-Log -Message "Error! $parameterToValidate must be defined" -OutputToConsole
        $parameterErrors ++
        $failedParameters += $parameterToValidate
    }
}

if(-not($PURGE_USERS)) {
    Write-Log -Message "PURGE_USERS not defined. Defaulting to 'false'..." -OutputToConsole
    $PURGE_USERS = $false
}

if (($GROUP_SEARCH_STRING.Length -eq 0) -and ($LIST_OF_GROUPS.Length -eq 0)) {
    Write-Log -Message "Either GROUP_SEARCH_STRING or LIST_OF_GROUPS must be defined. Please define one." -OutputToConsole
    $parameterErrors ++
    $failedParameters += "GROUP_SEARCH_STRING", "LIST_OF_GROUPS"
}
elseif (($GROUP_SEARCH_STRING.Length -gt 0) -and ($LIST_OF_GROUPS.Length -gt 0)) {
    Write-Log -Message "GROUP_SEARCH_STRING and LIST_OF_GROUPS cannot be used together. Please define one and leave the other blank." -OutputToConsole
    $parameterErrors ++
    $failedParameters += "GROUP_SEARCH_STRING", "LIST_OF_GROUPS"
}

if($parameterErrors -gt 0) {
    $parameterFailureMessage = "The following parameters have failed validation: $failedParameters"
    Write-Log -Message $parameterFailureMessage  -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Parameter validation failure" -Detail $parameterFailureMessage
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}

## LDAP directory
# Determine if using list or search string and build the filter
if ($GROUP_SEARCH_STRING -ne $null) {
    $groupsFilter = "(&(objectClass=$GROUP_CLASS)(cn=$GROUP_SEARCH_STRING))"
    Write-Log -Message "Getting all LDAP groups matching '$GROUP_SEARCH_STRING'..." -OutputToConsole
}
elseif ($LIST_OF_GROUPS -ne $null) {
    $groupsToFilter = $null
    foreach ($group in $LIST_OF_GROUPS.Split(',')) {
        $groupsToFilter += "(cn=$group)"
    }
    $groupsFilter = "(&(objectClass=$ENV:GROUP_CLASS)(|$groupsToFilter))"
    Write-Log -Message "Getting all groups matching '$LIST_OF_GROUPS'..." -OutputToConsole
}
else {
    $parameterFailureMessage = "A 'GROUP_SEARCH_STRING' or 'LIST_OF_GROUPS' must be specified!"
    Write-Log -Message $parameterFailureMessage  -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Parameter validation failure" -Detail $parameterFailureMessage
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}

# Get the LDAP groups
#$rawGroups = ldapsearch -LLL -x -H $LDAP_HOST -D $LDAP_USER -w $LDAP_USER_PASSWORD -b $BASE_DN $groupsFilter dn cn member
try {
    $rawGroups = (Invoke-Expression -Command "ldapsearch -LLL -x -H $LDAP_HOST -D '$LDAP_USER' -w '$LDAP_USER_PASSWORD' -b '$BASE_DN' '$groupsFilter' dn cn member" -ErrorVariable ldapGroupLookupError -ErrorAction SilentlyContinue) 2>&1

    if($lastexitcode -ne 0) {
        $ldapErrorMessage = "Error retrieveing groups from LDAP!"
        Write-Log "$ldapErrorMessage Error: $ldapGroupLookupError" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($ldapGroupLookupError | Out-String)
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
        EXIT 1
    }
    elseif (-not($rawGroups)) {
        $ldapErrorMessage = "Error retrieveing groups from LDAP!"
        Write-Log "$ldapErrorMessage Error: No groups returned!" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail "No groups returned with filter: $groupsFilter"
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
        EXIT 1
    }
    else {
        $rawGroups = $rawGroups | ForEach-Object {$_.TrimEnd()} | Where-Object {$_ -ne ""} #Remove empty lines
        $rawGroups = $rawGroups | Where-Object {$_ -notmatch "# ref"} #Needed for Active Directory
        $rawGroups = $rawGroups -join "`n" -split '(?ms)(?=^dn:)' -match '^dn:' #Split into seperate objects
    }
}
catch {
    $ldapErrorMessage = "Error retrieveing groups from LDAP!"
    Write-Log "$ldapErrorMessage Error: $($_)" -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($_ | Out-String)
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}

# Create LDAP groups object
$ldapGroups = @()
foreach ($group in $rawGroups) {
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name dn -Value $($group -split '\n' -match '^dn:' -replace 'dn:\s','')
    $object | Add-Member -MemberType NoteProperty -Name cn -Value $($group -split '\n' -match '^cn:' -replace 'cn:\s','')
    $object | Add-Member -MemberType NoteProperty -Name members -Value ($group -split '\n' -match '^member:' -replace 'member:\s','')
    $ldapGroups += $object
}
Write-Log -Message "$($ldapGroups.Count) LDAP Group(s) found." -OutputToConsole

# Collect only users of the RightScale groups
#$allLDAPRSUsers = $ldapGroups.members | Select-Object -Unique

# Build user LDAP filter
# Potentially expensive query, alternative is to do a single search per user dn, or get all LDAP users and do a client side filter
$groupsToFilter = $null
foreach ($group in $ldapGroups.dn) {
    $groupsToFilter += "(isMemberOf=$group)"
}
$userFilter = "(&(objectClass=$USER_CLASS)(|$groupsToFilter))"

# Get the LDAP users
try {
    Write-Log -Message "Getting all members of filtered LDAP groups..." -OutputToConsole
    #$rawUsers = & ldapsearch -LLL -x -H $LDAP_HOST -D $LDAP_USER -w $LDAP_USER_PASSWORD -b $BASE_DN $userFilter sn givenName mail telephoneNumber $PRINCIPAL_UID_ATTRIBUTE
    $rawUsers = (Invoke-Expression -Command "ldapsearch -LLL -x -H $LDAP_HOST -D '$LDAP_USER' -w '$LDAP_USER_PASSWORD' -b '$BASE_DN' '$userFilter' sn givenName mail telephoneNumber $PRINCIPAL_UID_ATTRIBUTE" -ErrorVariable ldapUserLookupError -ErrorAction SilentlyContinue) 2>&1
    if($lastexitcode -ne 0) {
        $ldapErrorMessage = "Error retrieveing users from LDAP!"
        Write-Log "$ldapErrorMessage Error: $ldapUserLookupError" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($ldapUserLookupError | Out-String)
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
        EXIT 1
    }
    elseif (-not($rawUsers)) {
        $ldapErrorMessage = "Error retrieveing users from LDAP!"
        Write-Log "$ldapErrorMessage Error: No users returned!" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail "No groups returned with filter: $userFilter"
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
        EXIT 1
    }
    else {
        $rawUsers = $rawUsers | ForEach-Object {$_.TrimEnd()} | Where-Object {$_ -ne ""} #Remove empty lines
        $rawUsers = $rawUsers | Where-Object {$_ -notmatch "# ref"} #Needed for Active Directory
        $rawUsers = $rawUsers -join "`n" -split '(?ms)(?=^dn:)' -match '^dn:' #Split into seperate objects
    }
}
catch {
    $ldapErrorMessage = "Error retrieveing users from LDAP!"
    Write-Log "$ldapErrorMessage Error: $($_)" -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($_ | Out-String)
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}

# Create LDAP users object
$ldapUsers = @()
foreach ($user in $rawUsers) {
    $phoneNumber = $null
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name dn -Value $($user -split '\n' -match '^dn:' -replace 'dn:\s','')
    $object | Add-Member -MemberType NoteProperty -Name sn -Value $($user -split '\n' -match '^sn:' -replace 'sn:\s','')
    $object | Add-Member -MemberType NoteProperty -Name givenName -Value $($user -split '\n' -match '^givenName:' -replace 'givenName:\s','')
    $object | Add-Member -MemberType NoteProperty -Name email -Value $($user -split '\n' -match '^mail:' -replace 'mail:\s','')
    $object | Add-Member -MemberType NoteProperty -Name $PRINCIPAL_UID_ATTRIBUTE -Value  $($user -split '\n' -match "^$([regex]::Escape($PRINCIPAL_UID_ATTRIBUTE)):" -replace "$([regex]::Escape($PRINCIPAL_UID_ATTRIBUTE)):\s",'')
    $phoneNumber = $($user -split '\n' -match '^telephoneNumber:' -replace 'telephoneNumber:\s','')
    if (($phoneNumber -eq $null) -or ($phoneNumber.length -eq 0) -or ($phoneNumber -notmatch '^[\.()\s\d+-]+$')) {
        $phoneNumber = "867-5309"
    }
    $object | Add-Member -MemberType NoteProperty -Name telephoneNumber -Value $phoneNumber
    $ldapUsers += $object
}
Write-Log -Message "$($ldapUsers.Count) LDAP User(s) found." -OutputToConsole

## RightScale Governance
# Get RightScale users
Write-Log -Message "Getting All RightScale Users... " -OutputToConsole
$rsGRSUsers = Invoke-RestMethod -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/users" -Method Get -Headers $grsHeader -ContentType $contentType
if(-not($rsGRSUsers)) {
    Write-Log -Message "Error retrieving users from RightScale!" -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}
$initialRSGRSUsersCount = $rsGRSUsers.Count
Write-Log -Message "$initialRSGRSUsersCount RightScale User(s) found." -OutputToConsole

# Determine if users need to be created or deleted
$usersToModify = Compare-Object -ReferenceObject $ldapUsers -DifferenceObject $rsGRSUsers -Property email
$usersToCreate = $usersToModify | Where-Object { $_.SideIndicator -eq "<=" } | Select-Object -ExpandProperty email
$usersToDelete = $usersToModify | Where-Object { $_.SideIndicator -eq "=>" } | Where-Object { $_.email -like "*$EMAIL_DOMAIN"} | Select-Object -ExpandProperty email

# Create new users
$newUsersCreated = @()
$newUsersNotCreated = @()
if($usersToCreate.count -gt 0){
    Write-Log -Message "$($usersToCreate.count) new user(s) to create..." -OutputToConsole
    foreach($user in $usersToCreate) {
        # Create New User and Set identity_provider, principal_uid, first_name, last_name, email, company and phone
        $ldapUser = $ldapUsers | Where-Object {$_.email -eq $user}

        $newUserParams = @{
            "FirstName" = $($ldapUser.givenName)
            "LastName" = $($ldapUser.sn)
            "Company" = $COMPANY_NAME
            "Email" = $($ldapUser.email)
            "Phone" = $($ldapUser.telephoneNumber)
            "IdentityProvider" = $IDP_HREF
            "PrincipalUID" = $($ldapUser.$PRINCIPAL_UID_ATTRIBUTE)
        }
        
        $newRSUserResult = New-RSUser -RSHost $RS_HOST -AccessToken $accessToken -GRSAccount $GRS_ACCOUNT @newUserParams
        if($newRSUserResult -eq $true) {
            $newUsersCreated += $ldapUser
        }
        else {
            $newUsersNotCreated += $ldapUser
        }
    }

    # Create audit entry for users created and not created
    $usersCreatedDetails = "Users created successfully: $($newUsersCreated | Out-String)"
    $usersCreatedDetails += "Users NOT created successfully: $($newUsersNotCreated | Out-String)"
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: User(s) Created" -Detail $usersCreatedDetails
}
else {
    Write-Log -Message "No new users to create." -OutputToConsole
}

if($newUsersCreated.count -gt 0) {
    Write-Log -Message "New user(s) created: $($newUsersCreated.count)" -OutputToConsole
    
    # Sleep to allow for replication
    $sleepSeconds = 60
    Write-Log -Message "Sleeping $sleepSeconds seconds to allow for user replication..." -OutputToConsole
    Start-Sleep -Seconds $sleepSeconds

    # Get Users again to account for newly added users
    Write-Log -Message "Getting All RightScale Users..." -OutputToConsole
    $rsGRSUsers = Invoke-RestMethod -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/users" -Method Get -Headers $grsHeader -ContentType $contentType
    if(-not($rsGRSUsers)) {
        Write-Log -Message "Error retrieving users from RightScale!" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
        EXIT 1
    }
    Write-Log -Message "$($rsGRSUsers.Count) RightScale User(s) found." -OutputToConsole
}

# Get RightScale groups
Write-Log -Message "Getting All RightScale Groups..." -OutputToConsole
$rsGRSGroups = Invoke-RestMethod -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/groups" -Method Get -Headers $grsHeader -ContentType $contentType
if(-not($rsGRSGroups)) {
    Write-Log -Message "Error retrieving groups from RightScale!" -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}
Write-Log -Message "$($rsGRSGroups.Count) RightScale Group(s) found." -OutputToConsole

# Update Group memberships - "replace"
# Replaces the Users in a Group. If an empty list of Users is passed in the request, then all the Users are removed from the Group given in the request.
Write-Log -Message "Determining group memberships and updating..." -OutputToConsole
foreach ($ldapGroup in $ldapGroups) {
    $group = $null
    $group = $rsGRSGroups | Where-Object { $_.name -eq $ldapGroup.cn }
    if ($group -ne $null) {
        $userPayload = @()
        $group_name = $ldapGroup.cn
        $group_id = $group.id
        Write-Log -Message "Group: $group_name (RS ID: $group_id)" -OutputToConsole
        if($ldapGroup.members.count -gt 0) {
            foreach ($member in $ldapGroup.members) {
                $user_id = $null
                $user_email = $null
                $user_email = $ldapUsers | Where-Object { $_.dn -eq $member } | Select-Object -ExpandProperty email
                $user_id = $rsGRSUsers | Where-Object { $_.email -eq $user_email } | Select-Object -ExpandProperty id
                if($user_id -eq $null) {
                    Write-Log -Message "Error retrieving $user_email RightScale ID. Skipping..." -OutputToConsole
                }
                else {
                    Write-Log -Message "* Member: $user_email (RS ID: $user_id)" -OutputToConsole
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name id -Value $user_id
                    $object | Add-Member -MemberType NoteProperty -Name href -Value "/grs/users/$user_id"
                    $object | Add-Member -MemberType NoteProperty -Name kind -Value "user"
                    $userPayload += $object
                    
                }
            }
        }
        else {
            Write-Log -Message "* No members" -OutputToConsole
        }
        
        Set-RSGroupMembership -RSHost $RS_HOST -AccessToken $accessToken -GRSAccount $GRS_ACCOUNT -GroupName $group_name -GroupID $group_id -UserPayload $userPayload     
    }
    else {
        Write-Log -Message "$($ldapGroup.cn) does not exist! Please create it first!" -OutputToConsole
    }
}

# Remove User Associations for users that are no longer members of LDAP groups
# Users must not be a member of any groups, so we do this last
$usersDeleted = @()
$usersNotDeleted = @()
if($usersToDelete.count -gt 0){
    Write-Log -Message "$($usersToDelete.count) user(s) to remove..." -OutputToConsole
    if($PURGE_USERS -eq $true) {
        foreach($user in $usersToDelete) {
            $rsGRSUser = $rsGRSUsers | Where-Object { $_.email -eq $user}
            
            $deleteResult = Remove-RSUser -RSHost $RS_HOST -AccessToken $accessToken -GRSAccount $GRS_ACCOUNT -UserID $($rsGRSUser.id) -Email $($rsGRSUser.email)
            if ($deleteResult -eq $true) {
                $usersDeleted += $rsGRSUser
            }
            else {
                $usersNotDeleted += $rsGRSUser
            }
        }
        
        # Create audit entry for users removed and not removed
        $usersDeletedDetails = "Users removed successfully:$($usersDeleted | Out-String)`n"
        $usersDeletedDetails += "Users NOT removed successfully:`n $($usersNotDeleted | Out-String)`n"
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: User(s) Removed" -Detail $usersDeletedDetails
    }
    else {
        Write-Log -Message "In order to remove users, set the 'PURGE_USERS' parameter to 'true'" -OutputToConsole
    }
}   
else {
    Write-Log -Message "No users to remove." -OutputToConsole
}

Write-Log -Message "Group Sync Complete!" -OutputToConsole
New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete" -Detail (Get-Content -Path $logFilePath | Out-String)