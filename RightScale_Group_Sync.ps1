#!/usr/bin/env pwsh
# ---
# RightScript Name: RightScale Group Sync
# Description: >
#   Synchronizes members of a LDAP directory service with RightScale Governance Groups.
#   Requires: PowerShell Core and LDAPSEARCH or Active Directory PowerShell Module
#   If a group is managed by this script, you will be unable to manually add/remove users via RightScale Governance.
#   View the readme for further information: https://github.com/rs-services/ldap-group-sync
# Inputs:
#   COMPANY_NAME:
#     Category: RIGHTSCALE
#     Description: "Used when creating a new user in RightScale."
#     Input Type: single
#     Required: true
#     Advanced: false
#   DEFAULT_PHONE_NUMBER:
#     Category: RIGHTSCALE
#     Description: "Used when creating a new user in RightScale and their phone number in ldap is not defined."
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
#     Description: "Connection string for ldap host. Example: ldap://ldap.acme.com:1389 or ldaps://ldap.acme.com:1636 or if using Active Directory Module, the FQDN of the desired DC, dc01.acme.com"
#     Input Type: single
#     Required: true
#     Advanced: false
#   LDAP_USER:
#     Category: LDAP
#     Description: "User that has read access to the Directory Service. Example: 'cn=Directory Manager' or if using Active Directory Module 'domain\aduser'"
#     Input Type: single
#     Required: true
#     Advanced: false
#   LDAP_USER_PASSWORD:
#     Category: LDAP
#     Description: "Password for the LDAP user"
#     Input Type: single
#     Required: true
#     Advanced: false
#   START_TLS:
#     Category: LDAP
#     Description: "Set to true to use StartTLS with ldapsearch command. Note: Ignored if using Active Directory Module"
#     Input Type: single
#     Required: true
#     Advanced: false
#     Possible Values: 
#       - text:true
#       - text:false
#     Default: text:false
#   BASE_GROUP_DN:
#     Category: LDAP
#     Description: "The base dn for groups in the Directory Service. Example: ou=Groups,DC=acme,DC=com"
#     Input Type: single
#     Required: true
#     Advanced: false
#     Default: "text:ou=Groups,DC=acme,DC=com"
#   GROUP_CLASS:
#     Category: LDAP
#     Description: "The Directory Services Object Class for groups of users. Example: groupOfNames or group. Note: Ignored if using Active Directory Module"
#     Input Type: single
#     Required: true
#     Advanced: false
#     Default: "text:groupOfName"
#   USER_CLASS:
#     Category: LDAP
#     Description: "The Directory Services Object Class for users. Example: person. Note: Ignored if using Active Directory Module"
#     Input Type: single
#     Required: true
#     Advanced: false
#     Default: "text:person"
#   GROUP_SEARCH_STRING:
#     Category: LDAP
#     Description: "Comma separated list of Groups to sync. Wildcards are supported. Example: RightScaleGroup_*,RS_Account_Admins"
#     Input Type: single
#     Required: false
#     Advanced: false
#   PRINCIPAL_UID_ATTRIBUTE:
#     Category: LDAP
#     Description: "The name of the LDAP attribute to use for the RightScale principal_uid. Example: entryUUID. Note: For Active Directory this value is ignored and the users SID is automatically used."
#     Input Type: single
#     Required: true
#     Advanced: false
#     Default: "text:entryUUID"
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

#
# Version: 2.0
#

# Copyright 2017 RightScale
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Present parameters to allow script be used outside of a RightScript
param(
    $COMPANY_NAME = $ENV:COMPANY_NAME, # Used when creating a new user in RightScale
    $DEFAULT_PHONE_NUMBER = $ENV:DEFAULT_PHONE_NUMBER, # Used when creating a new user in RightScale and their phone number in ldap is not defined.
    $CM_SSO_ACCOUNT = $ENV:CM_SSO_ACCOUNT, # The account number the SSO IdP is configured under
    $GRS_ACCOUNT = $ENV:GRS_ACCOUNT, # The account number for the RightScale Organization
    $RS_HOST = $ENV:RS_HOST, # RightScale host. Example: us-3.rightscale.com or us-4.rightscale.com
    $REFRESH_TOKEN = $ENV:REFRESH_TOKEN, # Refresh token for a RightScale user account that has the Enterprise Manager role
    $IDP_HREF = $ENV:IDP_HREF, # The href of the IdP associated with the users of the Groups. Example: /api/identity_providers/123
    $LDAP_HOST = $ENV:LDAP_HOST, # Connection string for ldap host. Example: ldap://ldap.server:1389 or ldaps://ldap.server:1636
    $LDAP_HOST_PORT = $ENV:LDAP_HOST_PORT, # Tje port used to access the LDAP server. Example: 389, 636
    $LDAP_USER = $ENV:LDAP_USER, # User that has read access to the Directory Service. Example: cn=Directory Manager
    $LDAP_USER_PASSWORD = $ENV:LDAP_USER_PASSWORD, # Password for the LDAP user
    $START_TLS = $ENV:START_TLS, # Set to true to use StartTLS
    $BASE_GROUP_DN = $ENV:BASE_GROUP_DN, # The base dn for groups in the Directory Service. Example: DC=some,DC=domain
    $GROUP_CLASS = $ENV:GROUP_CLASS, # The Directory Services Object Class for groups of users. Example: groupOfNames
    $USER_CLASS = $ENV:USER_CLASS, # The Directory Services Object Class for users. Example: person
    $GROUP_SEARCH_STRING = $ENV:GROUP_SEARCH_STRING, # LDAP search string to use to filter groups to sync. Wildcard must be added if required. Example: RightScaleGroup*
    $PRINCIPAL_UID_ATTRIBUTE = $ENV:PRINCIPAL_UID_ATTRIBUTE, # The name of the LDAP attribute to use for the RightScale principal_uid
    $EMAIL_DOMAIN = $ENV:EMAIL_DOMAIN, # The email domain to filter RightScale users on. Example: email.com
    $PURGE_USERS = $ENV:PURGE_USERS # Set to 'true' to remove user affiliations from RightScale that are no longer members of an LDAP group
)

$errorActionPreference = 'stop'

# Define log file
$logFilePath = "/tmp/rightscale_group_sync.log"

# Delete log file if it already exists as history is saved in RS Audit Entires
if(Test-Path $logFilePath) {
    Remove-Item -Path $logFilePath
}

## Functions
function Write-Log ($Message, [switch]$OutputToConsole) {
    if(-not(Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType "File" -Force > $null
    }
    
    $currentTime = Get-Date -Format "dd-MMM-yyyy HH:mm:ss z"
    $logMessage = "[$currentTime] $Message"
    $logMessage | Out-File -FilePath $logFilePath -Append -Encoding "UTF8"

    if($OutputToConsole) {
        Write-Host $logMessage
    }
}

function New-RSAuditEntry ($RSHost, $AccessToken, $Auditee, $Summary, $Detail) {
    try {
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
            $newUserId = $newUserHref | Split-Path -Leaf
            $newUserBodyPayload.Add("rs_user_href", $newUserHref)
            Write-Log -Message "Successfully created new RightScale user: $Email (RS ID:$newUserId)!" -OutputToConsole
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Successfully created new RightScale user: $Email!" -Detail ($newUserBodyPayload | ConvertTo-Json)
            
            # Return relevant information to update GRS user list
            $userObject = New-Object -TypeName PSObject
            $userObject | Add-Member -MemberType NoteProperty -Name id -Value $newUserId
            $userObject | Add-Member -MemberType NoteProperty -Name email -Value $Email
            RETURN $userObject
        }
        else {
            Write-Log -Message "Error creating new RightScale user: $Email! Status Code: $($newUserResult.StatusCode)" -OutputToConsole
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error creating new RightScale user: $Email!" -Detail "Status Code: $($newUserResult.StatusCode)`n`n$($newUserBodyPayload | ConvertTo-Json)`n`n$($newUserResult.RawContent)"
            RETURN $false
        }
    }
    catch {
        Write-Log -Message "Error creating new RightScale user: $Email! $($_ | Out-String)" -OutputToConsole
        New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error creating new RightScale user: $Email!" -Detail ($_ | Out-String)
        RETURN $false
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
        Write-Log -Message "Removing $Email (RS ID: $UserId) affiliation with organization... " -OutputToConsole
        
        $contentType = "application/json"

        $grsHeader = @{
            "X-API-Version"="2.0";
            "Authorization"="Bearer $AccessToken"
        }
        
        $deleteResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RSHost/grs/orgs/$GRSAccount/users/$UserID" -Method Delete -Headers $grsHeader -ContentType $contentType -ErrorAction SilentlyContinue -ErrorVariable deleteResultVariable

        if ($deleteResult.StatusCode -eq 204) {
            Write-Log -Message "Successfully removed $Email (RS ID: $UserId) affiliation!" -OutputToConsole
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Successfully removed $Email affiliation!" -Detail "RightScale User ID: $UserId"
            RETURN $true
        }
        else {
            Write-Log -Message "Error removing $Email (RS ID: $UserId) affiliation! Status Code: $($deleteResult.StatusCode)" -OutputToConsole
            New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error removing $Email affiliation!" -Detail "$deleteResultVariable `nStatus Code: $($deleteResult.StatusCode)`n`n$($deleteResult.RawContent)"
            RETURN $false
        }
    }
    catch {
        Write-Log -Message "Error removing $Email (RS ID: $UserId) affiliation! Error: $($_.ErrorDetails.ToString())" -OutputToConsole
        New-RSAuditEntry -RSHost $RSHost -AccessToken $AccessToken -Auditee $auditeeHref -Summary "RS Group Sync: Error removing $Email affiliation!" -Detail ($_.ErrorDetails.ToString())
        RETURN $false
    }
}


## Main
Write-Log -Message "Group Sync Starting..." -OutputToConsole

# Look for config file and if exists, use to set parameters
$parentPath = Split-Path -Parent $PSCommandPath
$configFile = Join-Path -Path $parentPath -ChildPath "groupsync.config.ps1"
if(Test-Path $configFile) {
    Write-Log -Message "Using config file to populate variables: $configFile" -OutputToConsole
    . $configFile
}

# Look for Active Directory Module
if(Get-Module -Name ActiveDirectory -ListAvailable) {
    Write-Log "Found Active Directory PowerShell module!" -OutputToConsole
    $useADModule = $true
    $adSecurePassword = ConvertTo-SecureString $LDAP_USER_PASSWORD -AsPlainText -Force
    $adCredential = New-Object System.Management.Automation.PSCredential $LDAP_USER,$adSecurePassword
    $GROUP_CLASS = "group"
    $USER_CLASS = "user"
    $PRINCIPAL_UID_ATTRIBUTE = "objectSID"
}
else {
    $useADModule = $false
}

# Get access token from CM
Write-Log -Message  "Getting RightScale CM Access Token..." -OutputToConsole
$contentType = "application/json"
$oauthHeader = @{"X_API_VERSION"="1.5"}
$oauthBody = @{
    "grant_type"="refresh_token";
    "refresh_token"=$REFRESH_TOKEN
} | ConvertTo-Json
$oauthResult = Invoke-RestMethod -Uri "https://$RS_HOST/api/oauth2" -Method Post -Headers $oauthHeader -ContentType $contentType -Body $oauthBody
$accessToken = $oauthResult.access_token

if (-not($accessToken)) {
    Write-Log -Message "Error retrieving access token!" -OutputToConsole
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
$regularParameters = "COMPANY_NAME","DEFAULT_PHONE_NUMBER","CM_SSO_ACCOUNT","GRS_ACCOUNT","RS_HOST","IDP_HREF","LDAP_HOST","LDAP_USER","BASE_GROUP_DN","GROUP_CLASS","USER_CLASS","GROUP_SEARCH_STRING","PRINCIPAL_UID_ATTRIBUTE","EMAIL_DOMAIN"
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

if($START_TLS -eq $true) {
    $useTLS = "-ZZ"
}
else{
    $useTLS = ""
}

if($parameterErrors -gt 0) {
    $parameterFailureMessage = "The following parameters have failed validation: $failedParameters"
    Write-Log -Message $parameterFailureMessage  -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Parameter validation failure" -Detail $parameterFailureMessage
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}

## LDAP directory
# Build the groups LDAP filter
$groupsToFilter = $null
foreach ($group in $GROUP_SEARCH_STRING.Split(',')) {
    $groupsToFilter += "(cn=$group)"
}
$groupsFilter = "(&(objectClass=$GROUP_CLASS)(|$groupsToFilter))"
Write-Log -Message "Getting all groups matching '$GROUP_SEARCH_STRING'..." -OutputToConsole

# Get the LDAP groups
try {
    $ldapGroups = @()
    if($useADModule) {
        $rawGroups = Get-ADGroup -LDAPFilter $groupsFilter -Credential $adCredential -SearchBase $BASE_GROUP_DN -Server $LDAP_HOST -ErrorVariable ldapGroupLookupError -ErrorAction SilentlyContinue
    }
    else {
        $rawGroups = (Invoke-Expression -Command "ldapsearch -LLL -x -H $LDAP_HOST $useTLS -D '$LDAP_USER' -w '$LDAP_USER_PASSWORD' -b '$BASE_GROUP_DN' '$groupsFilter' dn cn member" -ErrorVariable ldapGroupLookupError -ErrorAction SilentlyContinue) 2>&1
    }

    if(-not($?)) {
        $ldapErrorMessage = "Error retrieving groups from LDAP!"
        Write-Log "$ldapErrorMessage Error: $ldapGroupLookupError" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($ldapGroupLookupError | Out-String)
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
        EXIT 1
    }
    elseif (-not($rawGroups)) {
        $ldapErrorMessage = "Error retrieving groups from LDAP!"
        Write-Log "$ldapErrorMessage Error: No groups returned!" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail "No groups returned with filter: $groupsFilter"
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
        EXIT 1
    }
    
    if($useADModule) {
        foreach ($group in $rawGroups) {
            $groupMembers = $group | Get-ADGroupMember -Credential $adCredential -Server $LDAP_HOST -Recursive | Select-Object -ExpandProperty distinguishedName
            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name dn -Value $group.DistinguishedName
            $object | Add-Member -MemberType NoteProperty -Name cn -Value $group.Name
            $object | Add-Member -MemberType NoteProperty -Name members -Value $groupMembers
            $ldapGroups += $object
        }
    }
    else {
        $rawGroups = $rawGroups | ForEach-Object {$_.TrimEnd()} | Where-Object {$_ -ne ""} #Remove empty lines
        $rawGroups = $rawGroups | Where-Object {$_ -notmatch "# ref"} #Needed for Active Directory
        $rawGroups = $rawGroups -join "`n" -split '(?ms)(?=^dn:)' -match '^dn:' #Split into separate objects
        foreach ($group in $rawGroups) {
            $cn = $($group -split '\n' -match '^cn:' -replace 'cn:\s','')
            $dn = $($group -split '\n' -match '^dn:' -replace 'dn:\s','')
            $ldapFilter = "(&(objectClass=$USER_CLASS)(isMemberOf=$dn))"
            $rawMembers = (Invoke-Expression -Command "ldapsearch -LLL -x -H $LDAP_HOST $useTLS -D '$LDAP_USER' -w '$LDAP_USER_PASSWORD' '$ldapFilter' uniqueMember" -ErrorVariable ldapGroupLookupError -ErrorAction SilentlyContinue) 2>&1
            $rawMembers = $rawMembers | ForEach-Object {$_.TrimEnd()} | Where-Object {$_ -ne ""} #Remove empty lines
            $rawMembers = $rawMembers | Where-Object {$_ -notmatch "# ref"} #Needed for Active Directory
            $rawMembers = $rawMembers -join "`n" -split '(?ms)(?=^dn:)' -match '^dn:' #Split into separate objects
            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name dn -Value $dn
            $object | Add-Member -MemberType NoteProperty -Name cn -Value $cn
            $object | Add-Member -MemberType NoteProperty -Name members -Value $($rawMembers -split '\n' -match '^dn:' -replace 'dn:\s','')
            $ldapGroups += $object
        }
    }
}
catch {
    $ldapErrorMessage = "Error retrieving groups from LDAP!"
    Write-Log "$ldapErrorMessage Error: $($_)" -OutputToConsole
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($_ | Out-String)
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete (With Errors)" -Detail (Get-Content -Path $logFilePath | Out-String)
    EXIT 1
}
Write-Log -Message "$($ldapGroups.Count) LDAP Group(s) found." -OutputToConsole

# Get the LDAP users of the discovered RightScale groups - single LDAP query per user
$ldapUsers = @()
$allLDAPRSUsers = $ldapGroups.members | Select-Object -Unique
foreach ($ldapUser in $allLDAPRSUsers) {
    try {
        Write-Log -Message "Getting user details for '$ldapUser'..." -OutputToConsole
        if($useADModule) {
            $rawUser = Get-ADObject -Identity $ldapUser -Credential $adCredential -Properties 'sn','givenName','mail','telephoneNumber',$PRINCIPAL_UID_ATTRIBUTE,'objectClass' -Server $LDAP_HOST -ErrorVariable ldapUserLookupError -ErrorAction SilentlyContinue
        }
        else {
            $rawUser = (Invoke-Expression -Command "ldapsearch -LLL -x -H $LDAP_HOST $useTLS -D '$LDAP_USER' -w '$LDAP_USER_PASSWORD' -s base -b '$ldapUser' sn givenName mail telephoneNumber $PRINCIPAL_UID_ATTRIBUTE objectClass" -ErrorVariable ldapUserLookupError -ErrorAction SilentlyContinue) 2>&1
        }

        if(-not($?)) {
            $ldapErrorMessage = "Error retrieving user from LDAP!"
            Write-Log "$ldapErrorMessage Error: $ldapUserLookupError" -OutputToConsole
            New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($ldapUserLookupError | Out-String)
        }
        elseif (-not($rawUser)) {
            $ldapErrorMessage = "Error retrieving user from LDAP!"
            Write-Log "$ldapErrorMessage Error: No user returned!" -OutputToConsole
            New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail "User not found: $ldapUser"
        }

        if($useADModule) {
            $objectClass = $rawUser.objectClass
            if($objectClass -contains $USER_CLASS) {
                $phoneNumber = $null
                $object = New-Object -TypeName PSObject
                $object | Add-Member -MemberType NoteProperty -Name dn -Value $rawUser.DistinguishedName
                $object | Add-Member -MemberType NoteProperty -Name sn -Value $rawUser.sn
                $object | Add-Member -MemberType NoteProperty -Name givenName -Value $rawUser.givenName
                $object | Add-Member -MemberType NoteProperty -Name email -Value $rawUser.mail
                $object | Add-Member -MemberType NoteProperty -Name $PRINCIPAL_UID_ATTRIBUTE -Value $rawUser.$PRINCIPAL_UID_ATTRIBUTE.Value
                $phoneNumber = $rawUser.telephoneNumber
                if (($phoneNumber -eq $null) -or ($phoneNumber.length -eq 0) -or ($phoneNumber -notmatch '^[\.()\s\d+-]+$')) {
                    $phoneNumber = $DEFAULT_PHONE_NUMBER
                }
                $object | Add-Member -MemberType NoteProperty -Name telephoneNumber -Value $phoneNumber
                $ldapUsers += $object
            }
            else {
                Write-Log -Message "Object: $ldapUser is not of objectClass $USER_CLASS! objectClass(es): $($objectClass -join ', ')" -OutputToConsole
            }
        }
        else {
            $rawUser = $rawUser | ForEach-Object {$_.TrimEnd()} | Where-Object {$_ -ne ""} #Remove empty lines
            $rawUser = $rawUser | Where-Object {$_ -notmatch "# ref"} #Needed for Active Directory
            $rawUser = $rawUser -join "`n" -split '(?ms)(?=^dn:)' -match '^dn:' #Split into separate objects
            $objectClass = $($rawUser -split '\n' -match '^objectClass:' -replace 'objectClass:\s','')
            if($objectClass -contains $USER_CLASS) {
                $phoneNumber = $null
                $object = New-Object -TypeName PSObject
                $object | Add-Member -MemberType NoteProperty -Name dn -Value $($rawUser -split '\n' -match '^dn:' -replace 'dn:\s','')
                $object | Add-Member -MemberType NoteProperty -Name sn -Value $($rawUser -split '\n' -match '^sn:' -replace 'sn:\s','')
                $object | Add-Member -MemberType NoteProperty -Name givenName -Value $($rawUser -split '\n' -match '^givenName:' -replace 'givenName:\s','')
                $object | Add-Member -MemberType NoteProperty -Name email -Value $($rawUser -split '\n' -match '^mail:' -replace 'mail:\s','')
                $object | Add-Member -MemberType NoteProperty -Name $PRINCIPAL_UID_ATTRIBUTE -Value $($rawUser -split '\n' -match "^$([regex]::Escape($PRINCIPAL_UID_ATTRIBUTE)):" -replace "$([regex]::Escape($PRINCIPAL_UID_ATTRIBUTE)):\s",'')
                $phoneNumber = $($rawUser -split '\n' -match '^telephoneNumber:' -replace 'telephoneNumber:\s','')
                if (($phoneNumber -eq $null) -or ($phoneNumber.length -eq 0) -or ($phoneNumber -notmatch '^[\.()\s\d+-]+$')) {
                    $phoneNumber = $DEFAULT_PHONE_NUMBER
                }
                $object | Add-Member -MemberType NoteProperty -Name telephoneNumber -Value $phoneNumber
                $ldapUsers += $object
            }
            else {
                Write-Log -Message "Object: $ldapUser is not of objectClass $USER_CLASS! objectClass(es): $($objectClass -join ', ')" -OutputToConsole
            }
        }
    }
    catch {
        $ldapErrorMessage = "Error retrieving user from LDAP!"
        Write-Log "$ldapErrorMessage Error: $($_)" -OutputToConsole
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: $ldapErrorMessage" -Detail ($_ | Out-String)
    }
}
Write-Log -Message "$($ldapUsers.Count) LDAP User(s) found." -OutputToConsole

## RightScale Governance
# Get RightScale users
Write-Log -Message "Getting All RightScale Users... " -OutputToConsole
$rsGRSUsers = Invoke-RestMethod -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/users" -Method Get -Headers $grsHeader -ContentType $contentType
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
        if($newRSUserResult -ne $false) {
            $newUsersCreated += $newRSUserResult
            # Update RS GRS User list to include the necessary details for the new user
            $rsGRSUsers += $newRSUserResult
        }
        else {
            $newUsersNotCreated += $ldapUser
        }
    }

    # Create audit entry for users created and not created
    $usersCreatedDetails = "Users created successfully:$($newUsersCreated | Format-List | Out-String)"
    $usersCreatedDetails += "Users NOT created successfully:$($newUsersNotCreated | Format-List | Out-String)"
    New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: User(s) Created" -Detail $usersCreatedDetails
}
else {
    Write-Log -Message "No new users to create." -OutputToConsole
}

if($newUsersCreated.count -gt 0) {
    Write-Log -Message "New user(s) created: $($newUsersCreated.count)" -OutputToConsole
    # Sleep to allow for replication
    $sleepSeconds = 60
    Write-Log -Message "Sleeping $sleepSeconds seconds to allow for replication..." -OutputToConsole
    Start-Sleep -Seconds $sleepSeconds
}

# Get RightScale groups
Write-Log -Message "Getting All RightScale Groups..." -OutputToConsole
$rsGRSGroups = Invoke-RestMethod -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/groups" -Method Get -Headers $grsHeader -ContentType $contentType
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
    $prunedMembers = @()
    $group = $null
    $group = $rsGRSGroups | Where-Object { $_.name -eq $ldapGroup.cn }
    if ($group -ne $null) {
        $userPayload = @()
        $group_name = $ldapGroup.cn
        $group_id = $group.id
        Write-Log -Message "Group: $group_name (RS ID: $group_id)" -OutputToConsole
        if($ldapGroup.members.count -gt 0) {
            $prunedMembers = Compare-Object -ReferenceObject $ldapgroup.members -DifferenceObject $ldapUsers.dn -IncludeEqual -ExcludeDifferent | Select-Object -ExpandProperty InputObject
            foreach ($member in $prunedMembers) {
                $user_id = $null
                $user_email = $null
                $user_email = $ldapUsers | Where-Object { $_.dn -eq $member } | Select-Object -ExpandProperty email
                $user_id = $rsGRSUsers | Where-Object { $_.email -eq $user_email } | Select-Object -ExpandProperty id
                if($user_id -eq $null) {
                    Write-Log -Message "* Error retrieving RightScale ID for $member. Skipping..." -OutputToConsole
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
        Write-Log -Message "The group '$($ldapGroup.cn)' does not exist! Please create it first!" -OutputToConsole
    }
}

# Remove User affiliation from org for users that are no longer members of LDAP groups
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
        $usersDeletedDetails = "Users removed successfully:$($usersDeleted | Format-List | Out-String)"
        $usersDeletedDetails += "Users NOT removed successfully:$($usersNotDeleted | Format-List | Out-String)"
        New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: User(s) Removed" -Detail $usersDeletedDetails
    }
    else {
        Write-Log -Message "In order to remove users, set the 'PURGE_USERS' parameter to 'true'" -OutputToConsole
    }
}   
else {
    Write-Log -Message "No users to remove." -OutputToConsole
}

# We're done!
Write-Log -Message "Group Sync Complete!" -OutputToConsole
New-RSAuditEntry -RSHost $RS_HOST -AccessToken $accessToken -Auditee $auditeeHref -Summary "RS Group Sync: Complete" -Detail (Get-Content -Path $logFilePath | Out-String)
