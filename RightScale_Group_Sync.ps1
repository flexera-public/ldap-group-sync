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
#     Description: "FQDN of the Directory Service."
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
# ...

# Present parameters to allow script be used outside of a RightScript
param(
    $COMPANY_NAME = $ENV:COMPANY_NAME, # Used when creating a new user in RightScale
    $CM_SSO_ACCOUNT = $ENV:CM_SSO_ACCOUNT, # The account number the SSO IdP is configured under
    $GRS_ACCOUNT = $ENV:GRS_ACCOUNT, # The account number for the RightScale Organization
    $RS_HOST = $ENV:RS_HOST, # RightScale host. Example: us-3.rightscale.com or us-4.rightscale.com
    $REFRESH_TOKEN = $ENV:REFRESH_TOKEN, # Refresh token for a RightScale user account that has the Enterprise Manager role
    $IDP_HREF = $ENV:IDP_HREF, # The href of the IdP associated with the users of the Groups. Example: /api/identity_providers/123
    $LDAP_HOST = $ENV:LDAP_HOST, # FQDN of the Directory Service
    $LDAP_USER = $ENV:LDAP_USER, # User that has read access to the Directory Service. Example: cn=Directory Manager
    $LDAP_USER_PASSWORD = $ENV:LDAP_USER_PASSWORD, # Password for the LDAP user
    $BASE_DN = $ENV:BASE_DN, # The base dn of the Directory Service. Example: DC=some,DC=domain
    $GROUP_CLASS = $ENV:GROUP_CLASS, # The Directory Services Object Class for groups of users. Example: groupOfNames
    $USER_CLASS = $ENV:USER_CLASS, # The Directory Services Object Class for users. Example: person
    $GROUP_SEARCH_STRING = $ENV:GROUP_SEARCH_STRING, # LDAP search string to use to filter groups to sync. Wildcard must be added if required. Example: RightScaleGroup*
    $LIST_OF_GROUPS = $ENV:LIST_OF_GROUPS, # Comma seperated list of Groups to sync. Example: RightScale_Admins,RightScale_Observers
    $PRINCIPAL_UID_ATTRIBUTE = $ENV:PRINCIPAL_UID_ATTRIBUTE, # The name of the LDAP attribute to use for the RightScale principal_uid
    $EMAIL_DOMAIN = $ENV:EMAIL_DOMAIN
)

$errorActionPreference = 'stop'

$currentTime = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-Date)).Ticks
$logFilePath = Join-Path "/tmp" "rs_groupsync_$currentTime.log"

function Write-Log ($Message,[switch]$OutputToConsole) {
    if(-not(Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType "File"
    }
    
    $currentTime = (New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End (Get-Date)).Ticks 
    $logMessage = "[" + $currentTime + "] " + $Message
    $logMessage | Out-File -FilePath $logFilePath -Append -Encoding "UTF8"

    if($console) {
        Write-Host $logMessage
    }
}

## LDAP directory

# Determine if using list or search string and get the groups
if (($GROUP_SEARCH_STRING -ne $null) -and ($LIST_OF_GROUPS -ne $null)) {
    Write-Log -Message "GROUP_SEARCH_STRING and LIST_OF_GROUPS cannot be used together. Please specify one and leave the other blank" -OutputToConsole
}
elseif ($GROUP_SEARCH_STRING -ne $null) {
    Write-Log -Message "Getting all LDAP groups matching '$GROUP_SEARCH_STRING'..." -OutputToConsole
    $rawGroups = ldapsearch -LLL -x -h $LDAP_HOST -D $LDAP_USER -w $LDAP_USER_PASSWORD -b $BASE_DN "(&(objectClass=$GROUP_CLASS)(cn=$GROUP_SEARCH_STRING))" dn cn member
}
elseif ($LIST_OF_GROUPS -ne $null) {
    $groupsToFilter = $null
    foreach ($group in $LIST_OF_GROUPS.Split(',')) {
        $groupsToFilter += "(cn=$group)"
    }
    $groupsFilter = "(&(objectClass=$ENV:GROUP_CLASS)(|$groupsToFilter))"
    Write-Log -Message "Getting any groups matching '$LIST_OF_GROUPS'..." -OutputToConsole
    $rawGroups = ldapsearch -LLL -x -h $LDAP_HOST -D $LDAP_USER -w $LDAP_USER_PASSWORD -b $BASE_DN $groupsFilter dn cn member
}
else {
    Write-Log -Message "A 'GROUP_SEARCH_STRING' or 'LIST_OF_GROUPS' must be specified!" -OutputToConsole
    EXIT 1
}

$rawgroups = $rawGroups | ForEach-Object {$_.TrimEnd()} | Where-Object {$_ -ne ""} #Remove empty lines
$rawGroups = $rawGroups | Where-Object {$_ -notmatch "# ref"} #Needed for Active Directory
$rawGroups = $rawGroups -join "`n" -split '(?ms)(?=^dn:)' -match '^dn:' #Split into seperate objects

# Create groups object
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

# Build user ldap filter
# Potentially expensive query, alternative is to do a single search per user dn, 
# or get all LDAP users and do a client side filter
$groupsToFilter = $null
foreach ($group in $ldapGroups.dn) {
    $groupsToFilter += "(isMemberOf=$group)"
}
$userFilter = "(&(objectClass=$USER_CLASS)(|$groupsToFilter))"

# Get the users
Write-Log -Message "Getting all members of LDAP filtered groups..." -OutputToConsole
$rawUsers = & ldapsearch -LLL -x -h $LDAP_HOST -D $LDAP_USER -w $LDAP_USER_PASSWORD -b $BASE_DN $userFilter sn givenName mail telephoneNumber $PRINCIPAL_UID_ATTRIBUTE
$rawUsers = $rawUsers | ForEach-Object {$_.TrimEnd()} | Where-Object {$_ -ne ""} #Remove empty lines
$rawUsers = $rawUsers | Where-Object {$_ -notmatch "# ref"} #Needed for Active Directory
$rawUsers = $rawUsers -join "`n" -split '(?ms)(?=^dn:)' -match '^dn:' #Split into seperate objects

# Create users object
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
    Write-Log -Message "Error with retreiving access token! Exiting..." -OutputToConsole
    EXIT 1
}

# Use access token as bearer for additional CM calls
$cmHeader = @{
    "X_API_VERSION"="1.5";
    "Authorization"="Bearer $accessToken"
}

# Use access token as bearer for GRS api calls
$grsHeader = @{
    "X-API-Version"="2.0";
    "Authorization"="Bearer: $accessToken"
}

$auditeeHref = "/api/accounts/" + $CM_SSO_ACCOUNT

# Create audit entry to denote group sync starting
$auditEntryBodyPayload = @{
    "audit_entry" = @{
        "auditee_href" = $auditeeHref
        "summary" = "RS Group Sync: Starting"
    }
} | ConvertTo-Json

$auditEntryResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/api/audit_entries" -Method Post -Headers $cmHeader -ContentType $contentType -Body $auditEntryBodyPayload

if($auditEntryResult.StatusCode -ne "201") {
    Write-Log -Message "Error creating Audit Entry for Group Sync start! Status Code: $($auditEntryResult.StatusCode)" -OutputToConsole
}

# Get RightScale users
Write-Log -Message "Getting All RightScale Users... " -OutputToConsole
$rsGRSUsers = Invoke-RestMethod -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/users" -Method Get -Headers $grsHeader -ContentType $contentType
$initialRSGRSUsersCount = $rsGRSUsers.Count
Write-Log -Message "$initialRSGRSUsersCount RightScale User(s) found." -OutputToConsole

# Determine if users need to be created or deleted
$usersToModify = Compare-Object -ReferenceObject $ldapUsers -DifferenceObject $rsGRSUsers -Property email
$usersToCreate = $usersToModify | Where-Object { $_.SideIndicator -eq "<=" } | Select-Object -ExpandProperty InputObject
$usersToDelete = $usersToModify | Where-Object { $_.SideIndicator -eq "=>" } | Where-Object { $_.InputObject -like "*$EMAIL_DOMAIN"} | Select-Object -ExpandProperty InputObject

# Create new users
$newUsersCreated = @()
$newUsersNotCreated = @()
if($usersToCreate.count -gt 0){
    Write-Log -Message "$($usersToCreate.count) new user(s) to create..." -OutputToConsole
    foreach($user in $usersToCreate) {
        # Create New User and Set identity_provider, principal_uid, first_name, last_name, email, company and phone
        $ldapUser = $ldapUsers | Where-Object {$_.email -eq $user}
        Write-Log -Message "Creating new user $($ldapUser.email)..." -OutputToConsole

        $newUserBodyPayload = @{
            "user" = @{
                "first_name" = $($ldapUser.givenName)
                "last_name" = $($ldapUser.sn)
                "company" = $COMPANY_NAME
                "email" = $($ldapUser.email)
                "phone" = $($ldapUser.telephoneNumber)
                "identity_provider_href" = $IDP_HREF
                "principal_uid" = $($ldapUser.$PRINCIPAL_UID_ATTRIBUTE)
            }
        } | ConvertTo-Json
        
        $newUserResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/api/users" -Method Post -Headers $cmHeader -ContentType $contentType -Body $newUserBodyPayload
        
        if($newUserResult.StatusCode -eq "204") {
            $newUserHref = $null
            $newUserHref = $newUserResult.Headers.Get_Item('Location')
            Write-Log -Message "Successfully created $($ldapUser.email)! Href: $newUserHref" -OutputToConsole
            #$newUsersCreated += "$user ($newUserHref)"
            $newUsersCreated += $newUserBodyPayload
            $newUserId = $newUserHref | Split-Path -Leaf
        }
        else {
            Write-Log -Message "Error creating $($ldapUser.email)! Status Code: $($newUserResult.StatusCode)" -OutputToConsole
            $newUsersNotCreated += $ldapUser
        }
        <#
        #Affiliate with the org
        $newUserAffiliationBodyPayload = @{
            "id" = $newUserId
            "href" = "/grs/users/$newUserId"
            "kind" = "user"
        } | ConvertTo-Json
        $newUserAffiliationResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/users" -Method Post -Headers $grsHeader -ContentType $contentType -Body $newUserAffiliationBodyPayload
        #>
    }
    # Audit entry for users created and not created
    $usersCreatedDetails = "Users created successfully:" + "`n " + ($newUsersCreated | ForEach-Object { $_ + "`n" }) + "`n"
    if($newUsersNotCreated.Count -gt 0) {
        $usersCreatedDetails += "Users NOT created successfully:" + "`n " + ($newUsersNotCreated | ForEach-Object { $_ + "`n" }) + "`n"
    }
    
    $auditEntryBodyPayload = @{
        "audit_entry" = @{
            "auditee_href" = $auditeeHref
            "detail" = $usersCreatedDetails
            "summary" = "RS Group Sync: User(s) Created"
        }
    } | ConvertTo-Json
    
    $auditEntryResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/api/audit_entries" -Method Post -Headers $cmHeader -ContentType $contentType -Body $auditEntryBodyPayload
    
    if($auditEntryResult.StatusCode -ne "201") {
        Write-Log -Message "Error creating Audit Entry with user creation details! Status Code: $($auditEntryResult.StatusCode)" -OutputToConsole
    }
}
else {
    Write-Log -Message "No new users to create." -OutputToConsole
}

if($newUsersCreated.count -gt 0) {
    Write-Log -Message "New user(s) created: $($newUsersCreated.count)" -OutputToConsole
    # Sleep to allow for replication
    Start-Sleep -Seconds 60
    # Get Users again to account for newly added users
    Write-Log -Message "Getting All RightScale Users..." -OutputToConsole
    $rsGRSUsers = Invoke-RestMethod -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/users" -Method Get -Headers $grsHeader -ContentType $contentType
    Write-Log -Message "$($rsGRSUsers.Count) RightScale User(s) found." -OutputToConsole
}

# Get RightScale groups
Write-Log -Message "Getting All RightScale Groups..." -OutputToConsole
$rsGRSGroups = Invoke-RestMethod -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/groups" -Method Get -Headers $grsHeader -ContentType $contentType
Write-Log -Message "$($rsGRSGroups.Count) Group(s) found." -OutputToConsole

# Desired Memberships : Combine LDAP and GRS lists to capture RS User ID and RS Group ID
$desiredMemberships = @()
foreach ($ldapGroup in $ldapGroups) {
    $group = $null
    $group = $rsGRSGroups | Where-Object { $_.name -eq $ldapGroup.cn }
    if ($group -ne $null) {
        Write-Log -Message "Group: $($ldapGroup.cn) (RS ID: $($group.id))" -OutputToConsole
        foreach ($member in $ldapGroup.members) {
            $user_id = $null
            $user_email = $null
            $user_email = $ldapUsers | Where-Object { $_.dn -eq $member } | Select-Object -ExpandProperty email
            $user_id = $rsGRSUsers | Where-Object { $_.email -eq $user_email } | Select-Object -ExpandProperty id
            if($user_id -eq $null) {
                Write-Log -Message "Error retrieving $user_email RightScale ID. Skipping..." -OutputToConsole
            }
            else {
                $object = New-Object -TypeName PSObject
                $object | Add-Member -MemberType NoteProperty -Name user_id -Value $user_id
                $object | Add-Member -MemberType NoteProperty -Name user_mail -Value $user_email
                $object | Add-Member -MemberType NoteProperty -Name group_id -Value $group.id
                $object | Add-Member -MemberType NoteProperty -Name group_name -Value $ldapGroup.cn
                $desiredMemberships += $object
                Write-Log -Message "*Member: $user_email (RS ID: $user_id)" -OutputToConsole
            }
        }
    }
    else {
        Write-Log -Message "$($ldapGroup.cn) does not exist! Please create it first!" -OutputToConsole
    }
}

# Update Group memberships - "replace"
# Replaces the Users in a Group. If an empty list of Users is passed in the request, then all the Users are removed from the Group given in the request.
$groups = $desiredMemberships | Select-Object -ExpandProperty group_id -Unique
foreach ($group in $groups) {
    $userPayload = @()
    $memberships = $desiredMemberships | Where-Object { $_.group_id -eq $group }
    if($memberships.count -gt 0) {
        $groupName = $memberships | Select-Object -First 1 -ExpandProperty group_name
        foreach ($membership in $memberships) {
            $user_id = $($membership.user_id)
            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name id -Value $user_id
            $object | Add-Member -MemberType NoteProperty -Name href -Value "/grs/users/$user_id"
            $object | Add-Member -MemberType NoteProperty -Name kind -Value "user"
            $userPayload += $object
        }
    }
    
    Write-Log -Message "Updating '$groupName' membership..." -OutputToConsole

    $membershipBodyPayload = @{
        "group" = @{
            "id" = $group
            "href" = "/grs/orgs/$GRS_ACCOUNT/groups/$group"
            "kind" = "group"
        }
        "users" = @(
            $userPayload
        )
    } | ConvertTo-Json
    
    $membershipResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/memberships" -Method Put -Headers $grsHeader -ContentType $contentType -Body $membershipBodyPayload
    
    if($membershipResult.StatusCode -eq "204") {
        Write-Log -Message "Successfully updated '$groupName' membership!" -OutputToConsole
    }
    else {
        Write-Log -Message "Error updating '$groupName' membership!" -OutputToConsole
    }
}

# Remove User Associations for users that no longer have access
# Users must not be a member of any groups, so we do this last
$usersDeleted = @()
$usersNotDeleted = @()
if($usersToDelete.count -gt 0){
    Write-Log -Message "$($usersToDelete.count) users to remove..." -OutputToConsole
    foreach($user in $usersToDelete) {
        $rsGRSUser = $rsGRSUsers | Where-Object { $_.email -eq $user}
        Write-Log -Message "Removing $($rsGRSUser.email) affiliation with organization... " -OutputToConsole
        
        $deleteResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/grs/orgs/$GRS_ACCOUNT/users/$user_id" -Method Delete -Headers $grsHeader -ContentType $contentType

        if ($deleteResult.StatusCode -eq 204) {
            Write-Log -Message "Successfully removed $($rsGRSUser.email) affiliation!" -OutputToConsole
            $usersDeleted += $rsGRSUser
        }
        else {
            Write-Log -Message "Error removing $($rsGRSUser.email) affiliation!" -OutputToConsole
            $usersNotDeleted += $rsGRSUser
        }
    }

    # Create audit entry for users removed and not removed
    $usersDeletedDetails = "Users removed successfully:" + "`n " + ($usersDeleted | ForEach-Object { $_ + "`n" }) + "`n"
    if($usersNotDeleted.Count -gt 0) {
        $usersDeletedDetails += "Users NOT removed successfully:" + "`n " + ($usersNotDeleted | ForEach-Object { $_ + "`n" }) + "`n"
    }
    
    $auditEntryBodyPayload = @{
        "audit_entry" = @{
            "auditee_href" = $auditeeHref
            "detail" = $usersDeletedDetails
            "summary" = "RS Group Sync: User(s) Removed"
        }
    } | ConvertTo-Json
    
    $auditEntryResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/api/audit_entries" -Method Post -Headers $cmHeader -ContentType $contentType -Body $auditEntryBodyPayload
    
    if($auditEntryResult.StatusCode -ne "201") {
        Write-Log -Message "Error creating Audit Entry with user removal details! Status Code: $($auditEntryResult.StatusCode)" -OutputToConsole
    }
}
else {
    Write-Log -Message "No users to remove." -OutputToConsole
}

# Create audit entry to denote group sync complete
$auditEntryBodyPayload = @{
    "audit_entry" = @{
        "auditee_href" = $auditeeHref
        "details" = Get-Content -Path $logFilePath
        "summary" = "RS Group Sync: Complete"
    }
} | ConvertTo-Json

$auditEntryResult = Invoke-WebRequest -UseBasicParsing -Uri "https://$RS_HOST/api/audit_entries" -Method Post -Headers $cmHeader -ContentType $contentType -Body $auditEntryBodyPayload

if($auditEntryResult.StatusCode -ne "201") {
    Write-Log -Message "Error creating Audit Entry for Group Sync start! Status Code: $($auditEntryResult.StatusCode)" -OutputToConsole
}