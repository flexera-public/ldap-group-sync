#Create-SMBShare.ps1
$ShareName	= $ENV:NEW_SHARE_NAME
$DriveLetter	= $ENV:NEW_DATA_VOLUME
$Description	= $ENV:NEW_SHARE_DESCRIPTION

$SharePath = "{0}:\{1}" -f $DriveLetter,$ShareName

Write-Host "CREATE_SMB_SHARE:  Creating $ShareName at $SharePath"

if (!(Test-Path $SharePath)) {
	Write-Host "CREATE_SMB_SHARE:  $SharePath does not exist.  Creating."
	$IsCreated = New-Item $SharePath -ItemType Directory -Force
	if ($IsCreated) { Write-Host "CREATE_SMB_SHARE:  $SharePath created successfully." }
	else { Write-Host "CREATE_SMB_SHARE:  $SharePath was not able to be created.  Exiting." ; Exit }

	$IsCreated = $NULL
}

$IsShared = Get-SMBShare | ? { $_.Name -match $ShareName }
if ($IsShared) {
	Write-Host "CREATE_SMB_SHARE:  $ShareName already exists.  No work to do."
} else {
	Write-Host "CREATE_SMB_SHARE:  Creating \\$($ENV:COMPUTERNAME)\$ShareName."
	$IsCreated = New-SmbShare -Name $ShareName -Path $SharePath -Description $Description -FullAccess "Everyone"
	if ($IsCreated) {
		Write-Host "CREATE_SMB_SHARE:  \\$($ENV:COMPUTERNAME)\$ShareName created successfully.  Writing Tags."
		
		$CompSys	= GWMI Win32_ComputerSystem
		$FQDN		= "{0}.{1}" -f $CompSys.Name,$CompSys.Domain

		$Tag	= "rs_smb:server={0}" -f $FQDN.ToLower()
		rs_tag --add $Tag
		
		$Tag	= "rs_smb:share={0}" -f $ShareName
		rs_tag --add $Tag
		
	}
	else { Write-Host "CREATE_SMB_SHARE:  \\$($ENV:COMPUTERNAME)\$ShareName was not created." }
}
