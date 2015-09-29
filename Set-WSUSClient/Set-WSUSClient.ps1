# Powershell 2.0
# Copyright (c) 2008-2012 RightScale, Inc, All Rights Reserved Worldwide.

#Variables for Registry
$WSUSPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\'
$WSUSFolder = "WindowsUpdate"
$AutoUpdateFolder = "AU"
$Type = "Directory"

#Inputs for Registry
$ClientGroup = $env:WSUS_GROUP_NAME
$WSUSServer = $env:WSUS_SERVER_ADDRESS
$AUOptions = $env:AUTO_UPDATE_OPTIONS
$SchedInstDay = $env:DAY_TO_UPDATE
$SchedInstTime = $env:TIME_TO_UPDATE


if(!( Test-Path $WSUSPath\$WSUSFolder)){New-Item -Path $WSUSPath -Name $WSUSFolder -Type $Type}
New-ItemProperty -Path $WSUSPath\$WSUSFolder -Name "AcceptTrustedPublisherCerts" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder -Name "ElevateNonAdmins" -PropertyType "dword" -Value '00000001'


#Input for what group to put the server in
New-ItemProperty -Path $WSUSPath\$WSUSFolder -Name "TargetGroup" -PropertyType "String" -Value $ClientGroup
New-ItemProperty -Path $WSUSPath\$WSUSFolder -Name "TargetGroupEnabled" -PropertyType "dword" -Value '00000001'


#Input for the WSUS server
New-ItemProperty -Path $WSUSPath\$WSUSFolder -Name "WUServer" -PropertyType "String" -Value $WSUSServer
New-ItemProperty -Path $WSUSPath\$WSUSFolder -Name "WUStatusServer" -PropertyType "String" -Value $WSUSServer

New-Item -Path $WSUSPath\$WSUSFolder -Name $AutoUpdateFolder -Type $Type

#Input for the AUOptions
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "AUOptions" -PropertyType "dword" -Value $AUOptions


New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "AUPowerManagement" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "AutoInstallMinorUpdates" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "DetectionFrequency" -PropertyType "dword" -Value '10'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "DetectionFrequencyEnabled" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "IncludeRecommendedUpdates" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "NoAUAsDefaultShutdownOption" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "NoAUShutdownOption" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "NoAutoRebootWithLoggedOnUsers" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "NoAutoUpdate" -PropertyType "dword" -Value '00000000'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "RebootRelaunchTimeout" -PropertyType "dword" -Value '10'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "RebootRelaunchTimeoutEnabled" -PropertyType "dword" -Value '00000001'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "RescheduleWaitTime" -PropertyType "dword" -Value '10'
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "RescheduleWaitTimeEnabled" -PropertyType "dword" -Value '00000001'


New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "ScheduledInstallDay" -PropertyType "dword" -Value $SchedInstDay
New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "ScheduledInstallTime" -PropertyType "dword" -Value $SchedInstTime


New-ItemProperty -Path $WSUSPath\$WSUSFolder\$AutoUpdateFolder -Name "UseWUServer" -PropertyType "dword" -Value '00000001'