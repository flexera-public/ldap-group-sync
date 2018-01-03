# Looks for the "[DD-MMM-YYYY HH:MM:SS +Z] Group Sync Complete!" line in the group sync log file and uses it as the basis for the monitor gauge.
# Therefore the gauge will report on the time in minutes since the last successful group sync.
# You would then create an alert based on the gauge and the interval you have Group Sync running on to alert you if there is an issue.

$logFilePath = '/tmp/rightscale_group_sync.log'

while ($True) {
    $currentDate = Get-Date
    $nowT = [Math]::Floor([decimal](Get-Date -Date ($currentDate).ToUniversalTime() -UFormat "%s"))
    $value = 'NaN' # Need to define the default value for the gauge if there is an error.

    if(Test-Path -Path $logFilePath) {
        $logFileContents = Get-Content -Path $logFilePath
        $success = $false
    
        foreach ($line in $logFileContents) {
            if($line -match "^\[(.*)\] Group Sync Complete!$") {
                $success = $true
                BREAK
            }
        }

        if(($success -eq $true) -and $matches[1]) {
            $logSuccessDate = [DateTime]$matches[1]
            $timeSpan = New-TimeSpan -Start $logSuccessDate -End $currentDate
            $value = [System.Math]::Round($timeSpan.TotalMinutes, 2)
        }
        else {
            $logFileDetails = Get-Item -Path $logFilePath
            $lastWriteTimeSpan = New-TimeSpan -End $currentDate -Start $logFileDetails.LastWriteTime
            if($lastWriteTimeSpan.TotalSeconds -lt $Env:COLLECTD_INTERVAL) {
                $value = 0 # 0 Means the script is currently running
            }
        }
    }

    Write-Host "PUTVAL $Env:COLLECTD_HOSTNAME/GroupSync/gauge-last_sync_in_minutes interval=$Env:COLLECTD_INTERVAL ${nowT}:${value}"

    Sleep $Env:COLLECTD_INTERVAL
}