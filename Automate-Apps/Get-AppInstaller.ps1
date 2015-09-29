param (
	$dplyTlktPS 	= "deploytoolkit.ps1"													
	$srcTlkt		= 'https://mrp-us-bucket.s3.amazonaws.com/toolkit/DeployToolKit.ps1'
	$srcManifest	= 'https://mrp-us-bucket.s3.amazonaws.com/toolkit/manifest.xml'
)

set-executionpolicy -executionpolicy unrestricted

$destFolder 	= "c:\RSTools\DeployToolKit"
$destTlkt	= "$destFolder" + "\" + "deploytoolkit.ps1"
$destManifest	= "$destFolder" + "\" + "manifest.xml"

if(!(test-path $destFolder)){New-Item -Path $destFolder -ItemType directory}

$wc = New-Object system.Net.WebClient

try
{
		write-host "DEPLOYTOOLKIT`: Downloading script - $srcTlkt"
		$wc.downloadfile($srcTlkt,$destTlkt)
}
catch [System.Net.WebException]
{
		if($_.Exception.InnerException)
		{
			Write-Host "DPLYTOOLKIT`: Error downloading source - $($_.exception.innerexception.message)"
		}
		else
		{
			Write-Host "DPLYTOOLKIT`: Error downloading source - $_"
		}
	
}


try
{
	write-host "DEPLOYTOOLKIT`: Downloading manifest - $srcManifest"	
	$wc.downloadfile($srcManifest,$destManifest)
}
catch [System.Net.WebException]
{
		if($_.Exception.InnerException)
		{
			Write-Host "DPLYTOOLKIT`: Error downloading source - $($_.exception.innerexception.message)"
		}
		else
		{
			Write-Host "DPLYTOOLKIT`: Error downloading source - $_"
		}
	
}

set-location $destFolder

. $destTlkt
