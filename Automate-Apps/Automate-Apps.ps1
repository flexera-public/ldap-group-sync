param (
	[string]$bucket			= $env:BUCKET,									# DEFAULT:  "https://s3.amazonaws.com/JesB-East"								: S3 Bucket with install & config files
	[string]$logFile		= $env:LOG_FILE,								# DEFAULT:  "C:\RSTools\Automate-Appkits\Automate-AppKits.log"					: Log folder location for this script
	[string]$manifest		= $env:MANIFEST,								# DEFAULT:  "manifest.xml"														: XML file with install & config content
	[string]$tempFolder		= $env:TEMP_FOLDER,								# DEFAULT:  "C:\RSTools\Automate-AppKits"										: Temp location to dowload files into
	
	[string]$rs_datacenter				= $env:DATACENTER,					# RightScale Datacenter in which the server is running (EC2 availability zone) 	: Default & Hidden in RightScript
	[string]$rs_deployment_name			= $env:RS_DEPLOYMENT_NAME,			# RightScale Deployment Name as displayed in the dashboard 						: Default & Hidden in RightScript
	[string]$rs_eip						= $env:RS_EIP,						# RightScale Elastic IP address as issued by Amazon EC2 						: Default & Hidden in RightScript
	[string]$rs_instance_id				= $env:INSTANCE_ID,					# RightScale Instance ID 														: Default & Hidden in RightScript
	[string]$rs_instance_uuid			= $env:RS_INSTANCE_UUID,			# RightScale Universally-unique identifier for this server incarnation 			: Default & Hidden in RightScript
	[string]$rs_private_ip				= $env:PRIVATE_IP,					# RightScale Private IP 														: Default & Hidden in RightScript
	[string]$rs_public_ip				= $env:PUBLIC_IP,					# RightScale Public IP 															: Default & Hidden in RightScript
	[string]$rs_server					= $env:RS_SERVER,					# RightScale server name in my.rightscale.com 									: Default & Hidden in RightScript
	[string]$rs_server_name				= $env:RS_SERVER_NAME,				# RightScale Server Name as displayed in the dashboard 							: Default & Hidden in RightScript
	[string]$rs_server_template_name	= $env:RS_SERVER_TEMPLATE_NAME,		# RightScale Template Name as displayed in the dashboard 						: Default & Hidden in RightScript
	[string]$rs_sketchy					= $env:RS_SKETCHY,					# RightScale Sketchy server 													: Default & Hidden in RightScript
	[string]$rs_token					= $env:RS_TOKEN						# RightScale Token as 32 character alphanumeric string 							: Default & Hidden in RightScript
)

# == BEGIN FUNCTIONS == #

# == Outputs to both the console and a log file == #
function WriteLog {
	param (
		$text
	)
	$logText = "{0}: {1}" -f (Get-Date -Format "MM/dd/yyyy HH:mm:ss"),$text
	
	Write-Host $logText
	Write-Output $logText | Add-Content $logFile -Force
}

# == Writes data to the registry == #
function UpdateRegistry {
	param (
		$path,
		$keyname,
		$keytype,
		$value,
		$name
	)

	WriteLog "Starting registry action - $name"
	WriteLog "Registry Key path - $path"
	WriteLog "Registry Key name - $keyname"
	WriteLog "Registry Key type - $keytype"
	WriteLog "Registry Key value - $value"
	WriteLog "Setting registry $path,$name=$value"
	
	try { Set-ItemProperty -Path $path -Name $keyname -Value $value -Type $keytype }
	catch { WriteLog "Error setting registry $path - $_" }
	finally { WriteLog "Finished registry action - $name`n" }
}

# == Creates a new directory if it does not already exist == #
function CreateDirectory {
	param (
		[string]$path,
		[string]$name
	)
	if (!(Test-Path $path)) {

		WriteLog "Starting directory creation action - $name"
		WriteLog "Directory - $path"
		
		try { New-Item $path -ItemType Directory -ErrorAction Stop | Out-Null }
		catch { WriteLog "Error creating $path - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
		finally { WriteLog "Finished directory action - $path`n" }

		Start-Sleep -Milliseconds 500
	}
}

# == Downloads data from a given URL == #
function DownloadFile {
	param (
		[string]$source,
		[string]$destination,
		[string]$name
	)
	
	WriteLog "Starting download action - $name"
	WriteLog "Source - $source"
	WriteLog "Destination - $destination"

	$file = $source.Split("/")[-1]
	
	if ($destination.Length-1 -ne "\") { $destination = $destination + "\" + $file }
	else { $destination = $destination + $file }
	
	try {
		$netWebClient.downloadfile($source,$destination)
	}
	catch [System.Net.WebException] {
		if($_.Exception.InnerException) { WriteLog "Error downloading $source to $destination - $($_.exception.innerexception.message)" }
		else { WriteLog "Error downloading $source - $_" }
	}
	catch {
		 WriteLog "Error downloading $source to $destination - $_"
	}
	finally {
		 WriteLog "Finished downloaded action - $name`n"
	}
}

# == Copy a file == #
function CopyFile {
	param (
		[string]$source,
		[string]$destination,
		[string]$name
	)
	
	WriteLog "Starting copy action - $name"
	WriteLog "Source - $source"
	WriteLog "Destination -  $destination"
	
	try { Copy-Item -path $source -Destination $destination -Force }
	catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
	finally { WriteLog "Finished file copy action - $name`n" }
}

# == Install an application == #
function InstallApp {
	param (
		[string]$cmd,
		[string]$cmdArgs,
		[string]$name
	)
	WriteLog "Starting installation action - $name"
	WriteLog "Installer - $cmd"
	WriteLog "Arguements - $cmdArgs"

	try { Start-Process $cmd -ArgumentList $cmdArgs -Wait }
	catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
	finally { WriteLog "Finished installation action - $name`n" }
}

# == Stop/Start/Restart a service == #
function ManipulateService {
	param (
		[string]$service,
		[string]$command,
		[string]$name
	)
	WriteLog "Manipulate service action - $name"
	WriteLog "Service - $service"
	WriteLog "Command - $command"

	switch($command) {
		"stop" {
			try { Stop-Service -Name $service -Force | Out-Null }
			catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
			finally { WriteLog "Finished stoping service action - $name`n" }
		}
		"start" {
			try { Start-Service -Name $service -Force | Out-Null }
			catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
			finally { WriteLog "Finished starting service action - $name`n" }
		}
		"restart" {
			try { Restart-Service -Name $service -Force | Out-Null }
			catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
			finally { WriteLog "Finished restarting service action - $name`n" }
		}
	}
}

# == Execute a raw command line statement == #
function StartCommandline {
	param (
		[string]$path,
		[string]$file,
		[string]$cmdArgs,
		[string]$name,
		[string]$wrkFolder
	)

	WriteLog "Running command line action - $name"
	WriteLog "Path - $path"
	WriteLog "File - $file"
	WriteLog "Arguements - $cmdArgs"
	WriteLog "Working folder - $wrkFolder"

	$filePath = "{0}\{1}" -f $path, $file

	try { Start-Process -FilePath $filePath -ArgumentList $cmdArgs -WorkingDirectory -ErrorAction "Stop" }
	catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
	finally { WriteLog "Finished restarting service action - $name`n" }
	
}

# == Replace text in a given file == #
function ReplaceText {
	param (
		[string]$file,
		[string]$find,
		[string]$replace,
		[string]$name
	)

	WriteLog "Running find and replace action - $name"
	WriteLog "File - $file"
	WriteLog "Find - $find"
	WriteLog "Replace - $replace"

	try { (gc $file).Replace($find,$replace) }
	catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
	finally { WriteLog "Finished find and replace action - $name`n" }
}

# == Insert text at a given line in a given file == #
function InsertText {
	param (
		[string]$file,
		[string]$text,
		[string]$line,
		[string]$name
	)

	WriteLog "Running insert text action - $name"
	WriteLog "File - $file"
	WriteLog "Text - $text"
	WriteLog "Line - $line"

	$srcContent = gc $file
	$content = $srcContent[0..($line-1)] + $text + $srcContent[$line..($srcContent.Length)]
	
	try { $content | Set-Content $file -Force }
	catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
	finally { WriteLog "Finished insert text action - $name`n" }
}

# == Execute a PowerShell ScriptBlock == #
function ExecuteScriptBlock {
	param (
		[string]$block,
		[string]$name
	)

	WriteLog "Running scriptblock action - $name"
	WriteLog "Scriptblock - $($block.ToString())"

	try { &$executioncontext.invokecommand.NewScriptBlock($block) }
	catch { WriteLog "Error - $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
	finally { WriteLog "Finished scriptblock action - $name`n" }
}

# == END FUNCTIONS == #

$ErrorActionPreference = "Stop"	

# == Load necessary .Net classes == #
$netWebClient = New-Object System.Net.WebClient

# == Create the log file & temp folders == #
if (!(Test-Path $logFile)) { New-Item $logFile -ItemType File -Force | Out-Null }

CreateDirectory $tempFolder "manifest"

# == Echo all params from RightScript inputs == #
WriteLog "BUCKET:					$bucket"
WriteLog "LOGFILE:					$logFile"
WriteLog "MANIFEST:					$manifest"
WriteLog "TEMPFOLDER:				$tempFolder"	
WriteLog " "
WriteLog "RS_DATACENTER:			$rs_datacenter"		
WriteLog "RS_DEPLOYMENT_NAME:		$rs_deployment_name"			
WriteLog "RS_EIP:					$rs_eip"
WriteLog "RS_INSTANCE_ID:			$rs_instance_id"		
WriteLog "RS_INSTANCE_UUID:			$rs_instance_uuid"		
WriteLog "RS_PRIVATE_IP:			$rs_private_ip"		
WriteLog "RS_PUBLIC_IP:				$rs_public_ip"	
WriteLog "RS_SERVER:				$rs_server"	
WriteLog "RS_SERVER_NAME:			$rs_server_name"		
WriteLog "RS_SERVER_TEMPLATE_NAME:	$rs_server_template_name"				
WriteLog "RS_SKETCHY:				$rs_sketchy"	
WriteLog "RS_TOKEN:					$rs_token"

WriteLog "Beginning Actions`n"

# == Manifest download & load == #
$srcManifest = "{0}/{1}" -f $bucket,$manifest
$localManifest = "{0}\{1}" -f $tempFolder,$manifest

DownloadFile $srcManifest $tempFolder "manifest"

[xml]$xmlConfig = gc $localManifest

# == Begin parsing Manifest file == #
$xmlAppKits = $xmlConfig.APPKITS.APPKIT

foreach ($xmlAppKit in $xmlAppKits) {

	# == Load all top level XML info == #
	$xmlName		= $xmlAppKit.NAME
	$xmlSrcRepos	= $xmlAppKit.REPOSITORY
	$xmlTools		= $xmlAppKit.TOOLS
	$xmlTemp		= $xmlAppKit.TEMP
	$xmlDestination	= $xmlAppKit.DESTINATION
	
	$xmlSrcReposName		= $xmlSrcRepos.NAME
	$xmlSrcReposPath		= $xmlSrcRepos.PATH
	$xmlTempFolder			= $xmlTemp.PATH
	$xmlLocalDestination	= $xmlDestination.PATH	

	WriteLog "Starting action $xmlName"
	WriteLog "Repository - $xmlSrcReposName"
	WriteLog "Repository path - $xmlSrcReposPath"
	WriteLog "Local temp path - $xmlTempFolder`n"

	# == Creation of local Temp and Destination fodlers == #
	CreateDirectory $xmlTempFolder $xmlName
	CreateDirectory $xmlLocalDestination $xmlName

	# == Begin parsing individual tools == #
	foreach($xmlTool in $xmlTools.TOOL)
	{
		$srcFile	= $null
		$destFolder	= $null
		
		# == Load tool level XML data == #
		$xmlToolName		= $xmlTool.NAME
		$xmlToolVer			= $xmlTool.VER
		$xmlToolFilename	= $xmlTool.FILENAME
		$xmlToolAction		= $xmlTool.ACTION
		$xmlToolDownload	= $xmlTool.DOWNLOAD
		$xmlSrcFolder		= $xmlTool.REPOPATH
		$xmlSrcFileName		= $xmlTool.FILENAME
		
		WriteLog "Tool - $xmlToolName"
		WriteLog "Action - $xmlToolAction`n"
		
		# == Build source & destination file paths == #
		if ($xmlSrcFolder) { $srcFile = "{0}/{1}/{2}" -f $xmlSrcReposPath,$xmlSrcFolder,$xmlSrcFileName }
		else { $srcFile = "{0}/{1}" -f $xmlSrcReposPath,$xmlSrcFileName }
		if ($xmlSrcFolder) { $destFolder = "{0}\{1}" -f $xmlLocalDestination,$xmlSrcFolder }
		else { $destFolder = $xmlLocalDestination }
		
		$destFilePath = "{0}\{1}" -f $destFolder, $xmlSrcFileName
		
		# == Create download location & download files == #
		CreateDirectory $destFolder $xmlToolName
	
		if ($xmlToolDownload -eq "TRUE") { DownloadFile $srcFile $xmlTempFolder $xmlToolName }
			
		# == Begin processing actions == #
		switch($xmlToolAction) {
			
			# == Process installs ==#
			"install" {
				if (!(Test-Path "C:\RSTools")) { CreateDirectory "C:\RSTools" "RSToolsDir" }
				
				$srcType 		= $xmlSrcFileName.Split(".")[1]
				$installerPath	= "{0}\{1}" -f $xmlTempFolder, $xmlSrcFileName

				switch($srcType) {

					# == Process .exe files only == #
					"exe" {
						$cmdToRun 		= $installerPath
						$cmdSwitches	= $xmlTool.ARGS
						
						InstallApp $cmdToRun $cmdSwitches $xmlToolName
					}
					
					# == Process .msi files only == #
					"msi" {
						$cmdToRun		= "msiexec"
						$cmdSwitches	= "{0} /lv* C:\RSTools\{1}\{1}.log" -f $xmlTool.ARGS, $xmlToolName
						$cmdArgs		= "/i$installerPath $cmdSwitches"
						
						InstallApp $cmdToRun $cmdArgs $xmlToolName
					}
				}
			}

			# == Process filecopy ==#
			"filecopy" {
			
				# == Determines if the files to copy are in the Repo or local, then processes accordingly == #
				switch($xmlToolDownload) {
				
					# == From Repo == #
					"TRUE" {
						if ($xmlTool.DESTINATION) { $destFilePath = "{0}\{1}" -f $xmlTool.DESTINATION, $xmlToolFilename }
						
						$srcFile = "{0}\{1}" -f $xmlTempFolder, $xmlToolFilename
						
						CopyFile $srcFile $destFilePath $xmlToolName
					}
					
					# == Local only == #
					default {
						$xmlToolSource	=$xmlTool.SOURCE
						$xmlToolDest	= $xmlTool.DESTINATION
						
						$srcFile = "{0}\{1}" -f $xmlToolSource, $xmlToolFilename
						$dstFile = "{0}\{1}" -f $xmlToolDest, $xmlToolFilename
						
						CopyFile $srcFile $dstFile $xmlToolName
					}
				}
			}
			
			# == Registry path updates == #
	   		"registry" {
				$xmlRegKeyPath	= $xmlTool.PATH
				$xmlRegKeyName	= $xmlTool.KEYNAME
				$xmlRegKeyValue	= $xmlTool.VALUE
				$xmlRegKeyType	= $xmlTool.TYPE
					
				UpdateRegistry $xmlRegKeyPath $xmlRegKeyName $xmlRegKeyValue $xmlRegKeyType $xmlToolName
			}
			
			# == Raw comamnd line execution == #
			"commandline" {
				$xmlSrcFolder	= $xmlTool.PATH
				$xmlFilename	= $xmlTool.FILENAME
				$cmdSwitches	= $xmlTool.ARGS
								
				if ($xmlTool.WORKINGFOLDER) { $wrkFolder = $xmlTool.WORKINGFOLDER }

				StartCommandline $xmlSrcFolder $xmlFilename $cmdSwitches $xmlToolName $wrkFolder
			}
			
			# == Services stop/start/restart == #
			"service" {
				$xmlToolSrvc	= $xmlTool.SERVICE
				$xmlToolCmd		= $xmlTool.COMMAND
				
				ManipulateService $xmlToolSrvc $xmlToolCmd $xmlToolName
			}
			
			# == Replace text in a given text based file == #
			"replacetext" {
				$xmlToolFind	= $xmlTool.FIND
				$xmlToolReplace	= $xmlTool.REPLACE

				$xmlReplaceFile	= "{0}\{1}" -f $xmlTool.PATH, $xmlTool.FILENAME
				
				ReplaceText $xmlReplaceFile $xmlToolFind $xmlToolReplace $xmlToolName
			}
			
			# == Insert text at a specific line in a text based file == #
			"inserttext" {
				$xmlText = $xmlTool.TEXT
				$xmlLine = $xmlTool.LINE

				$xmlInsertFile = "{0}\{1}" -f $xmlTool.PATH, $xmlTool.FILENAME
				
				InsertText $xmlInsertFile $xmlText $xmlLine $xmlToolName
			}
			
			# == Run a PowerShell ScriptBlock == #
			"scriptblock" {
				$xmlScriptBlock = $xmlTool.SCRIPTBLOCK
				
				ExecuteScriptBlock $xmlScriptBlock $xmlToolName
			}
		}
	}
	
	# == Completed == #
	WriteLog "Completed All Actions: Exiting`n"
}