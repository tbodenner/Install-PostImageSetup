#Requires -RunAsAdministrator

# script version and name
$Version = '1.2.2'
$ScriptName = 'Install-PostImageSetup'

# ------------------------------------------------------- #
#      Install-PostImageSetup.ps1                         #
#        by Trenton Bodenner, Prescott OIT                #
#                                                         #
#      This script will install applications and          #
#      drivers on a freshly imaged laptop or desktop.     #
# ------------------------------------------------------- #

# ------------------------------------------------------- #
#                     CHANGE LOG                          #
# ------------------------------------------------------- #
<#
	1.0.0:
		Initial version.
	1.0.1:
		Added checking for a desktop or laptop.
		Updated driver lists
	1.0.2:
		Added Micro Focus 2FA DLL
	1.0.3:
		Added fix for firmware restart not working
		Added a check for Cisco AnyConnect being installed
	1.0.4:
		Added a check for the OSD Staging group
	1.0.5:
		Added a check for a specific lenovo model to install intel audio drivers
	1.0.6:
		Added power settings for desktops
	1.0.7:
		Added BIOS asset tag updates
	1.0.8:
		Updated paths to use variables
		Updated Lenovo custom function to include a BIOS update
	1.0.9:
		Changed reboot strings to variables
	1.1.0:
		Fixed issue with MSI packages not installing
	1.1.1:
		Added Ambir DS687 drivers
	1.1.2:
		Added a check to verify an install was successful and message is displayed on install success or failure
	1.1.3:
		Computer is moved into the correct OU if in staging OU
	1.1.4:
		If an install fails, then the install will be retried
		Changed cmd.exe commands into Start-Process commands
		Added registry value to possibly disable manufactureer app installs for devices (AMD Software)
	1.1.5:
		Updated Lynx installer to new version
	1.1.6:
		Changed individual reboot commands to a single function
	1.1.7:
		Progress count removed and text output colors changed
	1.1.8:
		Changed version number scheme
		Install work items are now read from a JSON file
	1.1.9:
		Added pause and retry count to items being installed
		Added json install file for Lenovo 21H2 laptop
		Added ability to delete a file or folder using a work object
	1.2.0:
		Added option for executables to skip checking if the application was installed
	1.2.1:
		Config variables moved to a json file
	1.2.2:
		Fixed RSAT uninstall command
		Updated config.json path to use script root path
#>

# ------------------------------------------------------- #
#                      CLASSES                            #
# ------------------------------------------------------- #

class BaseParameter {
	# properties
	[string]$Mesg
	[bool]$Laptop
	[bool]$Desktop
	# constructor
	BaseParameter([string]$Mesg, [bool]$Laptop, [bool]$Desktop) {
		$this.Mesg = $Mesg
		$this.Laptop = $Laptop
		$this.Desktop = $Desktop
	}
}

# parameters used to install an exe or msi file
class InstallParameter : BaseParameter {
	# properties
	[string]$Name
	[string]$File
	[string]$IArg
	[bool]$SkipCheck
	# constructor
	InstallParameter([string]$Name, [string]$File, [string]$IArg, [bool]$SkipCheck, [string]$Mesg, [bool]$Laptop, [bool]$Desktop)
		: base($Mesg, $Laptop, $Desktop) {
		$this.Name = $Name
		$this.File = $File
		$this.IArg = $IArg
		$this.SkipCheck = $SkipCheck
	}
}

# parameters used to manually install a driver
class DriverParameter : BaseParameter {
	# properties
	[string]$Name
	[string]$File
	# constructor
	DriverParameter([string]$Name, [string]$File, [string]$Mesg, [bool]$Laptop, [bool]$Desktop)
		: base($Mesg, $Laptop, $Desktop) {
		$this.Name = $Name
		$this.File = $File
	}
}

# parameters used to copy a file
class CopyParameter : BaseParameter {
	# properties
	[string]$File
	[string]$Dest
	# constructor
	CopyParameter([string]$File, [string]$Dest, [string]$Mesg, [bool]$Laptop, [bool]$Desktop)
		: base($Mesg, $Laptop, $Desktop) {
		$this.File = $File
		$this.Dest = $Dest
	}
}

# parameters used to run a command
class CommandParameter : BaseParameter {
	# properties
	[string]$CExe
	[string]$CArg
	# constructor
	CommandParameter([string]$CExe, [string]$CArg, [string]$Mesg, [bool]$Laptop, [bool]$Desktop)
		: base($Mesg, $Laptop, $Desktop) {
		$this.CExe = $CExe
		$this.CArg = $CArg
	}
}

# parameters used to delete a file or folder
class DeleteParameter : BaseParameter {
	# properties
	[string]$Path
	# constructor
	DeleteParameter([string]$Path, [string]$Mesg, [bool]$Laptop, [bool]$Desktop)
		: base($Mesg, $Laptop, $Desktop) {
		$this.Path = $Path
	}
}

# ------------------------------------------------------- #
#                        FUNCTIONS                        #
# ------------------------------------------------------- #

# run a command
function Invoke-Process {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Executable,
		[Parameter(Mandatory=$True)][string]$Arguments,
		[bool]$ReturnExitCode = $False
	)
	# our start-process parameters
	$Parameters = @{
		FilePath = $Executable
		ArgumentList = $Arguments
		RedirectStandardOutput = '.\NUL'
	}
	# check if we want the result returned
	if ($ReturnExitCode -eq $True) {
		# if true, start the command and return our results
		$Process = Start-Process @Parameters -PassThru -Wait -NoNewWindow
		return $Process.ExitCode
	}
	else {
		#Write-Host "Exe: $($Executable)" -ForegroundColor Magenta
		# otherwise, run the command and return null
		Start-Process @Parameters -Wait -NoNewWindow | Out-Null
		return $Null
	}
}

# get work items from json file
function Get-WorkItemsFromJson {
	param (
		[Parameter(Mandatory=$True)][string]$JsonFilePath,
		[Parameter(Mandatory=$True)][hashtable]$ExeHashtable,
		[Parameter(Mandatory=$True)][string]$InstallRootPath,
		[Parameter(Mandatory=$True)][string]$ComputerType
	)

	# try to read our data from the json file
	try {
		$JsonContent = Get-Content $JsonFilePath | ConvertFrom-Json
	}
	catch {
		# if we are unable to read the file, write an error message and return nothing
		Write-Host "Unable to get JSON data from file $($JsonFilePath)."
		return $Null
	}

	# our array that will store our work items
	$WorkItemArray = @()

	# loop through our work item data and create the object
	foreach ($Element in $JsonContent) {
		# try to convert our string values to boolean values
		try {
			# convert our strings to bools and store the result
			$LaptopBool = [System.Convert]::ToBoolean($Element.ltop)
			$DesktopBool = [System.Convert]::ToBoolean($Element.dtop)
			# if the computer is a laptop (2) and our bool is false
			if (($ComputerType -eq 2) -and ($LaptopBool -eq $False)) {
				# then skip this item
				continue
			}
			# if the computer is a desktop (1) and our bool is false
			if (($ComputerType -eq 1) -and ($DesktopBool -eq $False)) {
				# then skip this item
				continue
			}
		}
		catch {
			# if we can't get the boolean values, skip this item
			Write-Host "JSON Error: Could not get boolean values for laptop and/or desktop." -ForegroundColor Red
			continue
		}
		# switch on the work item type
		switch ($Element.type) {
			{ ($_ -eq "InstallExe") -or ($_ -eq "InstallMsi") } {
				# check if our install path is on the c: drive
				if ($Element.file.ToUpper() -like "C:\*") {
					# we have a root C: drive, don't change the path
					$InstallerPath = $Element.file
				}
				else {
					# otherwise, add our root install path to our json file path
					$InstallerPath = Join-Path -Path $InstallRootPath -ChildPath $Element.file
				}
				# get our skip check bool
				$SkipCheckBool = [System.Convert]::ToBoolean($Element.schk)
				# create the work item and add it to our array
				$WorkItemArray += [InstallParameter]::new($Element.name, $InstallerPath, $Element.args, $SkipCheckBool, $Element.mesg, $LaptopBool, $DesktopBool)
			}
			"CopyFile" {
				# add our root install path to our json file path
				$InstallerPath = Join-Path -Path $InstallRootPath -ChildPath $Element.file
				# get our json destination path
				$DestinationPath = $Element.dest
				# if the destination is the computer's public desktop
				if ($DestinationPath -eq "Public\Desktop") {
					# then update our path using the enviroment's path
					$DestinationPath = "$($env:PUBLIC)\Desktop"
				}
				# create the work item and add it to our array
				$WorkItemArray += [CopyParameter]::new($InstallerPath, $DestinationPath, $Element.mesg, $LaptopBool, $DesktopBool)
			}
			"RunCommand" {
				# get the path of our executable from our hashtable
				$ExePath = $ExeHashtable[$Element.file]
				# if we did not get a path
				if ($Null -eq $ExePath) {
					# skip this item
					Write-Host "JSON Error: Unknown executable '$($Element.file)'." -ForegroundColor Red
					continue
				}
				# create the work item and add it to our array
				$WorkItemArray += [CommandParameter]::new($ExePath, $Element.args, $Element.mesg, $LaptopBool, $DesktopBool)
			}
			"Driver" {
				# create the full path for our driver file
				$DriverFile = Join-Path -Path $InstallRootPath -ChildPath $Element.file
				# create the work item and add it to our array
				$WorkItemArray += [DriverParameter]::new($Element.name, $DriverFile, $Element.mesg, $LaptopBool, $DesktopBool)
			}
			"DeleteFile" {
				# create the work item and add it to our array
				$WorkItemArray += [DeleteParameter]::new($Element.file, $Element.mesg, $LaptopBool, $DesktopBool)
			}
			Default { Write-Host "JSON Error: Unknown type '$($Element.type)'." -ForegroundColor Red }
		}
	}

	# if everything worked, return our array
	$WorkItemArray
}

# get the filename for our transcript file
function Get-TranscriptFile {
	# file count
	$FileCount = 0
	# stop count
	$StopCount = 50
	# stop the while loop if set to false
	$LoopControl = $True
	# look for the next filename to use
	while ($LoopControl) {
		# create our zero padded string
		$PaddedFileCount = $FileCount.ToString().PadLeft(2, '0')
		# create our filename
		$TestFile = "$($TranscriptFile)-$($PaddedFileCount)$($TranscriptExtension)"
		# check if our filename exists
		if ((Test-Path -Path $TestFile) -eq $False) {
			# current file is not found, use it
			return $TestFile
		}
		# increase out file count
		$FileCount++
		# stop the loop
		if ($FileCount -ge $StopCount) { $LoopControl = $False }
	}
	# file name not create, return null
	return $Null
}

# install an executable
function Install-Exe {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Exe,
		[Parameter(Mandatory=$True)][string]$EArg
	)
	# run the installer
	Invoke-Process -Executable $Exe -Arguments $EArg
}

# install a msi
function Install-Msi {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Msi,
		[Parameter(Mandatory=$True)][string]$MArg
	)
	# run the installer
	Invoke-Process -Executable $Executables['MsiexecExe'] -Arguments "/i `"$($Msi)`" $($MArg)"
}

# manually install a driver with pnputil.exe
function Install-Driver {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$FilePath
	)
	# install the driver using pnputil
	& $Executables['PnpUtilExe'] /add-driver $FilePath /subdirs /install
}

# copy a file
function Copy-File {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Path,
		[Parameter(Mandatory=$True)][string]$Destination
	)
	# try to the copy the file
	try {
		# copy the file
		Copy-Item -Path $Path -Destination $Destination -Force -Recurse | Out-Null
	}
	catch {
		# write our error
		Write-Host "Unable to copy file '$($Path)' to '$($Destination)'" -ForegroundColor Red
	}
}

# delete a file or folder
function Remove-File {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Path
	)
	# try to the remove the file or folder
	try {
		# remove the file or folder
		Remove-Item -Path $Path -Force -Recurse | Out-Null
	}
	catch {
		# write our error
		Write-Host "Unable to delete file or folder '$($Path)'" -ForegroundColor Red
	}
}

function Update-Progress {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Status,
		[bool]$Echo = $False,
		[ConsoleColor]$Color
	)
	# if our color is empty
	if ($Null -eq $Color) {
		# then set it
		$Color = [System.ConsoleColor]::White
	}
	# check if we have a total value
	if ($ProgressTotal -gt 0) {
		# calculate our percentage
		$PComplete = ($ProgressCount / $ProgressTotal) * 100
		# don't allow values above 100
		if ($PComplete -ge 100) { $PComplete = 100 }
		# don't allow values below zero
		if ($PComplete -le 0) { $PComplete = 0 }
	}
	else {
		# if not, our percent is zero
		$PComplete = 0
	}
	# check if we are done
	if ($Status.ToUpper() -eq "DONE") {
		# if done, clear the progress bar
		Write-Progress -Activity $ProgressActivity -Status $Status -Completed
	}
	else {
		# update progress bar
		Write-Progress -Activity $ProgressActivity -Status " $($Status)" -PercentComplete $PComplete
	}
	# echo to host if our paramter is set
	if ($Echo -eq $True) {
		Write-Host $Status -ForegroundColor $Color
	}
	# sleep for a small amountof time to allow the update to be shown on screen
	Start-Sleep -Milliseconds 500
}

# check by name if a software package is installed
function Test-IsInstalled {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Name
	)
	# x86
	$Path32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
	# amd64
	$Path64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
	# get all installed software
	$Software = Get-ItemProperty -Path $Path32, $Path64
	# create our compare string
	$CompareName = "$($Name)*"
	# look for our software in our software list
	$Version = ($Software | Where-Object { $_.DisplayName -like $CompareName }).DisplayVersion
	# if the software is not found then IsInstalled is false
	if ($Null -eq $Version) {
		return $False
	}
	# return true for all other cases
	return $True
}

# check by name if our driver is found by pnputil /enum-drivers
function Test-IsPnpUtilDriverInstalled {
	# parameters
	param (
		[Parameter(Mandatory=$True)]$Drivers,
		[Parameter(Mandatory=$True)][string]$Name
	)
	# create our compare string
	$DriverName = "*$($Name)*"
	# look for our driver in our driver list
	$FoundDriver = $Drivers | Where-Object { if ($_ -like $DriverName ) { $_ } }
	# if the driver is not found then IsPnpUtilDriverInstalled is false
	if ($Null -eq $FoundDriver) {
		return $False
	}
	# return true for all other cases
	return $True
}

# check by name if our driver is found in our signed driver list
function Test-IsSignedDriverInstalled {
	# parameters
	param (
		[Parameter(Mandatory=$True)]$Drivers,
		[Parameter(Mandatory=$True)][string]$Name
	)
	# create our compare string
	$DriverName = "$($Name)*"
	# look for our driver in our driver list
	$FoundDriver = ($Drivers | Where-Object { $_.DeviceID -like $DriverName }).DeviceID
	# if the driver is not found then IsSignedDriverInstalled is false
	if ($Null -eq $FoundDriver) {
		return $False
	}
	# return true for all other cases
	return $True
}

# install an item based on it's object type
function Install-WorkItem {
	# parameters
	param (
		[Parameter(Mandatory=$True)][object]$WorkObject,
		[int]$RetryCount = 0
	)
	# skip our item if it is null
	if ($Null -eq $WorkObject) {
		Write-Host '!! Error, Work object is null' -ForegroundColor Red
		return
	}
	# update our progress count
	$Global:ProgressCount += 1
	# do work based on our object type
	switch ($WorkObject.GetType()) {
		# install an exe or msi item
		{ @([InstallParameter], [DriverParameter]) -contains $_ } {
			# write our message
			Write-Host "Install: $($WorkObject.Mesg)" -ForegroundColor White
		}
		# copy a file item
		([CopyParameter]) {
			# write our message
			Write-Host "   Copy: $($WorkObject.Mesg)" -ForegroundColor Cyan
		}
		# run a command item
		([CommandParameter]) {
			# write our message
			Write-Host "Command: $($WorkObject.Mesg)" -ForegroundColor Blue
		}
		# delete a file or folder
		([DeleteParameter]) {
			# write our message
			Write-Host " Delete: $($WorkObject.Mesg)" -ForegroundColor DarkCyan
		}
		# no match found, return
		default {
			Write-Host '!! Error, Wrong object type for work message (WorkObject.Mesg)' -ForegroundColor Red
			return
		}
	}
	# update our progress
	Update-Progress -Status $WorkObject.Mesg
	# do work based on our object type
	switch ($WorkObject.GetType()) {
		# install an exe or msi item
		([InstallParameter]) {
			# cast our work object into the correct object
			$Installer = [InstallParameter]$WorkObject
			# check if we should install this on the current computer type
			if (($ComputerType -eq 1) -and ($Installer.LaptopOnly -eq $True)) {
				Write-Host "-- '$($Installer.Name)' Skipped on Desktops" -ForegroundColor Magenta
				return
			}
			# check if the software is installed
			$IsSoftwareInstalled = Test-IsInstalled -Name $Installer.Name
			# check if the driver is installed
			$IsDriverInstalled = Test-IsSignedDriverInstalled -Drivers $SignedDrivers -Name $Installer.Name
			# install our item or skip it
			if (($IsSoftwareInstalled -eq $False) -and ($IsDriverInstalled -eq $False)) {
				# is this an exe or a msi file
				switch (Split-Path -Path $Installer.File -Extension) {
					'.exe' {
						# run the installer silently or passivly
						Install-Exe -Exe $Installer.File -EArg $Installer.IArg
					}
					'.msi' {
						# run the installer silently or passivly
						Install-Msi -Msi $Installer.File -MArg $Installer.IArg
					}
					Default {
						# wrong file type
						Write-Host "!! Error '$($Installer.File)', Wrong File Type" -ForegroundColor Red
						return
					}
				}
				# only check if the install worked if skip check if false
				if ($Installer.SkipCheck -eq $False) {
					# check if the software is installed
					if ((Test-IsInstalled -Name $Installer.Name) -eq $True) {
						# install was good
						Write-Host "-- '$($Installer.Name)' Installed" -ForegroundColor Green
					}
					else {
						# install failed
						Write-Host "-- '$($Installer.Name)' Failed" -ForegroundColor Red
						# the maximum number of times to try this work item
						$MaxInstallRetry = 5
						# check if we are at our retry count
						if ($RetryCount -lt $MaxInstallRetry) {
							# sleep for a set amount of time before retrying, because network connection might have been lost
							$InstallTimeoutSeconds = 30
							Write-Host "-- Trying again in $($InstallTimeoutSeconds) seconds" -ForegroundColor Yellow
							Start-Sleep -Seconds $InstallTimeoutSeconds
							# update our progress count
							$Global:ProgressCount -= 1
							# update our retry count
							$RetryCount += 1
							# run the installer again
							Install-WorkItem -WorkObject $Installer -RetryCount $RetryCount
						}
						else {
							# we are above our error count, write a message and return
							Write-Host "!! Error, failed to install '$($Installer.Name)' $($MaxInstallRetry) times, aborting." -ForegroundColor Red
							return
						}
					}
				}
				else {
					# otherwise, skip checking if the install was successful
					Write-Host "-- '$($Installer.Name)' skipped checking for install" -ForegroundColor DarkGreen
				}
			}
			else {
				# the item is already installed, so skip it
				Write-Host "-- '$($Installer.Name)' Already Installed" -ForegroundColor DarkGreen
			}
		}
		# install a driver
		([DriverParameter]) {
			# cast our work object into the correct object
			$Driver = [DriverParameter]$WorkObject
			# install the driver with pnputil
			if ((Test-IsPnpUtilDriverInstalled -Drivers $PnpUtilDrivers -Name $Driver.Name) -eq $False) {
				Install-Driver -FilePath $Driver.File
			}
			else {
				Write-Host "-- '$($Driver.Name)' Already Installed" -ForegroundColor DarkGreen
			}
		}
		# copy a file item
		([CopyParameter]) {
			# cast our work object into the correct object
			$Copy = [CopyParameter]$WorkObject
			# copy the file
			Copy-File -Path $Copy.File -Destination $Copy.Dest
		}
		# run a command item
		([CommandParameter]) {
			# cast our work object into the correct object
			$Cmd = [CommandParameter]$WorkObject
			# run the command
			Invoke-Process -Executable $Cmd.CExe -Arguments $Cmd.CArg
		}
		# delete a file or folder
		([DeleteParameter]) {
			# cast our work object into the correct object
			$Delete = [DeleteParameter]$WorkObject
			# remove the file or folder
			Remove-File -Path $Delete.Path
		}
		# no match found, return
		default {
			Write-Host '!! Error, Unknown type for work object (WorkObject.GetType)' -ForegroundColor Red
			return
		}
	}
}

# get the active directory organizational unit of this computer
function Get-ComputerOU {
	# get the gpresult data
	$ComputerOU = & $Executables['GpresultExe'] /r /scope computer 2>null
	# get our distinguished name from the data
	$ComputerOU = [string]($ComputerOU | Select-String "CN=")
	# if the object is null
	if ($Null -eq $ComputerOU) {
		# return an empty array
		return @()
	}
	# trim any whitspace, and split the string before returning the result
	return $ComputerOU.Trim() -Split ","
}

# check if this cmputer is in a specific organizational unit
function Test-IsStagingOU {
	# the group we are looking for
	$StagingGroup = 'OU=OSD Staging'
	# get our computer's UOs
	$OUnits = Get-ComputerOU
	# check if the group is in our ou string
	if ($OUnits -contains $StagingGroup) {
		# if found, return true
		return $True
	}
	else {
		# otherwise, return false
		return $False
	}
}

# update our computer's bios asset number
function Update-AssetTag {
	# parameters
	param (
		[Parameter(Mandatory=$True)][int]$AssetNumber,
		[Parameter(Mandatory=$True)][string]$Manufacturer
	)
	# we will create a command based on the computer manufacturer
	$AssetExe = $Null
	$AssetArg = $Null

	# set our command string based on our manufacturer
	switch ($Manufacturer.ToUpper()) {
		'DELL' {
			# create the command to set our asset tag number
			$AssetExe = $Executables['DellAssetExe']
			$AssetArg = "--asset=$($AssetNumber)"
		}
		'HP' {
			# create the command to set our asset tag number
			$AssetExe = $Executables['HpAssetExe']
			$AssetArg = "/setvalue:`"Asset Tracking Number,$($AssetNumber)`""
		}
		'LENOVO' {
			# create the command to set our asset tag number
			$AssetExe = $Executables['LenovoAssetExe']
			$AssetArg = "-silent -set USERASSETDATA.ASSET_NUMBER=$($AssetNumber)"
		}
		Default {
			# computer manufacturer not found
			Write-Host "Update-AssetTag: $($Manufacturer) not found"
			return $False
		}
	}
	# if our argument string is null or empty, return
	if (($Null -eq $AssetArg) -or ($AssetArg -eq "")) {
		return $False
	}
	# run the command
	Invoke-Process -Executable $AssetExe -Arguments $AssetArg
	# return true if we ran our command
	return $True
}

# get our asset number from our computer name
function Get-AssetTag {
	# parameters
	param (
		[Parameter(Mandatory=$True)][string]$Name
	)
	# get the asset number from our computer name
	# match five digits at the end of the line
	$Found = $Name -match '[0-9]{5}$'
	# check if we have a match
	if ($Found -eq $False) {
		# return null if not found
		return $Null
	}
	# get the first match
	$Number = $matches[0]
	# check if our asset tag is empty
	if ($Number -eq "") {
		# return null if our number is empty
		return $Null
	}
	# check if our asset tag is the correct length
	if ($Number.Length -ne $AssetTagLength) {
		# return null if not the correct length
		return $Null
	}
	# return our asset number
	return $Number
}

# add or update a value in the registry
function Add-RegistryKey {
	param (
		[string]$Path,
		[string]$KeyName,
		[Microsoft.Win32.RegistryValueKind]$KeyType,
		$Value
	)
	
	# check if path exists
	if ((Test-Path -Path $Path -Type Container) -eq $False) {
		# if the path is missing, then create it
		New-Item -Path $Path | Out-Null
	}

	# create the key if missing and set the value
	Set-ItemProperty -Path $Path -Name $KeyName -Value $Value -Type $KeyType | Out-Null
}

# add registry value to stop downloading manufacturers' apps for installed devices
function Set-DisableAppsForDevices {
	# the registry values
	#$RegPath = 'HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall'
	#$RegKeyName = 'AllowOSManagedDriverInstallationToUI'
	#$RegKeyValue = 0
	# add the key
	#Add-RegistryKey -Path $RegPath -Name $RegKeyName -Value $RegKeyValue -KeyType DWord

	# the registry values
	$RegPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Device Installer'
	$RegKeyName = 'DisableCoInstallers'
	$RegKeyValue = 1
	# add the key
	Add-RegistryKey -Path $RegPath -Name $RegKeyName -Value $RegKeyValue -KeyType DWord
}

# reboot the computer
function Start-ComputerRestart {
	param (
		[int]$TimeOut = 60,
		[bool]$Firmware = $False,
		[bool]$Abort = $False
	)
	$ShutdownExe = 'C:\Windows\System32\shutdown.exe'
	$RebootMessage = "Rebooting in $($RebootTimeout) seconds"
	$RebootArg = "/r /f /t $($RebootTimeout) /c `"$($RebootMessage)`""
	# abort a reboot
	if ($Abort -eq $True) {
		$RebootMessage = "Aborting reboot"
		$RebootArg = '/a'
	}
	# reboot to firmware with a timeout
	elseif (($Firmware -eq $True) -and ($TimeOut -gt 0)) {
		$RebootMessage = "Rebooting to Firmware (BIOS/UEFI) in $($TimeOut) seconds"
		$RebootArg = "/r /f /fw /t $($TimeOut) /c `"$($RebootMessage)`""
	}
	# immediately reboot to firmware
	elseif (($Firmware -eq $True) -and ($TimeOut -le 0)) {
		$RebootMessage = 'Rebooting to Firmware (BIOS/UEFI) now'
		$RebootArg = "/r /f /fw /t 0 /c `"$($RebootMessage)`""
	}
	# reboot normally with a timeout
	elseif (($Firmware -eq $False) -and ($TimeOut -gt 0)) {
		$RebootMessage = "Rebooting in $($TimeOut) seconds"
		$RebootArg = "/r /f /t $($TimeOut) /c `"$($RebootMessage)`""
	}
	# immediately reboot normally
	elseif (($Firmware -eq $False) -and ($TimeOut -le 0)) {
		$RebootMessage = 'Rebooting now'
		$RebootArg = "/r /f /t 0 /c `"$($RebootMessage)`""
	}
	# something else happened, don't reboot
	else {
		Write-Host 'Start-ComputerRestart: Invalid reboot arguments' -ForegroundColor Red
	}
	# run the reboot command
	$ReturnCode = Invoke-Process -Executable $ShutdownExe -Arguments $RebootArg -ReturnExitCode $True
	if ($ReturnCode -eq 203) {
		Write-Host "Error: 203 returned from shutdown.exe, trying again" -ForegroundColor Magenta
		Start-ComputerRestart -TimeOut $TimeOut -Firmware $Firmware -Abort $Abort
	}
}

# check if a config value is null
function Test-ConfigValueNull {
	param (
		[Parameter(Mandatory=$True)][hashtable]$Hashtable,
		[Parameter(Mandatory=$True)][string]$Key
	)
	# get our value
	$Value = $Hashtable[$Key]

	# check if the value is null
	if (($Null -eq $Value) -or ($Value -eq "")) {
		# if the value is null, write an error message and exit
		Write-Host "ERROR: Config '$($Key)' value is null or empty." -ForegroundColor Red
		exit
	}
	# otherwise, return the value
	$Value
}

# ------------------------------------------------------- #
#                         CONFIG                          #
# ------------------------------------------------------- #

# begin reading config and getting base system information
Write-Host "Initializing, please wait..." -ForegroundColor DarkGray

# our json config file
$JsonConfigFileName = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'

# check if our config file exists
if ((Test-Path -Path $JsonConfigFileName) -eq $False)
{
	# if we are unable to read the file, write an error message and exit
	Write-Host "ERROR: JSON config file '$($JsonConfigFileName)' not found." -ForegroundColor Red
	exit
}

# read our data from the json config file
$JsonConfigHashtable = Get-Content $JsonConfigFileName | ConvertFrom-Json -AsHashtable

# check if our hashtable is null
if ($Null -eq $JsonConfigHashtable) {
	# hashtable is null, exit
	Write-Host "ERROR: No config data read from JSON file '$($JsonConfigFileName)'." -ForegroundColor Red
	exit
}

# mapped drive variables
$MapDriveLetter = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "MapDriveLetter"
$MapDriveFolder = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "MapDriveFolder"

# temp folder
$TempFolder = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "TempFolder"

# system folder
$SystemFolder = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "SystemFolder"

# install folder
$InstallFolder = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "InstallFolder"

# file name for our json installs file
$JsonFileName = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "JsonFileName"

# paths for our bios asset update executables
$DellAssetExePath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "DellAssetExePath"
$HpAssetExePath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "HpAssetExePath"
$LenovoAssetExePath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoAssetExePath"

# computer model to install the lenovo intel audio drivers and updated BIOS
$LenovoModel21H2 = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoModel21H2"
# json file for our custom installs
$LenovoModel21H2JsonFileName = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoModel21H2JsonFileName"
# update the bios if not this version
$LenovoModel21H2BiosTargetVersion = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoModel21H2BiosTargetVersion"

# filename and path for the RSAT installer
$RSATFolderPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "RSATFolderPath"
$RSATFileName = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "RSATFileName"

# config was loaded from the json file
Write-Host "Config loaded." -ForegroundColor DarkGray

# ------------------------------------------------------- #
#                       PROPERTIES                        #
# ------------------------------------------------------- #

# transcript file
$TranscriptFile = "$($TempFolder)\PostImageSetup$($Version)-Transcript"
$TranscriptExtension = '.txt'

# mapped install folder
$MappedInstall = "$($MapDriveLetter):\$($InstallFolder)"

# executable location hashtable
$Executables = @{
	"CmdExe"		 = "$($SystemFolder)\cmd.exe"
	"WusaExe"		 = "$($SystemFolder)\wusa.exe"
	"PnpUtilExe"	 = "$($SystemFolder)\pnputil.exe"
	"MsiexecExe"	 = "$($SystemFolder)\msiexec.exe"
	"PowercfgExe"	 = "$($SystemFolder)\powercfg.exe"
	"GpupdateExe"	 = "$($SystemFolder)\gpupdate.exe"
	"GpresultExe"	 = "$($SystemFolder)\gpresult.exe"
	"DellAssetExe"	 = "$($MappedInstall)\$($DellAssetExePath)"
	"HpAssetExe"	 = "$($MappedInstall)\$($HpAssetExePath)"
	"LenovoAssetExe" = "$($MappedInstall)\$($LenovoAssetExePath)"
}

# file to read the work item data from
$JsonFilePath = Join-Path -Path $PSScriptRoot -ChildPath $JsonFileName

# reboot variables in seconds
$RebootTimeout = 60

# asset tag length
$AssetTagLength = 5

# read cim data
Write-Host "Getting computer information..." -ForegroundColor DarkGray

# get computer name
$ComputerName = $env:ComputerName
# get computer type: 1 = desktop, 2 = laptop
$ComputerType = (Get-CimInstance -ClassName Win32_ComputerSystem -Property PCSystemType).PCSystemType
# get computer manufacturer
$ComputerManufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
# check for alternate variations of the manufacture's name
if ($ComputerManufacturer.ToUpper() -eq "DELL INC.") {
	$ComputerManufacturer = "Dell"
}
# get computer model
$ComputerModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
# get computer asset tag
$ComputerAssetTag = (Get-CimInstance -ClassName Win32_SystemEnclosure).SMBIOSAssetTag

# progress message
$ProgressActivity = "Post-Image Setup"
# current progress count
$ProgressCount = 0
# total progress count
$ProgressTotal = 0

# pause before clearing the screen
Start-Sleep -Seconds 1

# clear the screen
Clear-Host

# ------------------------------------------------------- #
#                       MAIN SCRIPT                       #
# ------------------------------------------------------- #

# draw banner
Write-Host " _____                         _   _      ____ _____ _______ " -ForegroundColor Red
Write-Host "|  __ \                       | | | |    / __ \_   _|__   __|" -ForegroundColor Red
Write-Host "| |__) | __ ___  ___  ___ ___ | |_| |_  | |  | || |    | |   " -ForegroundColor White
Write-Host "|  ___/ '__/ _ \/ __|/ __/ _ \| __| __| | |  | || |    | |   " -ForegroundColor White
Write-Host "| |   | | |  __/\__ \ (_| (_) | |_| |_  | |__| || |_   | |   " -ForegroundColor Blue
Write-Host "|_|   |_|  \___||___/\___\___/ \__|\__|  \____/_____|  |_|   " -ForegroundColor Blue

# check if the temp directory exists
if ((Test-Path -Path $TempFolder) -eq $False) {
	# if not found, create it
	New-Item -Path $TempFolder -ItemType "directory" | Out-Null
}

# start the transcript
$TranscriptFile = Get-TranscriptFile
# check that we got a filename
if ($Null -eq $TranscriptFile) {
	# write our error message
	$EMsg = "Unable to create transcript file. Exiting."
	Write-Error $EMsg
	Write-Host $EMsg -ForegroundColor Red
	# exit
	exit
}
# start the transcript
Start-Transcript -Path $TranscriptFile -NoClobber | Out-Null

# write our script's name and version
# this is done after our transcript starts to record the script version
Write-Host "$($ScriptName) v$($Version)`n" -ForegroundColor DarkGray

# map the drive for our script root
Update-Progress -Status "Mapping Drive" -Echo $True
New-PSDrive -Name $MapDriveLetter -Root $MapDriveFolder -Persist -PSProvider "FileSystem" -ErrorAction SilentlyContinue | Out-Null

# change to our mapped drive
Set-Location "$($MapDriveLetter):"

# get the drivers from pnputil
$PnpUtilDrivers = & $Executables['PnpUtilExe'] /enum-drivers
# get the signed drivers
$SignedDrivers = Get-CimInstance Win32_PnPSignedDriver

# write out our computer's make and model
$MakeModel = "$($ComputerManufacturer) ($($ComputerModel))"
switch ($ComputerType) {
	1 { Write-Host "Desktop: $($MakeModel)" -ForegroundColor White }
	2 { Write-Host "Laptop: $($MakeModel)" -ForegroundColor White }
	Default { Write-Host "Other Device: $($MakeModel)" -ForegroundColor Yellow }
}

# check if the mapped drive exists
if ((Test-Path -Path "$($MapDriveLetter):\") -eq $False) {
	# clear the progress bar
	Write-Progress -Completed -Status "Error"
	# write an error
	$ErrorString = "Install drive was not mapped. Unable to continue."
	Write-Error $ErrorString
	Write-Host $ErrorString -ForegroundColor Red
	# exit the script
	exit
}

# add a registry value and set it's value
Set-DisableAppsForDevices

# boolean to determine if we will update our asset tag
$UpdateTag = $False

# get our asset tag number from our computer name
Update-Progress -Status "Getting BIOS Asset Tag" -Echo $True
$AssetNumber = Get-AssetTag -Name $ComputerName
# write our asset number
Write-Host "EE: $($AssetNumber)" -ForegroundColor White

# if the asset tag is empty
if ($ComputerAssetTag -eq "") {
	# update our asset tag
	$UpdateTag = $True
}
else {
	# check if our computer's asset tag is correct
	if ($Null -eq $AssetNumber) {
		# if not found, update our asset tag
		$UpdateTag = $True
	}
	else {
		# check if our asset tag matches what it should be
		if ($AssetNumber -eq $ComputerAssetTag) {
			# the tags match, don't update our tag
			$UpdateTag = $False
		}
		else {
			# the tags don't match, update our tag
			$UpdateTag = $True
		}
	}
}

# check if we need to updatge our tag
if ($UpdateTag -eq $False) {
	# asset tag already set
	Write-Host "BIOS Asset Tag Found" -ForegroundColor Cyan
}
else {
	# set our asset tag if it is not null
	if ($Null -ne $AssetNumber) {
		# set our asset number
		Update-Progress -Status "Setting BIOS Asset Tag" -Echo $True
		$Result = Update-AssetTag -AssetNumber $AssetNumber -Manufacturer $ComputerManufacturer
		# write the outcome of setting our asset tag
		if ($Result -eq $True) {
			Write-Host "BIOS Asset Tag Set" -ForegroundColor Green
		}
		else {
			Write-Host "BIOS Asset Tag NOT Set" -ForegroundColor Red
		}
	}
}

# check if this computer is still in the staging group in active directory
Update-Progress -Status "Checking Computer's OU" -Echo $True
if (Test-IsStagingOU -eq $True) {
	# get our installer path
	$RSATInstallerPath = Join-Path -Path $MappedInstall -ChildPath $RSATFolderPath -AdditionalChildPath $RSATFileName

	Write-Host "Attempting to move computer in Active Directory" -ForegroundColor Yellow
	Update-Progress -Status "Installing RSAT" -Echo $True
	# install the rsat tools
	$RSATInstallArg = "$($RSATInstallerPath) /quiet /norestart"
	Invoke-Process -Executable $Executables['WusaExe'] -Arguments $RSATInstallArg

	# distinguished name of the computer if in the staging OU
	$StagingName = "CN=$($ComputerName),OU=OSD Staging,OU=Test Lab,DC=v18,DC=med,DC=va,DC=gov"
	# check if the command we need was installed
	if ($Null -ne (Get-Command -Name 'Get-ADComputer' -ErrorAction SilentlyContinue)) {
		# get the computer object from AD
		$ComputerObject = Get-ADComputer -Identity $ComputerName
		# get the computer's distinguished name
		$ComputerDistinguishedName = $ComputerObject.DistinguishedName

		# check, again, if the computer is still in the staging OU
		if ($ComputerDistinguishedName -eq $StagingName) {
			# get the computer's object guid
			$ComputerGUID = $ComputerObject.ObjectGUID

			$TargetOU = $Null
			# check if this computer is a desktop
			if ($ComputerType -eq 1) {
				# set our OU to the workstations OU
				$TargetOU = "OU=Workstations,OU=Prescott (PRE),OU=VISN18,DC=v18,DC=med,DC=va,DC=gov"
			}
			# check if this computer is a laptop
			if ($ComputerType -eq 2) {
				# set our OU to the laptops OU
				$TargetOU = "OU=Laptops,OU=Prescott (PRE),OU=VISN18,DC=v18,DC=med,DC=va,DC=gov"
			}

			# move the computer if we have an OU
			if ($Null -ne $TargetOU) {
				try {
					# move the computer to the correct OU
					Move-ADObject -Identity $ComputerGUID -TargetPath $TargetOU
					Write-Host "Moved computer '$($ComputerName)' to '$($TargetOU)'." -ForegroundColor Green
				}
				catch {
					# the command to move the computer failed
					Write-Host "Error: Failed to move computer to correct OU." -ForegroundColor Red
				}
			}
		}
		# uninstall the rsat tools
		Update-Progress -Status "Removing RSAT" -Echo $True
		$RSATUninstallArg = "$($RSATInstallerPath) /uninstall /quiet /norestart"
		Invoke-Process -Executable $Executables['WusaExe'] -Arguments $RSATUninstallArg
	}
	else {
		Write-Host "Error: Failed to move computer to correct OU. (RSAT install failed)" -ForegroundColor Red
	}
}
else
{
	Write-Host "Computer has already been moved out of the staging OU." -ForegroundColor Green
}

# check if this computer model is a lenovo 21h2
if ($ComputerModel -eq $LenovoModel21H2) {
	# create our path for our json installs file
	$LenovoModel21H2JsonFile = Join-Path -Path $PSScriptRoot -ChildPath $LenovoModel21H2JsonFileName
	# get the commands from the install file and add them to our work array
	$WorkArray += Get-WorkItemsFromJson -JsonFilePath $LenovoModel21H2JsonFile -ExeHashtable $Executables -InstallRootPath $MappedInstall -ComputerType $ComputerType

	# get the bios major and minor version
	$BiosMajor = (Get-CimInstance -ClassName Win32_BIOS).SystemBiosMajorVersion
	$BiosMinor = (Get-CimInstance -ClassName Win32_BIOS).SystemBiosMinorVersion
	# create a dot seperated version
	$BiosVersion = "$($BiosMajor).$($BiosMinor)"
	# check if we have the correct bios version installed
	if ($BiosVersion -eq $LenovoModel21H2BiosTargetVersion) {
		Write-Host "Lenovo BIOS $($BiosVersion) already installed" -ForegroundColor DarkGreen
		# remove the last three bios commands from the array that copy, install, and delete
		$WorkArray = $WorkArray[0..($WorkArray.Length - 4)]
	}
}

# all work to be done will go into this array
$WorkArray += Get-WorkItemsFromJson -JsonFilePath $JsonFilePath -ExeHashtable $Executables -InstallRootPath $MappedInstall -ComputerType $ComputerType

# get total progress count
$ProgressTotal = $WorkArray.Count

# install each exe in our array
$WorkArray.ForEach({ Install-WorkItem -WorkObject $_; Start-Sleep -Milliseconds 500 })

# run gpupdate
Update-Progress -Status "Running GP Update" -Echo $True
& $Executables['CmdExe'] /c "ECHO N | $($Executables['GpupdateExe']) /force /wait:180" | Out-Null
Update-Progress -Status "GP Update Finished" -Echo $True

# anyconnect software name
$AnyConnect = 'Cisco AnyConnect Secure Mobility Client'
# check if this is a laptop and if anyconnect is installed
if (($ComputerType -eq 2) -and ((Test-IsInstalled -Name $AnyConnect) -eq $False)) {
	# if this is a laptop and the software is not found, alert the user
	Write-Host "************************************************************************************" -ForegroundColor Red
	Write-Host "* Warning, '$($AnyConnect)' NOT installed on this laptop! *" -ForegroundColor Red
	Write-Host "************************************************************************************`n`n" -ForegroundColor Red
}

# change out of our mapped drive
Set-Location $SystemFolder

# remove our temp drive
Update-Progress -Status "Removing Mapped Drive" -Echo $True
Remove-PSDrive -Name $MapDriveLetter -Force | Out-Null

# installs done
Update-Progress -Status "Done" -Echo $True

# stop the transcript
Stop-Transcript | Out-Null

# check if secure boot is enabled
[bool]$SecureBootEnabled = Confirm-SecureBootUEFI
# check if the securebootenabled variable was assigned a value
if ($Null -eq $SecureBootEnabled) {
	# if null, write a message and exit the script
	Write-Host "!! Error, Unable to get Secure Boot status!" -ForegroundColor Red
	exit
}

# reboot the computer
if ($SecureBootEnabled) {
	# if true, reboot the computer
	Start-ComputerRestart -TimeOut $RebootTimeout -Firmware $False
	Write-Host "Rebooting in $($RebootTimeout) seconds" -ForegroundColor Green
}
else {
	# if false, reboot the computer to the firmware
	Start-ComputerRestart -TimeOut $RebootTimeout -Firmware $True
	Write-Host "Rebooting to Firmware (BIOS/UEFI) in $($RebootTimeout) seconds" -ForegroundColor Green
}

# ask the user if they want to stop the reboot
$LoopControl = $True
while ($LoopControl) {
	Write-Host "Reboot Commands:`nA: Abort Reboot`nN: Close This Window`nY: Reboot Now"
	$Result = Read-Host -Prompt "Reboot Command: [a/n/y]"
	switch -Exact ($Result.ToUpper()) {
		"A" {
			# abort the shutdown and end the script
			Start-ComputerRestart -Abort $True
			Write-Host "Reboot Aborted" -ForegroundColor Red
			$LoopControl = $False
		}
		"N" {
			# end the script
			Write-Host "Continuing With Timed Reboot" -ForegroundColor Yellow
			$LoopControl = $False
		}
		"Y" {
			# abort the current shutdown
			Start-ComputerRestart -Abort $True
			# reboot now and end the script
			Write-Host "Rebooting Now" -ForegroundColor Green
			if ($SecureBootEnabled) {
				# secure boot is enabled, reboot normally
				$LoopControl = $False
				Start-ComputerRestart -TimeOut 0 -Firmware $False
			}
			else {
				# secure boot is disabled, reboot to firmware
				$LoopControl = $False
				Start-ComputerRestart -TimeOut 0 -Firmware $True
			}
		}
		Default {
			Write-Host "Invalid Response" -ForegroundColor Red
		}
	}
}
