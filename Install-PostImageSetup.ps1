#Requires -RunAsAdministrator

# script version and name
$Version = '1.3.6'
$ScriptName = 'Install-PostImageSetup'

# ------------------------------------------------------- #
#      Install-PostImageSetup.ps1                         #
#        by Trenton Bodenner, Prescott OIT                #
#                                                         #
#      This script will install applications and          #
#      drivers on a freshly imaged laptop or desktop.     #
# ------------------------------------------------------- #

#region CHANGE LOG
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
		Added registry value to possibly disable manufacturer app installs for devices (AMD Software)
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
	1.2.3:
		Fixed an error with gpresult writing to null instead of nul
	1.2.4:
		Enabled PowerShell 7 remoting
	1.2.5:
		Updated Cisco VPN software name
	1.2.6:
		Removed PSRemote version 7 update
		Updated the OSD Staging check to include the va.gov domain
		Added changing BIOS settings
		Removed secure boot check, and no longer boots to firmware
	1.2.7:
		ATH computers will not have any software or drivers installed
	1.2.8:
		Added a registry value change to hide the last logged in user
	1.2.9:
		Updated script to no longer use RSAT AD tools
	1.3.0:
		Added checks for baseline software
		Moved asset tag length and reboot time variables to config.json
	1.3.1:
		Moved banner to config.json file
	1.3.2:
		Updated getting asset number from device name to find 5 or 6 digits
	1.3.3:
		Some desktops are workstations in the CIM data. Updated script to treat workstations as desktops.
	1.3.4:
		Updated json config names to make them more readable.
	1.3.5:
		Updated AD searcher to set va.gov as entry point.
	1.3.6:
		Updated names in install config.
		Removed custom installs for Lenovo 21H2 laptop.
#>
#endregion CHANGE LOG

#region CLASSES
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
#endregion CLASSES

#region FUNCTIONS
# ------------------------------------------------------- #
#                        FUNCTIONS                        #
# ------------------------------------------------------- #

# run a command
function Invoke-Process {
	# parameters
	param (
		[Parameter(Mandatory=$true)][string]$Executable,
		[Parameter(Mandatory=$true)][string]$Arguments,
		[bool]$ReturnExitCode = $false
	)
	# our start-process parameters
	$Parameters = @{
		FilePath = $Executable
		ArgumentList = $Arguments
		RedirectStandardOutput = 'NUL'
	}
	# check if we want the result returned
	if ($ReturnExitCode -eq $true) {
		# if true, start the command and return our results
		$Process = Start-Process @Parameters -PassThru -Wait -NoNewWindow
		return $Process.ExitCode
	}
	else {
		#Write-Host "Exe: $($Executable)" -ForegroundColor Magenta
		# otherwise, run the command and return null
		Start-Process @Parameters -Wait -NoNewWindow | Out-Null
		return $null
	}
}

# get our baseline install names from the json file
function Get-BaselineItemsFromJson {
	param (
		[Parameter(Mandatory=$true)][string]$JsonFilePath
	)

	# try to read our data from the json file
	try {
		Get-Content $JsonFilePath | ConvertFrom-Json -AsHashtable
	}
	catch {
		# if we are unable to read the file, write an error message and return nothing
		Write-Host "Unable to get Baseline JSON data from file $($JsonFilePath)."
		return $null
	}
}

# get work items from json file
function Get-WorkItemsFromJson {
	param (
		[Parameter(Mandatory=$true)][string]$JsonFilePath,
		[Parameter(Mandatory=$true)][hashtable]$ExeHashtable,
		[Parameter(Mandatory=$true)][string]$InstallRootPath,
		[Parameter(Mandatory=$true)][string]$ComputerType
	)

	# try to read our data from the json file
	try {
		$JsonContent = Get-Content $JsonFilePath | ConvertFrom-Json
	}
	catch {
		# if we are unable to read the file, write an error message and return nothing
		Write-Host "Unable to get JSON data from file $($JsonFilePath)."
		return $null
	}

	# our array that will store our work items
	$WorkItemArray = @()

	# loop through our work item data and create the object
	foreach ($Element in $JsonContent) {
		# try to convert our string values to boolean values
		try {
			# convert our strings to bools and store the result
			$LaptopBool = [System.Convert]::ToBoolean($Element.IsLaptop)
			$DesktopBool = [System.Convert]::ToBoolean($Element.IsDesktop)
			# if the computer is a laptop (2) and our bool is false
			if (($ComputerType -eq 2) -and ($LaptopBool -eq $false)) {
				# then skip this item
				continue
			}
			# if the computer is a desktop (1) and our bool is false
			if (($ComputerType -eq 1) -and ($DesktopBool -eq $false)) {
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
		switch ($Element.Type) {
			"Install" {
				# check if our install path is on the c: drive
				if ($Element.FilePath.ToUpper() -like "C:\*") {
					# we have a root C: drive, don't change the path
					$InstallerPath = $Element.FilePath
				}
				else {
					# otherwise, add our root install path to our json file path
					$InstallerPath = Join-Path -Path $InstallRootPath -ChildPath $Element.FilePath
				}
				# get our skip check bool
				$SkipCheckBool = [System.Convert]::ToBoolean($Element.SkipCheck)
				# create the work item and add it to our array
				$WorkItemArray += [InstallParameter]::new($Element.Name, $InstallerPath, $Element.Arguments, $SkipCheckBool, $Element.Message, $LaptopBool, $DesktopBool)
			}
			"CopyFile" {
				# add our root install path to our json file path
				$InstallerPath = Join-Path -Path $InstallRootPath -ChildPath $Element.FilePath
				# get our json destination path
				$DestinationPath = $Element.Destination
				# if the destination is the computer's public desktop
				if ($DestinationPath -eq "Public\Desktop") {
					# then update our path using the environment's path
					$DestinationPath = "$($env:PUBLIC)\Desktop"
				}
				# create the work item and add it to our array
				$WorkItemArray += [CopyParameter]::new($InstallerPath, $DestinationPath, $Element.Message, $LaptopBool, $DesktopBool)
			}
			"RunCommand" {
				# get the path of our executable from our hashtable
				$ExePath = $ExeHashtable[$Element.FilePath]
				# if we did not get a path
				if ($null -eq $ExePath) {
					# skip this item
					Write-Host "JSON Error: Unknown executable '$($Element.FilePath)'." -ForegroundColor Red
					continue
				}
				# create the work item and add it to our array
				$WorkItemArray += [CommandParameter]::new($ExePath, $Element.Arguments, $Element.Message, $LaptopBool, $DesktopBool)
			}
			"Driver" {
				# create the full path for our driver file
				$DriverFile = Join-Path -Path $InstallRootPath -ChildPath $Element.FilePath
				# create the work item and add it to our array
				$WorkItemArray += [DriverParameter]::new($Element.Name, $DriverFile, $Element.Message, $LaptopBool, $DesktopBool)
			}
			"DeleteFile" {
				# create the work item and add it to our array
				$WorkItemArray += [DeleteParameter]::new($Element.FilePath, $Element.Message, $LaptopBool, $DesktopBool)
			}
			Default { Write-Host "JSON Error: Unknown type '$($Element.Type)'." -ForegroundColor Red }
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
	$LoopControl = $true
	# look for the next filename to use
	while ($LoopControl) {
		# create our zero padded string
		$PaddedFileCount = $FileCount.ToString().PadLeft(2, '0')
		# create our filename
		$TestFile = "$($TranscriptFile)-$($PaddedFileCount)$($TranscriptExtension)"
		# check if our filename exists
		if ((Test-Path -Path $TestFile) -eq $false) {
			# current file is not found, use it
			return $TestFile
		}
		# increase out file count
		$FileCount++
		# stop the loop
		if ($FileCount -ge $StopCount) { $LoopControl = $false }
	}
	# file name not create, return null
	return $null
}

# install an executable
function Install-Exe {
	# parameters
	param (
		[Parameter(Mandatory=$true)][string]$Exe,
		[Parameter(Mandatory=$true)][string]$EArg
	)
	# run the installer
	Invoke-Process -Executable $Exe -Arguments $EArg
}

# install a msi
function Install-Msi {
	# parameters
	param (
		[Parameter(Mandatory=$true)][string]$Msi,
		[Parameter(Mandatory=$true)][string]$MArg
	)
	# run the installer
	Invoke-Process -Executable $Executables['MsiexecExe'] -Arguments "/i `"$($Msi)`" $($MArg)"
}

# manually install a driver with pnputil.exe
function Install-Driver {
	# parameters
	param (
		[Parameter(Mandatory=$true)][string]$FilePath
	)
	# install the driver using pnputil
	& $Executables['PnpUtilExe'] /add-driver $FilePath /subdirs /install | Out-Null
}

# copy a file
function Copy-File {
	# parameters
	param (
		[Parameter(Mandatory=$true)][string]$Path,
		[Parameter(Mandatory=$true)][string]$Destination
	)
	# try to the copy the file
	try {
		# check if our paths exist
		$PathExists = Test-Path -Path $Path
		$DestinationExists = Test-Path -Path $Destination
		# if both paths exist
		if (($PathExists -eq $true) -and ($DestinationExists -eq $true)) {
			# copy the file
			Copy-Item -Path $Path -Destination $Destination -Force -Recurse | Out-Null
		}
		else {
			# write our error
			Write-Host "`t Unable to copy file. Path or Destination doesn't exist." -ForegroundColor Red
		}
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
		[Parameter(Mandatory=$true)][string]$Path
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
		[Parameter(Mandatory=$true)][string]$Status,
		[bool]$Echo = $false,
		[ConsoleColor]$Color
	)
	# if our color is empty
	if ($null -eq $Color) {
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
	# echo to host if our parameter is set
	if ($Echo -eq $true) {
		Write-Host $Status -ForegroundColor $Color
	}
	# sleep for a small amount of time to allow the update to be shown on screen
	Start-Sleep -Milliseconds 500
}

# check by name if a software package is installed
function Test-IsInstalled {
	# parameters
	param (
		[Parameter(Mandatory=$true)][string]$Name
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
	if ($null -eq $Version) {
		return $false
	}
	# return true for all other cases
	return $true
}

# check by name if our driver is found by pnputil /enum-drivers
function Test-IsPnpUtilDriverInstalled {
	# parameters
	param (
		[Parameter(Mandatory=$true)]$Drivers,
		[Parameter(Mandatory=$true)][string]$Name
	)
	# create our compare string
	$DriverName = "*$($Name)*"
	# look for our driver in our driver list
	$FoundDriver = $Drivers | Where-Object { if ($_ -like $DriverName ) { $_ } }
	# if the driver is not found then IsPnpUtilDriverInstalled is false
	if ($null -eq $FoundDriver) {
		return $false
	}
	# return true for all other cases
	return $true
}

# check by name if our driver is found in our signed driver list
function Test-IsSignedDriverInstalled {
	# parameters
	param (
		[Parameter(Mandatory=$true)]$Drivers,
		[Parameter(Mandatory=$true)][string]$Name
	)
	# create our compare string
	$DriverName = "$($Name)*"
	# look for our driver in our driver list
	$FoundDriver = ($Drivers | Where-Object { $_.DeviceID -like $DriverName }).DeviceID
	# if the driver is not found then IsSignedDriverInstalled is false
	if ($null -eq $FoundDriver) {
		return $false
	}
	# return true for all other cases
	return $true
}

# install an item based on it's object type
function Install-WorkItem {
	# parameters
	param (
		[Parameter(Mandatory=$true)][object]$WorkObject,
		[int]$RetryCount = 0
	)
	# skip our item if it is null
	if ($null -eq $WorkObject) {
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
			if (($ComputerType -eq 1) -and ($Installer.LaptopOnly -eq $true)) {
				Write-Host "-- '$($Installer.Name)' Skipped on Desktops" -ForegroundColor Magenta
				return
			}
			# check if the software is installed
			$IsSoftwareInstalled = Test-IsInstalled -Name $Installer.Name
			# check if the driver is installed
			$IsDriverInstalled = Test-IsSignedDriverInstalled -Drivers $SignedDrivers -Name $Installer.Name
			# install our item or skip it
			if (($IsSoftwareInstalled -eq $false) -and ($IsDriverInstalled -eq $false)) {
				# is this an exe or a msi file
				switch (Split-Path -Path $Installer.File -Extension) {
					'.exe' {
						# run the installer silently or passively
						Install-Exe -Exe $Installer.File -EArg $Installer.IArg
					}
					'.msi' {
						# run the installer silently or passively
						Install-Msi -Msi $Installer.File -MArg $Installer.IArg
					}
					Default {
						# wrong file type
						Write-Host "!! Error '$($Installer.File)', Wrong File Type" -ForegroundColor Red
						return
					}
				}
				# only check if the install worked if skip check if false
				if ($Installer.SkipCheck -eq $false) {
					# check if the software is installed
					if ((Test-IsInstalled -Name $Installer.Name) -eq $true) {
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
			if ((Test-IsPnpUtilDriverInstalled -Drivers $PnpUtilDrivers -Name $Driver.Name) -eq $false) {
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

function Get-ComputerDistinguishedName {
	param (
		[Parameter(Mandatory=$true)][string]$ComputerName
	)
	# create an AD entry object
	$ADEntry = New-Object System.DirectoryServices.DirectoryEntry("GC://DC=va,DC=gov")
	# create an AD search object
	$ADSearcher = New-Object System.DirectoryServices.DirectorySearcher($ADEntry)
	# create our filter
	$ADSearcher.Filter = "(&(objectCategory=computer)(name=$($ComputerName)))"
	# search for our computer
	$ComputerObject = $ADSearcher.FindOne()
	# check if we found a computer
	if ($null -eq $ComputerObject) {
		# a computer was not found, return null
		return $null
	}
	else {
		# otherwise, return our computer's distinguished name
		return $ComputerObject.Properties["distinguishedname"]
	}
}

function Test-IsStagingOU {
	param (
		[Parameter(Mandatory=$true)][string]$ComputerDN
	)
	# the group we are looking for
	$StagingGroup = 'OU=OSD Staging'
	# check if the computer is in the staging group
	if (($ComputerDN.Contains($StagingGroup)) -eq $true) {
		# computer is still in the staging group
		return $true
	}
	else {
		# computer is not in the staging group
		return $false
	}
}

function Move-ComputerWithLdap {
	param (
		[Parameter(Mandatory=$true)][string]$ComputerName
	)
	# get our computer's distinguished name
	$ComputerDN = Get-ComputerDistinguishedName($ComputerName)
	# check if we found our computer
	if ($null -eq $ComputerDN) {
		Write-Host "Unable to find computer in AD" -ForegroundColor Red
	}
	else {
		# check if the computer is in the staging group
		if ((Test-IsStagingOU($ComputerDN)) -eq $true) {
			# still in staging
			Update-Progress -Status "Attempting to move computer in Active Directory" -Echo $true
			# get our target OU
			$TargetOU = $null
			# get our OU based on our computer type
			switch ($ComputerType) {
				1 {
					# set our OU to the va.gov desktop OU
					$TargetOU = $DesktopOU
				}
				2 {
					# set our OU to the va.gov laptop OU
					$TargetOU = $LaptopOU
				}
				default {
					# if we can't determine the computer type, we can't set the target OU, so return
					Write-Host ".------------------------------------------------------------------." -ForegroundColor Red
					Write-Host "| Error: Unable to determine computer type. Computer was NOT moved |" -ForegroundColor Red
					Write-Host "'------------------------------------------------------------------'" -ForegroundColor Red
					return
				}
			}
			# get the computer entry object from the distinguished name
			$ComputerEntry = [ADSI]"LDAP://$($ComputerDN)"
			# get our OU entry object
			$TargetEntry = [ADSI]"LDAP://$($TargetOU)"
			# move the computer to the target OU
			$ComputerEntry.MoveTo($TargetEntry.Path)
			# wait a short time for the move
			Start-Sleep -Seconds 2
			# get our computer's distinguished name, again
			$ComputerDN = Get-ComputerDistinguishedName($ComputerName)
			# verify if the computer was moved
			if ((Test-IsStagingOU($ComputerDN)) -eq $true) {
				# computer was not moved and is still in staging
				Write-Host "Failed to move computer in Active Directory" -ForegroundColor Red
			}
			else {
				# computer was moved out of the staging OU
				Write-Host "Moved computer '$($ComputerName)' to '$($TargetOU)'." -ForegroundColor Green
			}
		}
		else {
			# not in the staging OU
			Write-Host "Computer has already been moved out of the staging OU." -ForegroundColor Green
		}
	}
}

# change a computer's bios settings
function Update-BIOS {
	param (
		[Parameter(Mandatory=$true)][string]$Manufacturer,
		[Parameter(Mandatory=$true)][string]$ComputerType
	)

	# we will create a command based on the computer manufacturer
	$UpdateExe = $null
	$UpdateArgs = $null

	# check our computer type
	if ($ComputerType -notin 1, 2) {
		Write-Host "Update-BIOS: ComputerType: $($ComputerType) not found"
		# do nothing
		return $false
	}

	# bios config file path
	$BiosConfigFilePath = ''
	# set our command string based on our manufacturer and computer type
	switch ($Manufacturer.ToUpper()) {
		'DELL' {
			# create the command to set our asset tag number
			$UpdateExe = $Executables['DellAssetExe']
			# get our config path based on our computer type
			if ($ComputerType -eq 1) {
				$BiosConfigFilePath = $BiosFilePaths["DellDesktopBios"]
			}
			if ($ComputerType -eq 2) {
				$BiosConfigFilePath = $BiosFilePaths["DellLaptopBios"]
			}
			# set our argument using our file path
			$UpdateArgs = "--infile $($BiosConfigFilePath)"
		}
		'HP' {
			# get our bios update utility
			$UpdateExe = $Executables['HpAssetExe']
			# get our config path based on our computer type
			if ($ComputerType -eq 1) {
				$BiosConfigFilePath = $BiosFilePaths["HpDesktopBios"]
			}
			if ($ComputerType -eq 2) {
				$BiosConfigFilePath = $BiosFilePaths["HpLaptopBios"]
			}
			# set our argument using our file path
			$UpdateArgs = "/set:$($BiosConfigFilePath)"
		}
		'LENOVO' {
			# create the command to set our asset tag number
			$UpdateExe = $Executables['CmdExe']
			# get our config path based on our computer type
			if ($ComputerType -eq 1) {
				$BiosConfigFilePath = $BiosFilePaths["LenovoDesktopBios"]
			}
			if ($ComputerType -eq 2) {
				$BiosConfigFilePath = $BiosFilePaths["LenovoLaptopBios"]
			}
			# set our argument using our file path
			$UpdateArgs = "/c $($Executables['LenovoBiosHta']) `"file=$($BiosConfigFilePath)`" `"log=$($TempFolder)`""
		}
		Default {
			# computer manufacturer not found
			Write-Host "Update-BIOS: Manufacturer: $($Manufacturer) not found"
			# do nothing
			return $false
		}
	}

	# check if either of our command strings are null
	if (($null -eq $UpdateExe) -or ($null -eq $UpdateArgs)) {
		# one of our strings is null
		Write-Host "Update-BIOS: UpdateExe or UpdateArgs is null"
		# do nothing
		return $false
	}

	# run the command
	$ReturnCode = Invoke-Process -Executable $UpdateExe -Arguments $UpdateArgs -ReturnExitCode $true
	# check if we got a return code
	if ($null -ne $ReturnCode) {
		if ($ReturnCode -eq 0) {
			# bios update program exited without errors
			return $true
		}
		else {
			# bios update program exited with errors
			return $false
		}
	}
	else {
		# return code was null
		return $false
	}
}

# update our computer's bios asset number
function Update-AssetTag {
	# parameters
	param (
		[Parameter(Mandatory=$true)][int]$AssetNumber,
		[Parameter(Mandatory=$true)][string]$Manufacturer
	)
	# we will create a command based on the computer manufacturer
	$AssetExe = $null
	$AssetArg = $null

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
			return $false
		}
	}
	# if our argument string is null or empty, return
	if (($null -eq $AssetArg) -or ($AssetArg -eq "")) {
		return $false
	}
	# run the command
	Invoke-Process -Executable $AssetExe -Arguments $AssetArg
	# return true if we ran our command
	return $true
}

# get our asset number from our computer name
function Get-AssetTag {
	# parameters
	param (
		[Parameter(Mandatory=$true)][string]$Name
	)
	# get the asset number from our computer name
	# match five digits at the end of the line
	$Found = $Name -match '[0-9]{5,6}$'
	# check if we have a match
	if ($Found -eq $false) {
		# return null if not found
		return $null
	}
	# get the first match
	$Number = $matches[0]
	# check if our asset tag is empty
	if ($Number -eq "") {
		# return null if our number is empty
		return $null
	}
	# check if our asset tag is the correct length
	if (($Number.Length -ge $AssetTagMinLength) -and ($Number.Length -le $AssetTagMaxLength)) {
		# return our asset number
		return $Number
	}
	else {
		# return null if not the correct length
		return $null
	}
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
	if ((Test-Path -Path $Path -Type Container) -eq $false) {
		# if the path is missing, then create it
		New-Item -Path $Path | Out-Null
	}

	# create the key if missing and set the value
	Set-ItemProperty -Path $Path -Name $KeyName -Value $Value -Type $KeyType | Out-Null
}

# add registry value to stop downloading manufacturers' apps for installed devices
function Set-DisableAppsForDevices {
	# the registry values
	$RegPath = 'HKCU:\Software\Policies\Microsoft\Windows\DeviceInstall'
	$RegKeyName = 'AllowOSManagedDriverInstallationToUI'
	$RegKeyValue = 0
	# add the key
	Add-RegistryKey -Path $RegPath -KeyName $RegKeyName -Value $RegKeyValue -KeyType DWord

	# the registry values
	$RegPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Device Installer'
	$RegKeyName = 'DisableCoInstallers'
	$RegKeyValue = 1
	# add the key
	Add-RegistryKey -Path $RegPath -KeyName $RegKeyName -Value $RegKeyValue -KeyType DWord
}

# reboot the computer
function Start-ComputerRestart {
	param (
		[int]$TimeOut = 60,
		[bool]$Firmware = $false,
		[bool]$Abort = $false
	)
	$ShutdownExe = 'C:\Windows\System32\shutdown.exe'
	$RebootMessage = "Rebooting in $($RebootTimeout) seconds"
	$RebootArg = "/r /f /t $($RebootTimeout) /c `"$($RebootMessage)`""
	# abort a reboot
	if ($Abort -eq $true) {
		$RebootMessage = "Aborting reboot"
		$RebootArg = '/a'
	}
	# reboot to firmware with a timeout
	elseif (($Firmware -eq $true) -and ($TimeOut -gt 0)) {
		$RebootMessage = "Rebooting to Firmware (BIOS/UEFI) in $($TimeOut) seconds"
		$RebootArg = "/r /f /fw /t $($TimeOut) /c `"$($RebootMessage)`""
	}
	# immediately reboot to firmware
	elseif (($Firmware -eq $true) -and ($TimeOut -le 0)) {
		$RebootMessage = 'Rebooting to Firmware (BIOS/UEFI) now'
		$RebootArg = "/r /f /fw /t 0 /c `"$($RebootMessage)`""
	}
	# reboot normally with a timeout
	elseif (($Firmware -eq $false) -and ($TimeOut -gt 0)) {
		$RebootMessage = "Rebooting in $($TimeOut) seconds"
		$RebootArg = "/r /f /t $($TimeOut) /c `"$($RebootMessage)`""
	}
	# immediately reboot normally
	elseif (($Firmware -eq $false) -and ($TimeOut -le 0)) {
		$RebootMessage = 'Rebooting now'
		$RebootArg = "/r /f /t 0 /c `"$($RebootMessage)`""
	}
	# something else happened, don't reboot
	else {
		Write-Host 'Start-ComputerRestart: Invalid reboot arguments' -ForegroundColor Red
	}
	# run the reboot command
	$ReturnCode = Invoke-Process -Executable $ShutdownExe -Arguments $RebootArg -ReturnExitCode $true
	if ($ReturnCode -eq 203) {
		Write-Host "Error: 203 returned from shutdown.exe, trying again" -ForegroundColor Magenta
		Start-ComputerRestart -TimeOut $TimeOut -Firmware $Firmware -Abort $Abort
	}
}

# check if a config value is null
function Test-ConfigValueNull {
	param (
		[Parameter(Mandatory=$true)][hashtable]$Hashtable,
		[Parameter(Mandatory=$true)][string]$Key
	)
	# get our value
	$Value = $Hashtable[$Key]

	# check if the value is null
	if (($null -eq $Value) -or ($Value -eq "")) {
		# if the value is null, write an error message and exit
		Write-Host "ERROR: Config '$($Key)' value is null or empty." -ForegroundColor Red
		exit
	}
	# otherwise, return the value
	$Value
}

# check if all our baseline applications are installed
function Test-Baseline {
	param (
		[Parameter(Mandatory=$true)][hashtable]$BaselineHashtable,
		[Parameter(Mandatory=$true)][int]$ComputerType
	)
	# update our progress
	Update-Progress -Status "Checking Baseline" -Echo $true -Color Yellow
	# check if our computer is a desktop, set our max number of missing packages
	if ($ComputerType -eq 1) {
		# desktops will allow an extra failure due to cisco anyconnect not being installed on them
		$MaxFailCount = 3
	}
	else {
		# otherwise, the max will be two
		$MaxFailCount = 2
	}
	# keep track of failures
	$SoftwareNotFoundCount = 0
	# loop through the hashtable's keys
	foreach ($Key in $BaselineHashtable.Keys) {
		# loop through the hashtable's value
		foreach ($Value in $BaselineHashtable[$Key]) {
			# check if each software package is installed
			$Result = Test-IsInstalled -Name $Value
			# add our result to the software name line
			if ($Result -eq $true) {
				# software found
				Write-Host "  Installed: $($Value)" -ForegroundColor Green
			}
			else {
				# software not found
				Write-Host "  Not Found: $($Value)" -ForegroundColor Red
				# update our count
				$SoftwareNotFoundCount += 1
			}
		}
	}

	# check our fail count
	if ($SoftwareNotFoundCount -lt $MaxFailCount) {
		# if less than our max, return true
		return $true
	}
	else {
		# otherwise, return false
		return $false
	}
}

# try to parse a string into an integer
function Test-ParseInt {
	param (
		[Parameter(Mandatory=$true)][string]$Name,
		[Parameter(Mandatory=$true)][string]$InputString
	)

	# our output int
	$ReturnInt = [int]::MinValue
	# parse our int
	$ParseResult = [int]::TryParse($InputString, [ref]$ReturnInt)
	# check our parse result
	if ($ParseResult -eq $false) {
		# write the error
		Write-Host "ERROR: Failed to parse integer for $($Name) from value '$($InputString)'." -ForegroundColor Red
		# exit the script
		exit
	}
	return $ReturnInt
}

# write our banner from an array of lines and colors
function Write-Banner {
	param (
		[Parameter(Mandatory=$true)][array]$InputArray
	)
	# keys
	$TextKey = "Text"
	$ColorKey = "ColorName"

	# loop through our array
	foreach ($Item in $InputArray) {
		# check if we have a text key in our hashtable
		if ($Item.ContainsKey($TextKey) -eq $true) {
			# get our text from the item
			$Text = $Item[$TextKey]
			# check if our text is a string
			if ($Text -is [string])
			{
				# our color
				$Color = $null
				
				# check if we have a color key in our hashtable
				if ($Item.ContainsKey($ColorKey) -eq $true) {	
					# try to get our color from the item
					$ColorParseResult = [Enum]::TryParse([System.ConsoleColor], $Item[$ColorKey], [ref]$Color)
					# check if our color parse failed
					if ($ColorParseResult -eq $false) {
						# set our color to null
						$Color = $null	
					}
				}

				# check if we have a color
				if ($null -eq $Color) {
					# write our text without a foreground color
					Write-Host $Text
				}
				else {
					# otherwise, write our text with our foreground color
					Write-Host $Text -ForegroundColor $Color
				}
			}
		}
	}
}
#endregion FUNCTIONS

#region CONFIG
# ------------------------------------------------------- #
#                         CONFIG                          #
# ------------------------------------------------------- #

# begin reading config and getting base system information
Write-Host "Initializing, please wait..." -ForegroundColor DarkGray

# our json config file
$JsonConfigFileName = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'

# check if our config file exists
if ((Test-Path -Path $JsonConfigFileName) -eq $false)
{
	# if we are unable to read the file, write an error message and exit
	Write-Host "ERROR: JSON config file '$($JsonConfigFileName)' not found." -ForegroundColor Red
	exit
}

# read our data from the json config file
$JsonConfigHashtable = Get-Content $JsonConfigFileName | ConvertFrom-Json -AsHashtable

# check if our hashtable is null
if ($null -eq $JsonConfigHashtable) {
	# hashtable is null, exit
	Write-Host "ERROR: No config data read from JSON file '$($JsonConfigFileName)'." -ForegroundColor Red
	exit
}

# banner array
$Banner = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "Banner"

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

# file name for our baseline check file
$BaselineFileName = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "BaselineFileName"

# paths for our bios asset update executables
$DellAssetExePath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "DellAssetExePath"
$HpAssetExePath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "HpAssetExePath"
$LenovoAssetExePath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoAssetExePath"

# paths for our bios update files
$DellDesktopBiosPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "DellDesktopBiosPath"
$DellLaptopBiosPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "DellLaptopBiosPath"
$HpDesktopBiosPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "HpDesktopBiosPath"
$HpLaptopBiosPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "HpLaptopBiosPath"
$LenovoBiosToolPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoBiosToolPath"
$LenovoDesktopBiosPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoDesktopBiosPath"
$LenovoLaptopBiosPath = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LenovoLaptopBiosPath"

# AD OUs for our computers
$DesktopOU = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "DesktopOU"
$LaptopOU = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "LaptopOU"

# asset tag length
$AssetTagMinLengthString = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "AssetTagMinLength"
$AssetTagMinLength = Test-ParseInt -Name "AssetTagMinLength" -InputString $AssetTagMinLengthString
$AssetTagMaxLengthString = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "AssetTagMaxLength"
$AssetTagMaxLength = Test-ParseInt -Name "AssetTagMaxLength" -InputString $AssetTagMaxLengthString
# reboot variables in seconds
$RebootTimeoutString = Test-ConfigValueNull -Hashtable $JsonConfigHashtable -Key "RebootTimeout"
$RebootTimeout = Test-ParseInt -Name "RebootTimeout" -InputString $RebootTimeoutString

# config was loaded from the json file
Write-Host "Config loaded." -ForegroundColor DarkGray
#endregion CONFIG

#region PROPERTIES
# ------------------------------------------------------- #
#                       PROPERTIES                        #
# ------------------------------------------------------- #

# transcript file
$TranscriptFile = "$($TempFolder)\PostImageSetup$($Version)-Transcript"
$TranscriptExtension = '.txt'

# file to read the work item data from
$JsonFilePath = Join-Path -Path $PSScriptRoot -ChildPath $JsonFileName

# file to read the work item data from
$BaselineFilePath = Join-Path -Path $PSScriptRoot -ChildPath $BaselineFileName
# check if our baseline json file exists
if ((Test-Path -Path $BaselineFilePath) -eq $true) {
	# get our data from our json file
	$BaselineJsonData = [hashtable](Get-BaselineItemsFromJson -JsonFilePath $BaselineFilePath)
}
else {
	# write an error
	Write-Host "ERROR: Baseline JSON file not found. Exiting." -ForegroundColor Red
	# exit the script
	exit
}

# read cim data
Write-Host "Getting computer information..." -ForegroundColor DarkGray

# get computer name
$EnvComputerName = $env:ComputerName
# get computer type: 1 = desktop, 2 = laptop, 3 = workstation
$ComputerType = (Get-CimInstance -ClassName Win32_ComputerSystem -Property PCSystemType).PCSystemType
# workstations will be considered the same as desktops
# so if our computer type is 3
if ($ComputerType -eq 3) {
	# set it to 1
	$ComputerType = 1
}
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
Start-Sleep -Seconds 2

# clear the screen
Clear-Host
#endregion PROPERTIES

#region MAIN SCRIPT
# ------------------------------------------------------- #
#                       MAIN SCRIPT                       #
# ------------------------------------------------------- #

# draw our banner
Write-Banner -InputArray $Banner

# check if the temp directory exists
if ((Test-Path -Path $TempFolder) -eq $false) {
	# if not found, create it
	New-Item -Path $TempFolder -ItemType "directory" | Out-Null
}

# start the transcript
$TranscriptFile = Get-TranscriptFile
# check that we got a filename
if ($null -eq $TranscriptFile) {
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

# check our baseline software
$BaselineResult = Test-Baseline -BaselineHashtable $BaselineJsonData -ComputerType $ComputerType
# stop the script if our baseline check has failed
if ($BaselineResult -eq $false) {
	# write an error
	Write-Host ".-----------------------------------------------------------." -ForegroundColor Red
	Write-Host "| Baseline check has FAILED. Use dBAT to scan the computer. |" -ForegroundColor Red
	Write-Host "| Install missing packages or re-image the computer.        |" -ForegroundColor Red
	Write-Host "| Script cannot continue. Exiting.                          |" -ForegroundColor Red
	Write-Host "'-----------------------------------------------------------'" -ForegroundColor Red
	# change our location
	Set-Location -Path $TempFolder
	# stop the transcript
	Stop-Transcript | Out-Null
	# exit the script
	exit
}

# map the drive for our script root
Update-Progress -Status "Mapping Drive" -Echo $true
New-PSDrive -Name $MapDriveLetter -Root $MapDriveFolder -Persist -PSProvider "FileSystem" -ErrorAction SilentlyContinue | Out-Null

# mapped install folder
$MappedInstall = Join-Path -Path "$($MapDriveLetter):" -ChildPath $InstallFolder

# executable location hashtable
$Executables = @{
	"CmdExe"		 = Join-Path -Path $SystemFolder -ChildPath "cmd.exe"
	"WusaExe"		 = Join-Path -Path $SystemFolder -ChildPath "wusa.exe"
	"PnpUtilExe"	 = Join-Path -Path $SystemFolder -ChildPath "pnputil.exe"
	"MsiexecExe"	 = Join-Path -Path $SystemFolder -ChildPath "msiexec.exe"
	"PowercfgExe"	 = Join-Path -Path $SystemFolder -ChildPath "powercfg.exe"
	"GpupdateExe"	 = Join-Path -Path $SystemFolder -ChildPath "gpupdate.exe"
	"GpresultExe"	 = Join-Path -Path $SystemFolder -ChildPath "gpresult.exe"
	"DellAssetExe"	 = Join-Path -Path $MappedInstall -ChildPath $DellAssetExePath
	"HpAssetExe"	 = Join-Path -Path $MappedInstall -ChildPath $HpAssetExePath
	"LenovoAssetExe" = Join-Path -Path $MappedInstall -ChildPath $LenovoAssetExePath
	"LenovoBiosHta"  = Join-Path -Path $MappedInstall -ChildPath $LenovoBiosToolPath
}

# bios file path hashtable
$BiosFilePaths = @{
	"DellDesktopBios"   = Join-Path -Path $MappedInstall -ChildPath $DellDesktopBiosPath
	"DellLaptopBios"    = Join-Path -Path $MappedInstall -ChildPath $DellLaptopBiosPath
	"HpDesktopBios"     = Join-Path -Path $MappedInstall -ChildPath $HpDesktopBiosPath
	"HpLaptopBios"      = Join-Path -Path $MappedInstall -ChildPath $HpLaptopBiosPath
	"LenovoDesktopBios" = Join-Path -Path $MappedInstall -ChildPath $LenovoDesktopBiosPath
	"LenovoLaptopBios"  = Join-Path -Path $MappedInstall -ChildPath $LenovoLaptopBiosPath
}

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
if ((Test-Path -Path "$($MapDriveLetter):\") -eq $false) {
	# clear the progress bar
	Write-Progress -Completed -Status "Error"
	# write an error
	$ErrorString = "Install drive was not mapped. Unable to continue."
	Write-Error $ErrorString
	Write-Host $ErrorString -ForegroundColor Red
	# exit the script
	exit
}

# is the computer an AT Hybrid computer
$IsATHybrid = $false

# check if this computer is an AT Hybrid computer
if ($EnvComputerName -like '*-SPATH*') { $IsATHybrid = $true }

# only do this for a non-ath computer
if ($IsATHybrid -eq $false) {
	# add a registry value and set it's value
	Set-DisableAppsForDevices
}

# boolean to determine if we will update our asset tag
$UpdateTag = $false

# get our asset tag number from our computer name
Update-Progress -Status "Getting BIOS Asset Tag" -Echo $true
$AssetNumber = Get-AssetTag -Name $EnvComputerName
# write our asset number
Write-Host "EE: $($AssetNumber)" -ForegroundColor White

# if the asset tag is empty
if ($ComputerAssetTag -eq "") {
	# update our asset tag
	$UpdateTag = $true
}
else {
	# check if our computer's asset tag is correct
	if ($null -eq $AssetNumber) {
		# if not found, update our asset tag
		$UpdateTag = $true
	}
	else {
		# check if our asset tag matches what it should be
		if ($AssetNumber -eq $ComputerAssetTag) {
			# the tags match, don't update our tag
			$UpdateTag = $false
		}
		else {
			# the tags don't match, update our tag
			$UpdateTag = $true
		}
	}
}

# check if we need to update our tag
if ($UpdateTag -eq $false) {
	# asset tag already set
	Write-Host "BIOS Asset Tag Found" -ForegroundColor Cyan
}
else {
	# set our asset tag if it is not null
	if ($null -ne $AssetNumber) {
		# set our asset number
		Update-Progress -Status "Setting BIOS Asset Tag" -Echo $true
		$Result = Update-AssetTag -AssetNumber $AssetNumber -Manufacturer $ComputerManufacturer
		# write the outcome of setting our asset tag
		if ($Result -eq $true) {
			Write-Host "BIOS Asset Tag Set" -ForegroundColor Green
		}
		else {
			Write-Host "BIOS Asset Tag NOT Set" -ForegroundColor Red
		}
	}
}

# update our bios settings
Update-Progress -Status "Updating BIOS Settings" -Echo $true
$BiosUpdateResult = Update-BIOS -Manufacturer $ComputerManufacturer -ComputerType $ComputerType
if ($BiosUpdateResult -eq $true) {
	Write-Host "BIOS Settings Updated" -ForegroundColor Green
}
else {
	Write-Host "BIOS Settings NOT Updated" -ForegroundColor Red
}

# check if this computer is still in the staging group in active directory
Update-Progress -Status "Checking Computer's OU" -Echo $true
# try to move the computer in AD
Move-ComputerWithLdap($EnvComputerName)

# only do this for an ath computer
if ($IsATHybrid -eq $true) {
	Write-Host ".--------------------------------------------------------." -ForegroundColor Magenta
	Write-Host "| Skipping driver and software installs for ATH Computer |" -ForegroundColor Magenta
	Write-Host "'--------------------------------------------------------'" -ForegroundColor Magenta
}

# all work to be done will go into this array
	$WorkItemJsonParameters = @{
		JsonFilePath	= $JsonFilePath
		ExeHashtable	= $Executables
		InstallRootPath	= $MappedInstall
		ComputerType	= $ComputerType
	}
	$WorkArray += Get-WorkItemsFromJson @WorkItemJsonParameters

# get total progress count
$ProgressTotal = $WorkArray.Count

# install each exe in our array
$WorkArray.ForEach({
	# boolean to skip the install or driver
	$SkipWorkItem = $false
	# check if this computer is an ATH computer
	if ($IsATHybrid -eq $true) {
		# get our item's type
		$WorkItemType = $_.GetType()
		# check if this is an installer or driver
		if ($WorkItemType -in @([InstallParameter],[DriverParameter])) {
			# skip this item for ATH computers
			$SkipWorkItem = $true
		}
	}
	if ($SkipWorkItem -eq $false) {
		# start the work item
		Install-WorkItem -WorkObject $_; Start-Sleep -Milliseconds 500
	}
})

# registry path and value name
$LastLoggedInUserRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$LastLoggedInUserPropertyName = 'dontdisplaylastusername'
# get our current value
$CurrentLastLoggedInUserValue = Get-ItemPropertyValue -Path $LastLoggedInUserRegistryPath `
													  -Name $LastLoggedInUserPropertyName `
													  -ErrorAction SilentlyContinue
# check if our value is not one
if (($null -eq $CurrentLastLoggedInUserValue) -or ($CurrentLastLoggedInUserValue -ne 1)) {
	# changing registry value to hide last logged in user
	Set-ItemProperty -Path $LastLoggedInUserRegistryPath `
					 -Name $LastLoggedInUserPropertyName `
					 -Value 1 -Force -ErrorAction SilentlyContinue
}

# run gpupdate
Update-Progress -Status "Running GP Update" -Echo $true
& $Executables['CmdExe'] /c "ECHO N | $($Executables['GpupdateExe']) /force /wait:180" | Out-Null
Update-Progress -Status "GP Update Finished" -Echo $true

# anyconnect software name
$AnyConnect = 'Cisco Secure Client - AnyConnect VPN'
# check if this is a laptop and if anyconnect is installed
if (($ComputerType -eq 2) -and ((Test-IsInstalled -Name $AnyConnect) -eq $false)) {
	# if this is a laptop and the software is not found, alert the user
	Write-Host "************************************************************************************" -ForegroundColor Red
	Write-Host "* Warning, '$($AnyConnect)' NOT installed on this laptop! *" -ForegroundColor Red
	Write-Host "************************************************************************************`n`n" -ForegroundColor Red
}

# change out of our mapped drive
Set-Location $SystemFolder

# remove our temp drive
Update-Progress -Status "Removing Mapped Drive" -Echo $true
Remove-PSDrive -Name $MapDriveLetter -Force | Out-Null

# installs done
Update-Progress -Status "Done" -Echo $true

# stop the transcript
Stop-Transcript | Out-Null

# reboot the computer
Start-ComputerRestart -TimeOut $RebootTimeout -Firmware $false
Write-Host "Rebooting in $($RebootTimeout) seconds" -ForegroundColor Green

# ask the user if they want to stop the reboot
$LoopControl = $true
while ($LoopControl) {
	Write-Host "Reboot Commands:`nA: Abort Reboot`nN: Close This Window`nY: Reboot Now"
	$Result = Read-Host -Prompt "Reboot Command: [a/n/y]"
	switch -Exact ($Result.ToUpper()) {
		"A" {
			# abort the shutdown and end the script
			Start-ComputerRestart -Abort $true
			Write-Host "Reboot Aborted" -ForegroundColor Red
			$LoopControl = $false
		}
		"N" {
			# end the script
			Write-Host "Continuing With Timed Reboot" -ForegroundColor Yellow
			$LoopControl = $false
		}
		"Y" {
			# abort the current shutdown
			Start-ComputerRestart -Abort $true
			# reboot now and end the script
			Write-Host "Rebooting Now" -ForegroundColor Green
			# stop our loop and reboot
			$LoopControl = $false
			Start-ComputerRestart -TimeOut 0 -Firmware $false
		}
		Default {
			Write-Host "Invalid Response" -ForegroundColor Red
		}
	}
}
#endregion MAIN SCRIPT
