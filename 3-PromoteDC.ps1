<#
    .Script prupose
        Promote this server to Domain Controller
    .NOTES
        Version:         1.0
        DateModified:    31/May/2017
        LasModifiedBy:   Vicente Rodriguez Eguibar
            vicente@eguibar.com
            Eguibar Information Technology S.L.
            http://www.eguibarit.com
    #>
<#
EGUIBARIT MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE OR NON-INFRINGEMENT. AS TO DOCUMENTS AND CODE, EGUIBARIT MAKES NO REPRESENTATION OR WARRANTY
THAT THE CONTENTS OF SUCH DOCUMENT OR CODE ARE FREE FROM ERROR OR SUITABLE FOR ANY PURPOSE; NOR THAT IMPLEMENTATION OF SUCH CONTENTS
WILL NOT INFRINGE ANY THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS., provided that
You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Code is embedded; and
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees,
that arise or result from the use or distribution of the Code.
This posting is provided "AS IS" with no warranties, and confers no rights.
Use of included script are subject to the terms specified at http://eguibarit.eu/copyright-notice-and-disclaimers/
#>
Start-Sleep -Seconds 5

# Clear any previous error
$error.clear()

# Get Folder where all Delegation Model scripts & files
$DMscripts = ('{0}\PsScripts' -f $env:SystemDrive)

# Logging all output
Start-Transcript -Path ('{0}\3-PromoteDC-{1}.log' -f $DMscripts, (Get-Date -Format 'dd-MMM-yyyy')) -NoClobber -Append -Force
#$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'
#$InformationPreference = 'Continue'
#$ErrorActionPreference = 'Continue'

<#
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_windows_powershell_compatibility?view=powershell-7.4
#
# Unless the module manifest indicates that module is compatible with PowerShell Core, modules
# in the %windir%\system32\WindowsPowerShell\v1.0\Modules folder are loaded in a background
# Windows PowerShell 5.1 process by Windows PowerShell Compatibility feature.
#
# o disable implicit import behavior of the Windows PowerShell Compatibility feature, use the DisableImplicitWinCompat
# setting in a PowerShell configuration file. This setting can be added to the powershell.config.json file
#
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_config?view=powershell-7.4

$ConfigPath = "$PSHOME\DisableWinCompat.powershell.config.json"
$ConfigJSON = ConvertTo-Json -InputObject @{
    'DisableImplicitWinCompat'                     = $true
    'Microsoft.PowerShell:ExecutionPolicy'         = 'RemoteSigned'
    'WindowsPowerShellCompatibilityModuleDenyList' = @(
        'PSScheduledJob',
        'BestPractices',
        'UpdateServices'
    )
}
$ConfigJSON | Out-File -Force $ConfigPath
#>

Write-Verbose -Message 'Import the Module: EguibarIT & ServerManager'
Import-Module -Name EguibarIT -Verbose:$false
Import-Module -Name ServerManager -Verbose:$false


# Read Config.xml file. The file should be located on the same directory as this script
try {
    # Check if Config.xml file is loaded. If not, proceed to load it.
    If (!(Test-Path -Path variable:confXML)) {
        # Check if the Config.xml file exist on the given path
        If (Test-Path -Path (Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve)) {
            #Open the configuration XML file
            $confXML = [xml](Get-Content (Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve))
        } #end if
    } #end if
} Catch {
    Get-CurrentErrorToDisplay -CurrentError $error[0]
} finally {
    # Validate configuration file
    if (-not (Test-Path -Path $DMscripts\Config.xml -PathType Leaf)) {
        throw 'Config.xml file not found'
    }
} #end try-catch-finally



# Check if DC is using Single Disk or multiple disks
Try {
    $DcDisks = $confXML.n.PCs.DC1.Disks
} Catch {
    Write-Verbose -Message 'This DC is configured to use single disk. All NTDS, Logs, SYSVOL, Temp, Pagefile and EventViewer files will reside on the same drive.'
} #end Try

If ($DcDisks) {

    Get-Disk
    $AllDisks = Get-Disk

    Write-Verbose -Message ('Initializing and formatting {0} disks' -f $AllDisks.Count)

    #iterate all disks
    Foreach ($Disk in $AllDisks) {
        # Exclude OS drive which is zero
        If ($Disk.Number -gt 0) {

            If ($disk.PartitionStyle -eq 'RAW') {
                # Disk is RAW. Let's initialize it.
                Initialize-Disk -Number $Disk.Number -PartitionStyle GPT -ErrorAction Ignore
            } #end If

            Switch ($Disk.Number) {

                1 {
                    Write-Verbose -Message 'Processing NTDS disk!'

                    If ($Disk.NumberOfPartitions -lt 1) {
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'N'
                    } #end If

                    Format-Volume -DriveLetter 'N' -FileSystem NTFS -NewFileSystemLabel 'NTDS' -Force

                    New-Item -Path 'N:\NTDS' -ItemType Directory
                }

                2 {
                    Write-Verbose -Message 'Processing NTDS-Logs disk!'

                    If ($Disk.NumberOfPartitions -lt 1) {
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'L'

                    } #end If
                    Format-Volume -DriveLetter 'L' -FileSystem NTFS -NewFileSystemLabel 'NTDS-Logs' -Force
                    New-Item -Path 'L:\NTDS-LOGs' -ItemType Directory
                }

                3 {
                    Write-Verbose -Message 'Processing SYSVOL disk!'

                    If ($Disk.NumberOfPartitions -lt 1) {
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'S'

                    } #end If
                    Format-Volume -DriveLetter 'S' -FileSystem NTFS -NewFileSystemLabel 'SYSVOL' -Force
                    New-Item -Path 'S:\SYSVOL' -ItemType Directory
                }

                4 {
                    Write-Verbose -Message 'Processing TEMP disk! TEMP variable changed to point "T:\TEMP"'

                    If ($Disk.NumberOfPartitions -lt 1) {
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'T'

                    } #end If
                    Format-Volume -DriveLetter 'T' -FileSystem NTFS -NewFileSystemLabel 'TEMP' -Force
                    New-Item -Path 'T:\TEMP' -ItemType Directory
                    $env:TEMP = 'T:\TEMP'
                    $env:TMP = 'T:\TEMP'
                }

                5 {
                    Write-Verbose -Message 'Processing Pagefile disk! Pagefile.sys moved to this drive with new size.'

                    If ($Disk.NumberOfPartitions -lt 1) {
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'P'

                    } #end If
                    Format-Volume -DriveLetter 'P' -FileSystem NTFS -NewFileSystemLabel 'Pagefile' -Force

                    # Disable AutomaticManagedPagefile
                    $YourSys = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue)
                    $YourSys | Set-CimInstance -Property @{ AutomaticManagedPageFile = $false } -ErrorAction Stop

                    # Remove Pagefile from Drive C
                    try {
                        $PageFile = (Get-CimInstance -ClassName Win32_PageFileSetting -Filter "SettingID='pagefile.sys @ $('C'):'" -ErrorAction Stop)
                        $null = ($PageFile | Remove-CimInstance -ErrorAction SilentlyContinue)
                    } catch {
                        Write-Verbose -Message 'Pagefile did not exist. who cares?'
                    } #end Try-Catch

                    try {
                        #Set Pagefile on P:
                        New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name = 'P:\pagefile.sys' }

                        # Configure Size
                        Get-CimInstance -ClassName Win32_PageFileSetting | Set-CimInstance -Property @{InitialSize = 4096; MaximumSize = 4096 }
                    } catch {
                        throw
                    }
                }

                6 {
                    Write-Verbose -Message 'Processing EvtLog disk! Log files will be moved to this location.'

                    If ($Disk.NumberOfPartitions -lt 1) {
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'E'

                    } #end If
                    Format-Volume -DriveLetter 'E' -FileSystem NTFS -NewFileSystemLabel 'EvtLog' -Force

                    New-Item -Path 'E:\WindowsLogs' -ItemType Directory
                    New-Item -Path 'E:\ApplicationAndServicesLogs' -ItemType Directory

                    # replicate permissions
                    $originalAcl = Get-Acl -Path "$env:SystemRoot\system32\winevt\Logs" -Audit

                    Set-Acl -Path 'E:\WindowsLogs' -AclObject $originalAcl -ClearCentralAccessPolicy
                    $targetAcl = Get-Acl -Path 'E:\WindowsLogs' -Audit
                    $targetAcl.SetOwner([System.Security.Principal.NTAccount]::new('SYSTEM'))

                    Set-Acl -Path 'E:\ApplicationAndServicesLogs' -AclObject $originalAcl -ClearCentralAccessPolicy
                    $targetAcl = Get-Acl -Path 'E:\ApplicationAndServicesLogs' -Audit
                    $targetAcl.SetOwner([System.Security.Principal.NTAccount]::new('SYSTEM'))

                    # Move log files to E drive
                    $regkeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog'
                    <#
                        $EvtLogFiles = @(
                            'Active Directory Web Services',
                            'Application',
                            'DFS Replication',
                            'Directory Service',
                            'DNS Server',
                            'HardwareEvents',
                            'Internet Explorer',
                            'Key Management Service',
                            'Security',
                            'System',
                            'Windows PowerShell'
                        )
                        #>

                    $EvtLogFiles = Get-ChildItem $regkeypath

                    Foreach ($item in $EvtLogFiles) {
                        #Set-ItemProperty -Path ('{0}\{1}' -f $regkeyPath, $item) -Name 'File' -Value ('E:\WindowsLogs\{0}.evtx' -f $item)
                        if (-not(Test-RegistryValue -Path $item.PSPath -Value 'File')) {
                            New-ItemProperty -Path $item.PSPath -Name 'File' -PropertyType ExpandString
                        }
                        Set-ItemProperty -Path $item.PSPath -Name 'File' -Value ('E:\WindowsLogs\{0}.evtx' -f $item.PSChildName)

                        Limit-EventLog -LogName $item.PSChildName -MaximumSize 4080MB -OverflowAction OverwriteAsNeeded
                    }#end Foreach
                }
            } #end Switch
        }
    }
} #end If




###############################################################################
# START Create unattended file
###############################################################################

# Promote domain.

Import-Module -Name ADDSDeployment -Force

# configure new forest
$parameters = @{
    DomainName                    = $confXML.N.PCs.DC1.DnsDomainName
    DomainNetbiosName             = $confXML.N.PCs.DC1.NetBIOSDomainName
    DomainMode                    = $confXML.N.DcPromo.DomainLevel
    ForestMode                    = $confXML.N.DcPromo.ForestLevel
    InstallDns                    = $true
    NoDnsOnNetwork                = $true
    NoRebootOnCompletion          = $true
    SafeModeAdministratorPassword = (ConvertTo-SecureString -String $confXML.N.DefaultPassword -AsPlainText -Force)
    Force                         = $true
}

if ($DcDisks -eq 'Multiple-Disks') {
    $parameters.Add('DatabasePath', 'N:\NTDS')
} else {
    $parameters.Add('DatabasePath', $confXML.N.DcPromo.NtdsPath)
}

if ($DcDisks -eq 'Multiple-Disks') {
    $parameters.Add('SysvolPath', 'S:\SYSVOL')
} else {
    $parameters.Add('SysvolPath', $confXML.N.DcPromo.SysvolPath)
}

if ($DcDisks -eq 'Multiple-Disks') {
    $parameters.Add('LogPath', 'L:\NTDS-LOGs')
} else {
    $parameters.Add('LogPath', $confXML.N.DcPromo.NtdsLogsPath)
}

Install-ADDSForest @parameters






###############################################################################
# START Set Default Domain
###############################################################################
# Set the Key and the permission to AutoLogon
$regkeypath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

# Set the Default Domain. If Standalone/Workgroup use the computername
if (-not(Test-RegistryValue -Path $regkeypath -Value 'DefaultDomainName')) {
    New-ItemProperty $regkeypath -Name 'DefaultDomainName' -type String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultDomainName' -Value $env:USERDOMAIN


###############################################################################
# END Set Default Domain
###############################################################################






###############################################################################
# START Set Autologon
###############################################################################
# Set the Key and the permission to AutoLogon
$regkeypath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (-not(Test-RegistryValue -Path $regkeypath -Value 'AutoAdminLogon')) {
    New-ItemProperty -Path $regkeypath -Name 'AutoAdminLogon' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'AutoAdminLogon' -Value 1

# Set the User Name
#
# We need to logon back with default Administrator. The NewAdmin (TheUgly)
# needs to be addedd to the "Domain Admins" group.
if (-not(Test-RegistryValue -Path $regkeypath -Value 'DefaultUserName')) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultUserName' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultUserName' -Value $confXML.N.Admin.Users.Admin.Name

# Set the Password
if (-not(Test-RegistryValue -Path $regkeypath -Value 'DefaultPassword')) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultPassword' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultPassword' -Value $confXML.N.DefaultPassword

# Set the Domain Name (Dot if local machine)
if ($null -eq (Get-ItemProperty -Path $regkeypath).DefaultDomainName) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultDomainName' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultDomainName' -Value $env:USERDNSDOMAIN

# Set the AutoLogon count to 1 time
if (-not(Test-RegistryValue -Path $regkeypath -Value 'AutoLogonCount')) {
    New-ItemProperty -Path $regkeypath -Name 'AutoLogonCount' -PropertyType DWORD
}
Set-ItemProperty -Path $regkeyPath -Name 'AutoLogonCount' -Value 1

# Force Autologon
if (-not(Test-RegistryValue -Path $regkeypath -Value 'ForceAutoLogon')) {
    New-ItemProperty -Path $regkeypath -Name 'ForceAutoLogon' -PropertyType DWORD
}
Set-ItemProperty -Path $regkeyPath -Name 'ForceAutoLogon' -Value 1

###############################################################################
# END Set Autologon
###############################################################################



###############################################################################
# START LAPS-Extension.ps1 at next Logon (Scheduled Task)
###############################################################################

If (($null -eq $DMscripts) -or ($DMscripts -eq '')) {
    $DMscripts = 'C:\PsScripts'
}


$UserID = $confXML.N.Admin.Users.Admin.Name

$principal = New-ScheduledTaskPrincipal -UserId $UserID -LogonType Interactive -RunLevel Highest

$TaskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserID

$Stset = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopOnIdleEnd


if ($confXML.N.Domains.Prod.CreateLAPS -eq 'True') {

    Write-Verbose -Message 'Next stage is LAPS-Extension. Preparing automated Script.'

    $File = 'LAPS-Extension.ps1'
    $NextFile = '{0}\{1}' -f $DMscripts, $file
    $Arguments = '-NoLogo -NoExit -ExecutionPolicy Bypass -File {0}' -f $NextFile

    $TaskAction = New-ScheduledTaskAction -Execute 'PowerShell' -Argument $Arguments

    $Splat = @{
        Action      = $TaskAction
        Description = 'Execute {0} on the next logon.' -f $file
        Force       = $true
        Principal   = $principal
        Settings    = $Stset
        TaskName    = $File
        Trigger     = $TaskTrigger
        Verbose     = $true
    }
    try {
        Register-ScheduledTask @Splat
    } catch {
        Throw
    }

} else {

    Write-Verbose -Message 'Next stage is 4-ConfigureDom. Preparing automated Script.'

    $File = '4-ConfigureDom.ps1'
    $NextFile = '{0}\{1}' -f $DMscripts, $file
    $Arguments = '-NoLogo -NoExit -ExecutionPolicy Bypass -File {0}' -f $NextFile

    $TaskAction = New-ScheduledTaskAction -Execute 'PowerShell' -Argument $Arguments

    $Splat = @{
        Action      = $TaskAction
        Description = 'Execute {0} on the next logon.' -f $file
        Force       = $true
        Principal   = $principal
        Settings    = $Stset
        TaskName    = $File
        Trigger     = $TaskTrigger
        Verbose     = $true
    }
    try {
        Register-ScheduledTask @Splat
    } catch {
        throw
    }

}
# Unregister previous scheduled task
Unregister-ScheduledTask -TaskName '3-PromoteDC.ps1' -Confirm:$false -Verbose

###############################################################################
# END
###############################################################################


Write-Verbose -Message '5 second pause to give Win a chance to catch up and reboot'
Start-Sleep -Seconds 5




# Stop Logging
Stop-Transcript


Write-Verbose -Message 'Reboot???'
Restart-Computer -Force
