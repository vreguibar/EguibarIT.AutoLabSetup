<#
    .Script prupose
        Copy requested files and prepare the computer for automated process
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

[CmdletBinding()]
Param(

    # Param1 VM new name
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        Position = 0)]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(0, 20)]
    [string]
    $vmName
)

$VerbosePreference = 'Continue'

$Splat = [hashtable]::New()

# Change Execution Policy
#Set-ExecutionPolicy -ExecutionPolicy Unrestricted

# Create a new Remote Session
# VM always use the same PWD. Change this for PROD.
$password = ConvertTo-SecureString 'P@ssword 123456' -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential ('Administrator', $password)


try {
    # Check iv is a VM and is running on this host
    $Vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue

    If ($VM) {
        # The computer is a VM and is running on this host
        # PowerShell Direct can be used
        $s = New-PSSession -VMName $vmName -Credential $Creds -ErrorAction Stop
    } else {
        # Computer running on other Hyper-V. PowerShell direct cannot be used
        # Normal PsSession used instead.
        $s = New-PSSession -ComputerName $vmName -Credential $Creds -ErrorAction Stop
    }

    Write-Verbose -Message ('Successfully created a session to {0}' -f $vmName)
} catch {
    Write-Error -Message ('Failed to create a session to {0}. Error: {1}' -f $vmName, $_)
    return
}




$ScriptBlock = {

    # Create New Local Administrator
    New-LocalUser 'TheUgly' -Password $Using:Password -FullName 'TheUgly' -Description 'New local admin'
    Add-LocalGroupMember -Group 'Administrators' -Member 'TheUgly'




    # Create Folder where to store all Delegation Model scripts & files
    New-Item -ItemType Directory -Force -Path 'C:\PsScripts'



    ###############################################################################
    # START CORE configuration
    ###############################################################################

    # Configure Execution Policy
    Set-ExecutionPolicy -ExecutionPolicy unrestricted -Force

    # Configure Display Resolution
    Set-DisplayResolution -Width 1920 -Height 1080 -Force

    # Make Powershell default shell
    $regkeypath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (-not(Get-ItemProperty -Path $regkeypath).Shell) {
        New-ItemProperty -Path $regkeypath -Name 'Shell' -PropertyType String
    }
    #Set-ItemProperty -Path $regkeyPath -Name 'Shell' -Value 'CMD.exe /c "Start SConfig && Start CMD.exe && Start pwsh.exe"'
    Set-ItemProperty -Path $regkeyPath -Name 'Shell' -Value 'pwsh.exe'

    # Enable PowerShell Remoting
    #Enable-PSRemoting -SkipNetworkProfileCheck -Force
    #Set-WSManQuickConfig -Force

    # Ensure Network Profile is PRIVATE
    Set-NetConnectionProfile -NetworkCategory Private

    # Set the home location setting to Spain
    Set-WinHomeLocation -GeoId 217

    # Sets the system locale for the current computer
    Set-WinSystemLocale -SystemLocale en-US

    # Sets the default input method override for the current user account.
    Set-WinDefaultInputMethodOverride -InputTip '0409:0000040A'

    # Set the trustedhost list "DON'T DO THIS IN PRODUCTION!!!"
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

    ###############################################################################
    # END CORE configuration
    ###############################################################################



    ###############################################################################
    # START Set Autologon
    ###############################################################################
    # Set the Key and the permission to AutoLogon
    $regkeypath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ((Get-ItemProperty -Path $regkeypath).AutoAdminLogon -eq $null) {
        New-ItemProperty -Path $regkeypath -Name 'AutoAdminLogon' -PropertyType String
    }
    Set-ItemProperty -Path $regkeyPath -Name 'AutoAdminLogon' -Value 1

    # Set the User Name
    if ((Get-ItemProperty -Path $regkeypath).DefaultUserName -eq $null) {
        New-ItemProperty -Path $regkeypath -Name 'DefaultUserName' -PropertyType String
    }
    Set-ItemProperty -Path $regkeyPath -Name 'DefaultUserName' -Value 'TheUgly'

    # Set the Domain Name (Dot if local machine)
    if ((Get-ItemProperty -Path $regkeypath).DefaultDomainName -eq $null) {
        New-ItemProperty -Path $regkeypath -Name 'DefaultDomainName' -PropertyType String
    }
    Set-ItemProperty -Path $regkeyPath -Name 'DefaultDomainName' -Value '.'

    # Set the Password
    if ((Get-ItemProperty -Path $regkeypath).DefaultPassword -eq $null) {
        New-ItemProperty -Path $regkeypath -Name 'DefaultPassword' -PropertyType String
    }
    Set-ItemProperty -Path $regkeyPath -Name 'DefaultPassword' -Value 'P@ssword 123456'

    # Set the AutoLogon count to 1 time
    if ((Get-ItemProperty -Path $regkeypath).AutoLogonCount -eq $null) {
        New-ItemProperty -Path $regkeypath -Name 'AutoLogonCount' -PropertyType String
    }
    Set-ItemProperty -Path $regkeyPath -Name 'AutoLogonCount' -Value 1

    # Force Autologon
    if (-not(Get-ItemProperty -Path $regkeypath).ForceAutoLogon) {
        New-ItemProperty -Path $regkeypath -Name 'ForceAutoLogon' -PropertyType DWORD
    }
    Set-ItemProperty -Path $regkeyPath -Name 'ForceAutoLogon' -Value 1

    ###############################################################################
    # END Set Autologon
    ###############################################################################



    ###############################################################################
    # START CMD and SConfig at Logon (Scheduled Task)
    ###############################################################################

    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

    $TaskAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\CMD.exe' -Argument '/c "Start SConfig && Start CMD && Start PowerShell && Start pwsh.exe"' -WorkingDirectory $env:USERPROFILE

    $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn

    $Stset = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopOnIdleEnd -Compatibility Win8

    $Splat = @{
        Action      = $TaskAction
        Description = 'Execute CMD once logon for all users.'
        Force       = $true
        Principal   = $principal
        Settings    = $Stset
        TaskName    = 'CMD and SConfig'
        Trigger     = $TaskTrigger
        verbose     = $true
    }
    try {
        Register-ScheduledTask @Splat
    } Catch {
        Throw
    }

    ###############################################################################
    # END
    ###############################################################################



    ###############################################################################
    # START 1.BasicConfig.ps1 at next Logon (Scheduled Task)
    ###############################################################################

    If (($null -eq $DMscripts) -or ($DMscripts -eq '')) {
        $DMscripts = 'C:\PsScripts'
    }

    $File = '1-BasicConf.ps1'
    $NextFile = '{0}\{1}' -f $DMscripts, $file
    $UserID = 'TheUgly'
    $Arguments = '-NoLogo -NoExit -ExecutionPolicy Bypass -File {0}' -f $NextFile

    $principal = New-ScheduledTaskPrincipal -UserId $UserID -LogonType Interactive -RunLevel Highest

    $TaskAction = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' -Argument $Arguments

    $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserID

    $Stset = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopOnIdleEnd -Compatibility Win8

    $Splat = @{
        Action      = $TaskAction
        Description = 'Execute {0} on the next logon.' -f $file
        Force       = $true
        Principal   = $principal
        Settings    = $Stset
        TaskName    = $file
        Trigger     = $TaskTrigger
        Verbose     = $true
    }
    try {
        Register-ScheduledTask @Splat
    } catch {
        Throw
    }


    ###############################################################################
    # END
    ###############################################################################
} #end ScriptBlock
# Run remote scriptblock
try {
    Invoke-Command -Session $s -ScriptBlock $ScriptBlock -Verbose
} Catch {
    Throw
}

# Check PsSession. if different than Opened, re-create it.
$CurrentSession = Get-PSSession

If ($CurrentSession.State -ne 'Opened') {
    try {
        # Remove Broken session
        Remove-PSSession -Id $CurrentSession.Id -Verbose

        #Stablish New Session
        $s = New-PSSession -ComputerName $vmName -Credential $Creds -ErrorAction Stop
        Write-Verbose -Message ('Successfully created a session to {0}' -f $vmName)
    } catch {
        Write-Error -Message ('Failed to create a session to {0}. Error: {1}' -f $vmName, $_)
        return
    }
}

#### Copy-Item might throw an error (Exception setting "Attributes": "Cannot convert value "525344" to type "System.IO.FileAttributes")
### but will copy file. This is due file "flag" to sync with OneDrive.
# Provide the path where local files are located
$SourceFiles = 'C:\Users\RODRIGUEZEGUIBARVice\OneDrive - Vicente Rodriguez Eguibar\_Scripts\LabSetup\SourceDC\Modules\EguibarIT.AutoLabSetup'


#To $Scripts directory
$Splat = @{
    Destination = 'C:\PsScripts'
    ToSession   = $s
    Force       = $true
    Verbose     = $true
    ErrorAction = 'SilentlyContinue'
}
try {
    Copy-Item @Splat -Path $SourceFiles\1-BasicConf.ps1
    Copy-Item @Splat -Path $SourceFiles\2-AddFeatures.ps1
    Copy-Item @Splat -Path $SourceFiles\3-PromoteDC.ps1
    Copy-Item @Splat -Path $SourceFiles\4-ConfigureDom.ps1
    Copy-Item @Splat -Path $SourceFiles\5-PopulateDom.ps1
    Copy-Item @Splat -Path $SourceFiles\LAPS-Extension.ps1
    Copy-Item @Splat -Path $SourceFiles\Config.xml
    Copy-Item @Splat -Path $SourceFiles\SecTemp.inf
    Copy-Item @Splat -Path $SourceFiles\group.csv
    Copy-Item @Splat -Path $SourceFiles\Share.csv
    Copy-Item @Splat -Path $SourceFiles\StarWars-Users.csv
    Copy-Item @Splat -Path $SourceFiles\mngdsvcacc.csv
    Copy-Item @Splat -Path $SourceFiles\Set-AdPicture.ps1
    Copy-Item @Splat -Path $SourceFiles\Set-ADAllAdminPictures.ps1
    Copy-Item @Splat -Path $SourceFiles\SecTmpl -Recurse
    Copy-Item @Splat -Path $SourceFiles\Pic -Recurse

    #Provide the path where files are
    $SourceFiles = 'C:\Users\RODRIGUEZEGUIBARVice\OneDrive - Vicente Rodriguez Eguibar\_Scripts\LabSetup\SW'

    # Copy Lab.bgi and IPv6.ps1 files
    Copy-Item -ToSession $s -Path $SourceFiles\BGInfo\Lab.bgi -Destination 'C:\PsScripts' -Force -ErrorAction SilentlyContinue -Verbose
    Copy-Item -ToSession $s -Path $SourceFiles\BGInfo\IPv6.vbs -Destination 'C:\PsScripts' -Force -ErrorAction SilentlyContinue -Verbose

    Copy-Item -ToSession $s -Path $SourceFiles\AdmPwd.PS -Destination $env:ProgramFiles\WindowsPowerShell\Modules -Recurse -ErrorAction SilentlyContinue -Force -Verbose
    #To C:\Windows\PolicyDefinitions
    Copy-Item -ToSession $s -Path "$SourceFiles\Admin Templates\*" -Destination "$env:windir\PolicyDefinitions\" -Recurse -Container:$false -Force -ErrorAction SilentlyContinue
} catch {
    Throw
}






# Run remote scriptblock
Invoke-Command -Session $s -ScriptBlock {

    # Get all available disks
    Get-Disk
    $AllDisks = Get-Disk

    If ($AllDisks.Count -gt 1) {

        Write-Verbose -Message ('Initializing and formatting {0} disks' -f $AllDisks.Count)

        #iterate all disks
        Foreach ($Disk in $AllDisks) {
            # Exclude OS drive which is zero
            If ($Disk.Number -gt 0) {

                If ($disk.PartitionStyle -eq 'RAW') {
                    # Disk is RAW. Let's initialize it.
                    Initialize-Disk -Number $Disk.Number -PartitionStyle GPT -ErrorAction Ignore
                }

                Switch ($Disk.Number) {

                    1 {
                        Write-Verbose -Message 'Processing NTDS disk!'

                        # We know partition does not exist. Let's create it
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'N'

                        # Format
                        Format-Volume -DriveLetter 'N' -FileSystem NTFS -NewFileSystemLabel 'NTDS' -Force

                        New-Item -Path 'N:\NTDS' -ItemType Directory

                    }

                    2 {
                        Write-Verbose -Message 'Processing NTDS-Logs disk!'

                        # We know partition does not exist. Let's create it
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'L'

                        # Format
                        Format-Volume -DriveLetter 'L' -FileSystem NTFS -NewFileSystemLabel 'NTDS-Logs' -Force

                        New-Item -Path 'L:\NTDS-LOGs' -ItemType Directory

                    }

                    3 {
                        Write-Verbose -Message 'Processing SYSVOL disk!'

                        # We know partition does not exist. Let's create it
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'S'

                        # Format
                        Format-Volume -DriveLetter 'S' -FileSystem NTFS -NewFileSystemLabel 'SYSVOL' -Force

                        New-Item -Path 'S:\SYSVOL' -ItemType Directory

                    }

                    4 {
                        Write-Verbose -Message 'Processing TEMP disk! TEMP variable changed to point "T:\TEMP"'

                        # We know partition does not exist. Let's create it
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'T'

                        # Format
                        Format-Volume -DriveLetter 'T' -FileSystem NTFS -NewFileSystemLabel 'TEMP' -Force

                        New-Item -Path 'T:\TEMP' -ItemType Directory
                        $env:TEMP = 'T:\TEMP'
                        $env:TMP = 'T:\TEMP'

                    }

                    5 {
                        Write-Verbose -Message 'Processing Pagefile disk! Pagefile.sys moved to this drive with new size.'

                        # We know partition does not exist. Let's create it
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'P'

                        # Format
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

                        # We know partition does not exist. Let's create it
                        # Create New Partition
                        New-Partition -DiskNumber $Disk.Number -UseMaximumSize -DriveLetter 'E'

                        # Format
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

                        # Get the name of existing windows evtx from registry
                        $EvtLogFiles = (Get-ChildItem $regkeypath).PsChildName

                        # Get the other list of logs (Microsoft/Windows)
                        [System.Collections.ArrayList]$ArrayList = wevtutil enum-logs

                        Foreach ($item in $EvtLogFiles) {
                            $RegPath = ('{0}\{1}' -f $regkeypath, $item)
                            #Set-ItemProperty -Path ('{0}\{1}' -f $regkeyPath, $item) -Name 'File' -Value ('E:\WindowsLogs\{0}.evtx' -f $item)
                            if (-not(Test-RegistryValue -Path $RegPath -Value 'File')) {
                                New-ItemProperty -Path $RegPath -Name 'File' -PropertyType ExpandString
                            }
                            New-ItemProperty -Path $RegPath -Name 'AutoBackupLogFiles' -Value '1' -PropertyType 'DWord' -Force
                            New-ItemProperty -Path $RegPath -Name 'Flags' -Value '1' -PropertyType 'DWord' -Force

                            Set-ItemProperty -Path $RegPath -Name 'File' -Value ('E:\WindowsLogs\{0}.evtx' -f $item) -Force

                            Limit-EventLog -LogName $item -MaximumSize 4080MB -OverflowAction OverwriteAsNeeded

                            #remove Windows Logs (above) from the full list (Microsoft/Windows)
                            [Void]$ArrayList.Remove($Item)
                        }#end Foreach

                        [int]$i = 0

                        # Move remaining EVTX files to E:\ApplicationAndServicesLogs
                        Foreach ($Item in $ArrayList) {
                            $i ++

                            $parameters = @{
                                Activity         = 'Moving a total of {0} EventLog files' -f $ArrayList.Count
                                Status           = 'Moving file number {0}. ' -f $i
                                PercentComplete  = ($i / $ArrayList.Count) * 100
                                CurrentOperation = 'Processing file: {0}' -f $Item
                            }
                            Write-Progress @parameters

                            # Some logs has a / in the event log filename, this is an illegal character and is therefore replaces with %4
                            $EventLogFile = $Item -replace '/', '%4'

                            # Use wevutil to change the log path
                            Start-Process -Wait "$env:windir\System32\wevtutil.exe" -ArgumentList "sl `"$Item`" /lfn:`"E:\ApplicationAndServicesLogs\$EventLogFile.evtx`"" -NoNewWindow
                        } #end Foreach
                    }
                } #end Switch
            }
        } #end Foreach
    } #end If

    Write-Host 'Reboot???'
    #Restart-Computer -Force

} #end Invoke-Command
