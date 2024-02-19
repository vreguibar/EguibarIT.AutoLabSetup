<#
    .Script prupose
        Add features to this windows instance
        Configure DNS on this instance
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

Write-Verbose -Message 'Import the Module: EguibarIT & ServerManager'
Import-Module -Name EguibarIT -Verbose:$false
Import-Module -Name ServerManager -Verbose:$false

# Get Folder where all Delegation Model scripts & files
$DMscripts = ('{0}\PsScripts' -f $env:SystemDrive)

# Logging all output
Start-Transcript -Path ('{0}\2-AddFeatures-{1}.log' -f $DMscripts, (Get-Date -Format 'dd-MMM-yyyy')) -NoClobber -Append -Force
#$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'
#$InformationPreference = 'Continue'
#$ErrorActionPreference = 'Continue'

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

#Get the OS Instalation Type
$OsInstalationType = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' | Select-Object -ExpandProperty InstallationType

############################################################
## START Add Windows Features
############################################################
#add some empty lines so the progress bar does not hide text
[System.Environment]::NewLine
[System.Environment]::NewLine
[System.Environment]::NewLine
[System.Environment]::NewLine

Write-Verbose -Message 'Add Windows Features DNS'
Add-WindowsFeature -Name DNS -IncludeAllSubFeature -Verbose:$False

If ($OsInstalationType -ne 'Server Core') {
    Write-Verbose -Message 'Add Windows Features DNS Management Tools'
    Add-WindowsFeature -Name RSAT-DNS-Server -Verbose:$False
}



Write-Verbose -Message 'Add Windows Features NET-Framework-Features'
Add-WindowsFeature -Name NET-Framework-Features -Verbose:$False



Write-Verbose -Message 'Add Windows Features NET-Framework-45-Features'
Add-WindowsFeature -Name NET-Framework-45-Features -Verbose:$False


<#
Write-Verbose -Message 'Add Windows Features AS-NET-Framework'
Add-WindowsFeature -Name AS-NET-Framework -IncludeAllSubFeature
#<<<<<<<<<< START Logging >>>>>>>>>>
    if ($error.count -ne 0) { [int]$xLine = Get-LineNumber; Get-Error -xLine $xLine -ScriptName $myInvocation.MyCommand }
        else { Set-LogEntry -ScriptName $myInvocation.MyCommand -LogText 'Add windows features - AS-NET-Framework.' -Status 0 }
#<<<<<<<<<<  END  Logging >>>>>>>>>>
#>

# Add .Net 3.5 Features



Write-Verbose -Message 'Add Windows Features FS-FileServer'
Add-WindowsFeature -Name FS-FileServer -IncludeAllSubFeature -Verbose:$False

If ($OsInstalationType -ne 'Server Core') {
    Write-Verbose -Message 'Add Windows Features File-Services Management Tools'
    Add-WindowsFeature -Name RSAT-File-Services -Verbose:$False
}



Write-Verbose -Message 'Add Windows Features FS-DFS-Namespace'
Add-WindowsFeature -Name FS-DFS-Namespace -IncludeAllSubFeature -Verbose:$False

If ($OsInstalationType -ne 'Server Core') {
    Write-Verbose -Message 'Add Windows Features DFS Management Tools'
    Add-WindowsFeature -Name RSAT-DFS-Mgmt-Con -Verbose:$False
}



Write-Verbose -Message 'Add Windows Features FS-DFS-Replication'
Add-WindowsFeature -Name FS-DFS-Replication -IncludeAllSubFeature -Verbose:$False




Write-Verbose -Message 'Add Windows Features FS-Resource-Manager'
Add-WindowsFeature -Name FS-Resource-Manager -Verbose:$False




Write-Verbose -Message 'Add Windows Features Group Policy Management'
Add-WindowsFeature -Name GPMC -IncludeAllSubFeature -Verbose:$False




Write-Verbose -Message 'Add Windows Features Backup'
Add-WindowsFeature -Name Windows-Server-Backup -IncludeAllSubFeature -Verbose:$False




Write-Verbose -Message 'Add AD-Domain-Services feature'
# Add AD feature and tools
Add-WindowsFeature -Name AD-Domain-Services

If ($OsInstalationType -ne 'Server Core') {
    Write-Verbose -Message 'Add AD-Domain-Services Management Tools'
    Add-WindowsFeature -Name RSAT-AD-Tools -Verbose:$False
}



############################################################
## END Add Windows Features
############################################################




############################################################
# START Add DNS zones
############################################################

# Load DnsServer module - ONLY 2012 and higher
If ([System.Environment]::OSVersion.Version.Build -ge 9200) {
    Import-Module -Name DnsServer -Verbose:$false

    Write-Verbose -Message 'Add DNS reverse lookup zones'
    if (-not (([string]::IsNullOrEmpty($confXML.N.PCs.DC1.IPv4)) -or (([string]::IsNullOrEmpty($confXML.N.PCs.DC1.PrefixLengthIPv4))))) {
        $NetworkAddress = ConvertTo-IPv4NetworkAddress -IPv4Address $confXML.N.PCs.DC1.IPv4 -PrefixLength $confXML.N.PCs.DC1.PrefixLengthIPv4
        Add-DnsServerPrimaryZone -NetworkId ('{0}/{1}' -f ([String]$NetworkAddress).Substring(1), $confXML.N.PCs.DC1.PrefixLengthIPv4) -ZoneFile 'IPv4.dns'
    }
    # ToDo function to find IPv6 network address
    #Add-DnsServerPrimaryZone -NetworkId ('{0}/{1}' -f $confXML.N.PCs.DC1.IPv6, $confXML.N.PCs.DC1.PrefixLengthIPv6) -ZoneFile 'IPv6.dns'
    Add-DnsServerPrimaryZone -NetworkId 'fd36:46d4:a1a7:9d18::0/64' -ZoneFile 'IPv6.dns'
} else {
    Write-Verbose -Message 'Add DNS reverse lookup zones'
    $dnsserver = ([wmiclass]'\\.\ROOT\Microsoftdns:Microsoftdns_zone').CreateZone(('{0}/{1}' -f $confXML.N.PCs.DC1.IPv4, $confXML.N.PCs.DC1.PrefixLengthIPv4), 0, $false)
    $dnsserver = ([wmiclass]'\\.\ROOT\Microsoftdns:Microsoftdns_zone').CreateZone(('{0}/{1}' -f $confXML.N.PCs.DC1.IPv6, $confXML.N.PCs.DC1.PrefixLengthIPv6), 0, $false)
}

############################################################
## END Add DNS Zones
############################################################

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
if (-not(Test-RegistryValue -Path $regkeypath -Value 'DefaultUserName')) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultUserName' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultUserName' -Value $confXML.N.Admin.Users.Admin.Name

# Set the Domain Name (Dot if local machine)
if ($null -eq (Get-ItemProperty -Path $regkeypath).DefaultDomainName) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultDomainName' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultDomainName' -Value '.'

# Set the Password
if (-not(Test-RegistryValue -Path $regkeypath -Value 'DefaultPassword')) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultPassword' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultPassword' -Value $confXML.N.DefaultPassword

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
# START 3-PromoteDC.ps1 at next Logon (Scheduled Task)
###############################################################################

If (($null -eq $DMscripts) -or ($DMscripts -eq '')) {
    $DMscripts = 'C:\PsScripts'
}

$File = '3-PromoteDC.ps1'
$NextFile = '{0}\{1}' -f $DMscripts, $file
$UserID = $confXML.N.Admin.Users.Admin.Name
$Arguments = '-NoLogo -NoExit -ExecutionPolicy Bypass -File {0}' -f $NextFile

$principal = New-ScheduledTaskPrincipal -UserId $UserID -LogonType Interactive -RunLevel Highest

$TaskAction = New-ScheduledTaskAction -Execute 'PowerShell' -Argument $Arguments

$TaskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $UserID

$Stset = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopOnIdleEnd

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
} Finally {
    # Unregister previous scheduled task
    Unregister-ScheduledTask -TaskName '2-AddFeatures.ps1' -Confirm:$false -Verbose
}


###############################################################################
# END
###############################################################################








Write-Verbose -Message '5 second pause to give Win a chance to catch up and reboot'
Start-Sleep -Seconds 5



# Stop Logging
Stop-Transcript


Write-Verbose -Message 'Reboot???'
Restart-Computer -Force
