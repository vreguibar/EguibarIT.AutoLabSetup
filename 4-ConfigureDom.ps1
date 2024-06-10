<#
    .Script purpose
        Configure the new domain
            BGInfo
            DNS
            Create Central Admin structure
            Configure Policies
            Configure Sites & Subnets
            Configure DFS and Shares
            Configure Domain Policy Repository
            Enable Recycle BIN
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
Start-Sleep -Seconds 20

# Clear any previous error
$error.clear()

# Get Folder where all Delegation Model scripts & files
$DMscripts = ('{0}\PsScripts' -f $env:SystemDrive)

# Logging all output
Start-Transcript -Path ('{0}\4-ConfigureDom-{1}.log' -f $DMscripts, (Get-Date -Format 'dd-MMM-yyyy')) -NoClobber -Append -Force
#$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'
#$InformationPreference = 'Continue'
#$ErrorActionPreference = 'Continue'

Write-Verbose -Message 'Import the corresponding Modules'
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

# https://learn.microsoft.com/en-us/archive/blogs/adpowershell/disable-loading-the-default-drive-ad-during-import-module
#$Env:ADPS_LoadDefaultDrive = 0

Import-Module -Name ServerManager -Force -Verbose:$false
Import-Module -Name GroupPolicy -Force -Verbose:$false

$AllModules = @(
    'ActiveDirectory',
    'EguibarIT',
    'EguibarIT.DelegationPS',
    'DnsServer',
    'SmbShare',
    'SmbWitness'
)
foreach ($item in $AllModules) {
    Write-Verbose -Message ('Importing module {0}' -f $Item)

    try {
        # Check if the module is already imported
        $module = Get-Module -Name $item -ListAvailable -ErrorAction SilentlyContinue

        if ($null -eq $module) {
            Write-Error -Message ('Module {0} is not installed. Please install the module before importing.' -f $item)
        } else {
            # Import the module if it's not already imported
            if (-not (Get-Module -Name $item -ErrorAction SilentlyContinue)) {
                $Splat = @{
                    ModuleInfo  = $module
                    ErrorAction = 'Stop'
                    Verbose     = $false
                }

                if ($Force) {
                    $Splat.Add('Force', $true)
                }

                Import-Module @Splat
                Write-Verbose -Message ('Successfully imported module {0}' -f $item)
            } else {
                Write-Verbose -Message ('Module {0} is already imported.' -f $item)
            }
        }
    } catch {
        throw
    } #end Try-Catch
} #end ForEach

[System.Environment]::NewLine


#Get the OS Instalation Type
#$OsInstalationType = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' | Select-Object -ExpandProperty InstallationType

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



# Naming conventions hashtable
$NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix;
    'sg'     = $confXML.n.NC.GlobalGroupPreffix;
    'su'     = $confXML.n.NC.UniversalGroupPreffix;
    'Delim'  = $confXML.n.NC.Delimiter;
    'T0'     = $confXML.n.NC.AdminAccSufix0;
    'T1'     = $confXML.n.NC.AdminAccSufix1;
    'T2'     = $confXML.n.NC.AdminAccSufix2
}

#('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM.Name, $NC['T0'])
# SG_PAWM_T0

# Read SYSVOL physical path
$RegPath = 'HKLM:SYSTEM/CurrentControlSet/Services/Netlogon/Parameters'
$SysVol = (Get-ItemProperty -Path $RegPath -Name 'SysVol').SysVol




# remove TheGood user from Schema Admin
Remove-ADGroupMember -Identity 'Schema Admins' -Members $env:username -Confirm:$false



###############################################################################
# START Configure BGInfo and AdImagePhoto
###############################################################################

# Configure BGInfo
#Write-Verbose -Message 'Configure BGInfo'

Copy-Item -Path "$DMscripts\Lab.bgi" -Destination ('{0}\{1}\scripts' -f $SysVol, $env:USERDNSDOMAIN)
Copy-Item -Path "$DMscripts\IPv6.vbs" -Destination ('{0}\{1}\scripts' -f $SysVol, $env:USERDNSDOMAIN)


Copy-Item -Path $DMscripts\Pic\Default.jpg -Destination ('{0}\{1}\scripts' -f $SysVol, $env:USERDNSDOMAIN)

Copy-Item -Path $DMscripts\Set-AdPicture.ps1 -Destination ('{0}\{1}\scripts' -f $SysVol, $env:USERDNSDOMAIN)

# Unblock Security from BGinfo.exe

#Unblock-File -Path "${env:ProgramFiles(x86)}\BGInfo\BGinfo.exe"

Unblock-File -Path ('{0}\{1}\scripts\Set-AdPicture.ps1' -f $SysVol, $env:USERDNSDOMAIN)


###############################################################################
# END Copy BGInfo and AdImagePhoto
###############################################################################





###############################################################################
# Change DNS zones
###############################################################################
Write-Verbose -Message 'Set aging & Scavenging, convert reverse lookup zones to ADintegrated and Dynamic Secure Update'

#Convert reverse lookup zones to ADintegrated and Dynamic Secure Update
ConvertTo-DnsServerPrimaryZone -Name $confXML.N.IP.IPv4ReverseZone -PassThru -Verbose -ReplicationScope Forest -Force
#DNSCMD $strComputer /ZoneResetType $confXML.N.IP.IPv4ReverseZone /DSPrimary



Set-DnsServerPrimaryZone -Name $confXML.N.IP.IPv4ReverseZone -DynamicUpdate Secure -PassThru
#DNSCMD $strComputer /Config $confXML.N.IP.IPv4ReverseZone /AllowUpdate 2



ConvertTo-DnsServerPrimaryZone -Name $confXML.N.IP.IPv6ReverseZone -PassThru -Verbose -ReplicationScope Forest -Force
#DNSCMD $strComputer /ZoneResetType $confXML.N.IP.IPv6ReverseZone /DSPrimary


Set-DnsServerPrimaryZone -Name $confXML.N.IP.IPv6ReverseZone -DynamicUpdate Secure -PassThru
#DNSCMD $strComputer /Config $confXML.N.IP.IPv6ReverseZone /AllowUpdate 2



# Configure Aging for the zones

Set-DnsServerZoneAging $env:USERDNSDOMAIN -Aging $True

Set-DnsServerZoneAging ('_msdcs.{0}' -f $env:USERDNSDOMAIN) -Aging $True

Set-DnsServerZoneAging $confXML.N.IP.IPv4ReverseZone -Aging $True

Set-DnsServerZoneAging $confXML.N.IP.IPv6ReverseZone -Aging $True

Set-DnsServerScavenging -ComputerName $Env:COMPUTERNAME -ApplyOnAllZones -ScavengingState $true -ScavengingInterval 7.00:00:00



# Set DNS Server Forwarders
$Splat = @(
    $confXML.N.IP.GatewayIPv4,
    $confXML.N.IP.GatewayIPv6,
    $confXML.N.IP.GoogleDns1Ipv6,
    $confXML.N.IP.GoogleDns2Ipv6,
    $confXML.N.IP.GoogleDns1Ipv4,
    $confXML.N.IP.GoogleDns2Ipv4
)
Set-DnsServerForwarder -IPAddress $Splat

###############################################################################
# END Changing DNS zones
###############################################################################




# Get the Administrator by Well-Known SID and if not named as per the XML file, proceed to rename it
$AdminName = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
If ($AdminName.SamAccountName -ne $confXML.n.Admin.users.Admin.Name) {
    Rename-ADObject -Identity $AdminName.DistinguishedName -NewName $confXML.n.Admin.users.Admin.Name
    Set-ADUser $AdminName -SamAccountName $confXML.n.Admin.users.Admin.Name -DisplayName $confXML.n.Admin.users.Admin.Name
}


# rename harlequin (Local guest account) to TheUgly. If not found look for Guest
$Guest = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-501' }
If ($Guest) {
    $Splat = @{
        Identity       = $Guest
        SamAccountName = $confXML.N.Admin.Users.Guest.Name
        DisplayName    = $confXML.N.Admin.Users.Guest.Name
    }
    Set-ADUser @Splat
}






# Get the Config.xml file
$Splat = @{
    ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
    verbose       = $true
}

# Check if Exchange needs to be created
if ($confXML.N.Domains.Prod.CreateExContainers -eq $True) {
    $Splat.add('CreateExchange', $true)
}

# Check if DFS needs to be created
if ($confXML.N.Domains.Prod.CreateDFS -eq $True) {
    $Splat.add('CreateDFS', $true)
}

# Check if CA needs to be created
if ($confXML.N.Domains.Prod.CreateCa -eq $True) {
    $Splat.add('CreateCa', $true)
}

# Check if LAPS needs to be created
if ($confXML.N.Domains.Prod.CreateLAPS -eq $True) {
    $Splat.add('CreateLAPS', $true)
}

# Check if DHCP needs to be created
if ($confXML.N.Domains.Prod.CreateDHCP -eq $True) {
    $Splat.add('CreateDHCP', $true)
}

Write-Verbose -Message 'Configuring Tier Model & Delegation Model'
#Create Central OU Structure
New-CentralItOu @Splat



###############################################################################
# START Configure Default Policies
###############################################################################
# Configure Default Domain GPO

##### Import-GPO -BackupId <GPO GUID> -TargetName <CurrentGpoName> -path <Path of the stored GPOs>



# This is the WMI Filter for the PDCe Domain Controller
$PDCeWMIFilter = @('PDCe Domain Controller',
    'Queries for the domain controller that holds the PDC emulator FSMO role',
    'root\CIMv2',
    'Select * from Win32_ComputerSystem where DomainRole=5')

# This is the WMI Filter for the non-PDCe Domain Controllers
$NonPDCeWMIFilter = @('Non-PDCe Domain Controllers',
    'Queries for all domain controllers except for the one that holds the PDC emulator FSMO role',
    'root\CIMv2',
    'Select * from Win32_ComputerSystem where DomainRole=4')

# Configure GPO to follow PDCe Role configuration
$parameters = @{
    GpoName           = 'Set PDCe Domain Controller as Authoritative Time Server'
    NtpServer         = $confXML.N.NTP
    AnnounceFlags     = 5
    Type              = 'NTP'
    WMIFilter         = $PDCeWMIFilter
    DisableVMTimeSync = $true
}
New-TimePolicyGPO @parameters

$parameters = @{
    GpoName           = 'Set Time Settings on non-PDCe Domain Controllers'
    AnnounceFlags     = 10
    Type              = 'NT5DS'
    WMIFilter         = $NonPDCeWMIFilter
    DisableVMTimeSync = $true
}
New-TimePolicyGPO @parameters

# This is the WMI Filter for the non-PDCe Domain Controllers
$VMWareWMIFilter = @('Identify Virtual Machine',
    'Identifies if the machine is a virtual machine',
    'root\CIMv2',
    "Select * from Win32_ComputerSystem WHERE (Model LIKE '%Virtual%')")

# Try to catch all VM regardless of manufacturer
# OLD => "Select * from Win32_ComputerSystem where Model='VMWare Virtual Platform'"
# NEW => "Select * from Win32_ComputerSystem WHERE (Model LIKE '%Virtual%')"


# Create new Domain Controllers GPO that applies to VM for TimeSync
New-DelegateAdGpo -gpoDescription ('Set TIME parameters for Virtual Machine DC') -gpoScope C -gpoLinkPath ('OU=Domain Controllers,{0}' -f ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

# Adding settings
Set-GPPrefRegistryValue -Name 'C-Set TIME parameters for Virtual Machine DC' -Context Computer -Action Update -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSetservices\W32time\Parameters' -ValueName Enabled -Value 0 -Type DWord
Set-GPPrefRegistryValue -Name 'C-Set TIME parameters for Virtual Machine DC' -Context Computer -Action Update -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSetservices\W32time\Config' -ValueName MaxNegPhaseCorrection -Value 3600 -Type DWord
Set-GPPrefRegistryValue -Name 'C-Set TIME parameters for Virtual Machine DC' -Context Computer -Action Update -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSetservices\W32time\Config' -ValueName MaxPosPhaseCorrection -Value 3600 -Type DWord
Set-GPPrefRegistryValue -Name 'C-Set TIME parameters for Virtual Machine DC' -Context Computer -Action Update -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSetservices\W32time\TimeProviders\NtpClient' -ValueName SpecialPollInterval -Value 900 -Type DWord

###############################################################################
# END Configure Default Policies
###############################################################################




###############################################################################
# START configure Sites and Subnets
###############################################################################


# Create 3 more sites apart from 'Default-First-Site-Name'
New-ADReplicationSite -Name 'Second-Site' -Description 'Research & Development Facilities' -ProtectedFromAccidentalDeletion $true
New-ADReplicationSite -Name 'Third-Site' -Description 'Asian Business Precense' -ProtectedFromAccidentalDeletion $true
New-ADReplicationSite -Name 'Fourth-Site' -Description 'Manufacturing Facilities' -ProtectedFromAccidentalDeletion $true

# IPv4 Subnets. Class C into 4 smaller
New-ADReplicationSubnet -Name '192.168.0.0/26' -Site 'Third-Site' -Location 'Tokio,Japon'
New-ADReplicationSubnet -Name '192.168.0.64/26' -Site 'Second-Site' -Location 'Vancouver,Canada'
New-ADReplicationSubnet -Name '192.168.0.128/26' -Site 'Fourth-Site' -Location 'Rostov,Rusia'
New-ADReplicationSubnet -Name '192.168.0.192/26' -Site 'Default-First-Site-Name' -Location 'Puebla,Mexico'

# IPv6 Subnets. 4 smaller
# <<<<<< Not working on w2k8 >>>>>>
# https://www.internex.at/de/toolbox/ipv6
New-ADReplicationSubnet -Name 'fd36:46d4:a1a7:9d18::/66' -Site 'Fourth-Site' -Location 'Rostov,Rusia'
New-ADReplicationSubnet -Name 'fd36:46d4:a1a7:9d18:4000::/66' -Site 'Second-Site' -Location 'Vancouver,Canada'
New-ADReplicationSubnet -Name 'fd36:46d4:a1a7:9d18:8000::/66' -Site 'Third-Site' -Location 'Tokio,Japon'
New-ADReplicationSubnet -Name 'fd36:46d4:a1a7:9d18:c000::/66' -Site 'Default-First-Site-Name' -Location 'Puebla,Mexico'

#
Set-ADReplicationSiteLink -Identity 'DEFAULTIPSITELINK' -SitesIncluded @{Add = 'Second-Site' }
Set-ADReplicationSiteLink -Identity 'DEFAULTIPSITELINK' -SitesIncluded @{Add = 'Third-Site' }
Set-ADReplicationSiteLink -Identity 'DEFAULTIPSITELINK' -SitesIncluded @{Add = 'Fourth-Site' }


###############################################################################
# END configure Sites and Subnets
###############################################################################




###############################################################################
# START configure domain DFS and Shares
###############################################################################
Write-Verbose -Message 'Create Share storage'
#Create Share storage
IF (!(Test-Path -Path $confXML.N.Shares.ShareLocation)) {
    New-Item -Path $confXML.N.Shares.ShareLocation -ItemType Directory
}


Revoke-Inheritance -path $confXML.N.Shares.ShareLocation


Revoke-NTFSPermissions -path $confXML.N.Shares.ShareLocation -object Users -permission 'ReadAndExecute'


IF (!(Test-Path -Path (Join-Path -Path $confXML.N.Shares.ShareLocation -ChildPath $confXML.N.Shares.HomeFoldersName))) {
    New-Item -Path (Join-Path -Path $confXML.N.Shares.ShareLocation -ChildPath $confXML.N.Shares.HomeFoldersName) -ItemType Directory
}


Grant-NTFSPermission -path (Join-Path -Path $confXML.N.Shares.ShareLocation -ChildPath $confXML.N.Shares.HomeFoldersName) -object EVERYONE -permission 'FullControl'

IF (!(Test-Path -Path (Join-Path -Path $confXML.N.Shares.ShareLocation -ChildPath $confXML.N.Shares.AreasName))) {
    New-Item -Path (Join-Path -Path $confXML.N.Shares.ShareLocation -ChildPath $confXML.N.Shares.AreasName) -ItemType Directory
}


#
# http://windowsitpro.com/powershell/managing-file-shares-windows-powershell
#
# (Get-WmiObject Win32_Share -List).Create
#   (
#     "C:\Users\jxg768\Desktop\RobsShare", "RobsShare", 0
#   )
#
# Windows 2012
# Import-Module SmbShare
# Import-Module SmbWitness
#
# New-SmbShare -Name Spring -Path C:\Spring -Description 'Shared Folder for Spring Students' -FullAccess Administrator -ReadAccess Everyone
#
# Share the root, the HomeFolders and Areas
#[string]$cmd = "C:\Windows\system32\net.exe share Shares=" + $confXML.N.Shares.ShareLocation + " '/GRANT:Everyone,FULL'"
#Invoke-Expression -Command $cmd
New-SmbShare -Name $confXML.N.Shares.RootShare -Path $confXML.N.Shares.ShareLocation -FullAccess Everyone

#[string]$cmd = "C:\Windows\system32\net.exe share HomeFolders=" + $confXML.N.Shares.ShareLocation + "\" + $confXML.N.Shares.DefaultHomeFoldersName + " '/GRANT:Everyone,FULL'"
#Invoke-Expression -Command $cmd
$path = '{0}\{1}' -f $confXML.N.Shares.ShareLocation, $confXML.N.Shares.HomeFoldersName
New-SmbShare -Name $confXML.N.Shares.HomeFoldersName -Path $path -FullAccess Everyone

#[string]$cmd = "C:\Windows\system32\net.exe share Areas=" + $confXML.N.Shares.ShareLocation + "\" + $confXML.N.Shares.AreasName + " '/GRANT:Everyone,FULL'"
#Invoke-Expression -Command $cmd
$path = '{0}\{1}' -f $confXML.N.Shares.ShareLocation, $confXML.N.Shares.AreasName
New-SmbShare -Name $confXML.N.Shares.AreasName -Path $path -FullAccess Everyone



# Create the domain DFS
New-DfsnRoot -TargetPath ('\\{0}\Shares' -f $env:COMPUTERNAME) -Type DomainV2 -Path ('\\{0}\Shares' -f $env:userdnsdomain)



###############################################################################
# END configure domain DFS and Shares
###############################################################################



###############################################################################
# START Configure Domain Policy Repository (PolicyDefinitions for ADMX files)
###############################################################################
# Create PolicyDefinition folder within SYSVOL
Write-Verbose -Message 'Create PolicyDefinition folder within SYSVOL'
# Get registry key where SYSVOL path resides
$SysvolPath = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'sysvol').sysvol
$PolicyDefinitionsPath = '{0}\{1}\Policies\PolicyDefinitions' -f $SysvolPath, $env:UserDnsDomain
IF (-not(Test-Path -Path $PolicyDefinitionsPath)) {
    New-Item -Path $PolicyDefinitionsPath -ItemType Directory
    New-Item -Path $PolicyDefinitionsPath\en-US -ItemType Directory
}


# Copy LAPS module
#### Should be already copied to Windows\Policy Definitions
# copy-item -Path $env:ProgramFiles\WindowsPowerShell\Modules\AdmPwd.PS\AdmPwd.admx -Destination $PolicyDefinitionsPath -Force
# copy-item -Path $env:ProgramFiles\WindowsPowerShell\Modules\AdmPwd.PS\en-US\AdmPwd.adml -Destination $PolicyDefinitionsPath\en-US -Force

# Copy existing ADMX templates to the central store
Write-Verbose -Message 'Copy existing ADMX templates to the central store'
Copy-Item -Path "$env:windir\PolicyDefinitions\" -Destination $PolicyDefinitionsPath -Recurse -Container:$false -Force

Copy-Item -Path $PolicyDefinitionsPath\*.adml -Destination $PolicyDefinitionsPath\en-US\ -Force

###############################################################################
# END Configure Domain Policy Repository (PolicyDefinitions for ADMX files)
###############################################################################





###############################################################################
# START Enable Recycle BIN
###############################################################################
# Create Recycle Bin CN variable
$RecycleBinCN = 'CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()

# Enable the Recycle Bin
Enable-ADOptionalFeature -Identity $RecycleBinCN -Scope ForestOrConfigurationSet -Target $env:userdnsdomain -Confirm:$false


###############################################################################
# END Enable Recycle BIN
###############################################################################








#ToDo..........

###############################################################################
# START Remove MachineAccountQuota
###############################################################################
Write-Verbose -Message 'Removing permission for all users to add workstations to the domain"'
Set-ADDomain -Identity ((Get-ADDomain).DistinguishedName) -Replace @{'ms-DS-MachineAccountQuota' = '0' }
###############################################################################
# END Remove MachineAccountQuota
###############################################################################
# Set UPN Suffixes
Write-Verbose -Message 'Adding UPN suffixes for Domain...'
ForEach ($upn in $confXML.N.Admin.UPNsufix.ChildNodes) {
    Try {
        Get-ADForest | Set-ADForest -UPNSuffixes @{Add = $upn.'#text' }
    } Catch {
        throw
    }
}








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

# Set the Password
if (-not(Test-RegistryValue -Path $regkeypath -Value 'DefaultPassword')) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultPassword' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultPassword' -Value $confXML.N.DefaultPassword

# Set the Domain Name (Dot if local machine)
if ($null -eq (Get-ItemProperty -Path $regkeypath).DefaultDomainName) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultDomainName' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultDomainName' -Value $env:UserDnsDomain

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
# START 5-PopulateDom.ps1 at next Logon (Scheduled Task)
###############################################################################

If (($null -eq $DMscripts) -or ($DMscripts -eq '')) {
    $DMscripts = 'C:\PsScripts'
}

$File = '5-PopulateDom.ps1'
$NextFile = '{0}\{1}' -f $DMscripts, $file
$UserID = $confXML.N.Admin.Users.Admin.Name
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
    TaskName    = $File
    Trigger     = $TaskTrigger
    Verbose     = $true
}
try {
    #Register-ScheduledTask @Splat
} catch {
    throw
} finally {
    # Unregister previous scheduled task
    Unregister-ScheduledTask -TaskName 4-ConfigureDom.ps1 -Confirm:$false -Verbose
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
