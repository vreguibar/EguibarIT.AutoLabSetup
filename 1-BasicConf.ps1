<#
    .Script prupose
        Basic configuration of the computer for automated process
            Implement basic security
            Configure network and name
            Disable depreciated config
            Configure Services
    .NOTES
        Version:         1.1
        DateModified:    17/Dic/2018
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
Start-Transcript -Path ('{0}\1-BasicConf-{1}.log' -f $DMscripts, (Get-Date -Format 'dd-MMM-yyyy')) -NoClobber -Append -Force
#$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'
#$InformationPreference = 'Continue'
#$ErrorActionPreference = 'Continue'

Write-Verbose -Message 'Import the Module: ServerManager'
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




###############################################################################
# START IP Configuration
###############################################################################

# Configure IPv4
If (-not (Get-NetAdapter | Get-NetIPAddress -AddressFamily ipv4 -IPAddress $confXML.N.PCs.DC1.IPv4)) {
    # Configure IPv4 address
    Get-NetAdapter | New-NetIPAddress -IPAddress $confXML.N.PCs.DC1.IPv4 -DefaultGateway $confXML.N.ip.GatewayIPv4 -PrefixLength $confXML.N.PCs.DC1.PrefixLengthIPv4

    # Configure DNS

    # Check if specific DNS has to be used (Within the PCs.<name>.DNS1IPv4). Otherwise use generic IP.DNSServer1
    if ($null -eq $confXML.N.PCs.DC1.DNS1IPv4) {
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $confXML.N.PCs.DC1.DNS1IPv4
    } else {
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $confXML.N.ip.DNSserver1
    } #end If-Else
}

# Configure IPv6
If (-Not (Get-NetAdapter | Get-NetIPAddress -AddressFamily ipv6 -IPAddress $confXML.N.PCs.DC1.IPv6)) {
    # Configure IPv6 Address
    Get-NetAdapter | New-NetIPAddress -IPAddress $confXML.N.PCs.DC1.IPv6 -DefaultGateway $confXML.N.ip.GatewayIPv6 -PrefixLength $confXML.N.PCs.DC1.PrefixLengthIPv6

    # Check if specific DNS has to be used (Within the PCs.<name>.DNS1IPv6). Otherwise use generic IP.DNSserver1IPv6
    if ($null -eq $confXML.N.PCs.DC1.DNS1IPv6) {
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $confXML.N.PCs.DC1.DNS1IPv6
    } else {
        Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses $confXML.N.ip.DNSserver1ipv6
    }

    $NicName = Get-WmiObject -Class win32_networkadapter -Filter 'netconnectionstatus = 2' | Select-Object -ExpandProperty netconnectionid

    & 'C:\Windows\system32\netsh.exe' int ipv6 add route ::/0 $NicName $confXML.N.ip.GatewayIPv6
}


# HOST RESOLUTION PRIORITY TWEAK

$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider'
# (DWORD, recommended: 4, default: 499) - local names cache
Set-ItemProperty -Path $regkeyPath -Name 'LocalPriority' -Value 4

# (DWORD, recommended: 5, default: 500) - the HOSTS file
Set-ItemProperty -Path $regkeyPath -Name 'HostsPriority' -Value 5

# (DWORD, recommended: 6, default: 2000) - DNS
Set-ItemProperty -Path $regkeyPath -Name 'DnsPriority' -Value 6

# (DWORD, recommended: 7, default: 2001) - NetBT name resolution, including WINS
Set-ItemProperty -Path $regkeyPath -Name 'NetbtPriority' -Value 7



# QOS RESERVED BANDWIDTH
$regkeypath = 'HKLM:SOFTWARE\Policies\Microsoft\Windows'
if (-not(Test-Path -Path $regkeypath\Psched)) {
    # Create Key if it does not exists
    New-Item -Path $regkeypath -Name Psched

    New-ItemProperty -Path $regkeypath\Psched -Name 'NonBestEffortLimit' -PropertyType DWord -Value 0
}

#-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-
# Windows 2012 configuration - Start

Write-Verbose -Message 'Configure IPv6'


# https://www.speedguide.net/articles/windows-8-10-2012-server-tcpip-tweaks-5077
# https://docs.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-tuning-nics#bkmk_tcp

# RECEIVE WINDOW AUTO-TUNING LEVEL
Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal

# DISABLE WINDOWS SCALING HEURISTICS
Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics Disabled

# ADD-ON CONGESTION CONTROL PROVIDER (CTCP)
Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CTCP

# TCP CHIMNEY OFFLOAD
Set-NetOffloadGlobalSetting -Chimney Disabled


<#
    'chimney' is not a valid argument for this command.
The syntax supplied for this command is not valid. Check help for the correct syntax.

Usage: set global [[rss=]disabled|enabled|default]
             [[autotuninglevel=]
                disabled|highlyrestricted|restricted|normal|experimental]
             [[congestionprovider=]none|ctcp|default]
             [[ecncapability=]disabled|enabled|default]
             [[timestamps=]disabled|enabled|default]
             [[initialrto=]<300-3000>]
             [[rsc=]disabled|enabled|default]
             [[nonsackrttresiliency=]disabled|enabled|default]
             [[maxsynretransmissions=]<2-8>]
             [[fastopen=]disabled|enabled|default]
             [[fastopenfallback=]disabled|enabled|default]
             [[hystart=]disabled|enabled|default]
             [[pacingprofile=]off|initialwindow|slowstart|always|default]

Parameters:

    Tag           Value
    rss             - One of the following values:
                      disabled: Disable receive-side scaling.
                      enabled : Enable receive-side scaling.
                      default : Restore receive-side scaling state to
                          the system default.
    autotuninglevel - One of the following values:
                      disabled: Fix the receive window at its default
                          value.
                      highlyrestricted: Allow the receive window to
                          grow beyond its default value, but do so
                          very conservatively.
                      restricted: Allow the receive window to grow
                          beyond its default value, but limit such
                          growth in some scenarios.
                      normal: Allow the receive window to grow to
                          accommodate almost all scenarios.
                      experimental: Allow the receive window to grow
                          to accommodate extreme scenarios.
    congestionprovider - This parameter is deprecated. Please use
                         netsh int tcp set supplemental instead.
    ecncapability   - Enable/disable ECN Capability.
                      default : Restore state to the system default.
    timestamps      - Enable/disable RFC 1323 timestamps.
                      default: Restore state to the system default.
    initialrto      - Connect (SYN) retransmit time (in ms). default: 3000.
    rsc             - Enable/disable receive segment coalescing.
                      default: Restore state to the system default.
    nonsackrttresiliency - Enable/disable rtt resiliency for non sack
                      clients. default: disabled.
    maxsynretransmissions - Connect retry attempts using SYN packets.
                      default: 2.
    fastopen        - Enable/disable TCP Fast Open.
                      default: Restore state to the system default.
    fastopenfallback - Enable/disable TCP Fast Open fallback.
                      default: Restore state to the system default.
    hystart         - Enable/disable the HyStart slow start algorithm.
                      default: Restore state to the system default.
    pacingprofile   - Set the periods during which pacing is enabled.
                      One of the following values:
                      off: Never pace.
                      initialwindow: Pace the initial congestion window.
                      slowstart: Pace only during slow start.
                      always: Always pace.
                      default: off.


Remarks: Sets TCP parameters that affect all connections
.

Example:

       set global rss=enabled autotuninglevel=normal
    #>

# DIRECT CACHE ACCESS (DCA)
& "$env:windir\system32\netsh.exe" int tcp set global dca=enabled

# NetDMA State
& "$env:windir\system32\netsh.exe" int tcp set global netdma=enabled

# CHECKSUM OFFLOAD
Enable-NetAdapterChecksumOffload -Name *

# RECEIVE-SIDE SCALING STATE (RSS)
Enable-NetAdapterRss -Name *

# RECEIVE SEGMENT COALESCING STATE (RSC)
Enable-NetAdapterRsc -Name *

# LARGE SEND OFFLOAD (LSO)
Disable-NetAdapterLso -Name *

# TCP 1323 TIMESTAMPS
Set-NetTCPSetting -SettingName InternetCustom -Timestamps Disabled

# NON SACK RTT RESILIENCY
Set-NetTCPSetting -SettingName InternetCustom -NonSackRttResiliency disabled

# MAX SYN RETRANSMISSIONS
Set-NetTCPSetting -SettingName InternetCustom -MaxSynRetransmissions 2

# INITIALCONGESTIONWINDOW (ICW)
Set-NetTCPSetting -SettingName InternetCustom -InitialCongestionWindow 10

#
Set-SmbClientConfiguration -RequireSecuritySignature $true -Confirm:$false

# Disable SMB v1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false


# Windows 2012 configuration - FINISH
#-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-

###############################################################################
# END IP Configuration
###############################################################################











###############################################################################
# Security Settings
###############################################################################
$regkeypath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'


if (-not((Get-ItemProperty -Path $regkeypath).ScreenSaverGracePeriod)) {
    New-ItemProperty -Path $regkeypath -Name 'ScreenSaverGracePeriod' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'ScreenSaverGracePeriod' -Value 0

$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager'
if (-not((Get-ItemProperty -Path $regkeypath).SafeDllSearchMode)) {
    New-ItemProperty -Path $regkeypath -Name 'SafeDllSearchMode' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'SafeDllSearchMode' -Value 1

$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
if (-not((Get-ItemProperty -Path $regkeypath).DisableIPSourceRouting)) {
    New-ItemProperty -Path $regkeypath -Name 'DisableIPSourceRouting' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'DisableIPSourceRouting' -Value 2

if (-not((Get-ItemProperty -Path $regkeypath).EnableICMPRedirect)) {
    New-ItemProperty -Path $regkeypath -Name 'EnableICMPRedirect' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'EnableICMPRedirect' -Value 0

if (-not((Get-ItemProperty -Path $regkeypath).SynAttackProtect)) {
    New-ItemProperty -Path $regkeypath -Name 'SynAttackProtect' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'SynAttackProtect' -Value 2

if (-not((Get-ItemProperty -Path $regkeypath).TcpMaxPortsExhausted)) {
    New-ItemProperty -Path $regkeypath -Name 'TcpMaxPortsExhausted' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'TcpMaxPortsExhausted' -Value 5

if (-not((Get-ItemProperty -Path $regkeypath).TcpMaxHalfOpen)) {
    New-ItemProperty -Path $regkeypath -Name 'TcpMaxHalfOpen' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'TcpMaxHalfOpen' -Value 500

if (-not((Get-ItemProperty -Path $regkeypath).TcpMaxHalfOpenRetried)) {
    New-ItemProperty -Path $regkeypath -Name 'TcpMaxHalfOpenRetried' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'TcpMaxHalfOpenRetried' -Value 400

if (-not((Get-ItemProperty -Path $regkeypath).NoNameReleaseOnDemand)) {
    New-ItemProperty -Path $regkeypath -Name 'NoNameReleaseOnDemand' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'NoNameReleaseOnDemand' -Value 1

if (-not((Get-ItemProperty -Path $regkeypath).TcpMaxConnectResponseRetransmissions)) {
    New-ItemProperty -Path $regkeypath -Name 'TcpMaxConnectResponseRetransmissions' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'TcpMaxConnectResponseRetransmissions' -Value 3

if (-not((Get-ItemProperty -Path $regkeypath).TcpMaxDataRetransmissions)) {
    New-ItemProperty -Path $regkeypath -Name 'TcpMaxDataRetransmissions' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'TcpMaxDataRetransmissions' -Value 3

if (-not((Get-ItemProperty -Path $regkeypath).EnablePMTUDiscovery)) {
    New-ItemProperty -Path $regkeypath -Name 'EnablePMTUDiscovery' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'EnablePMTUDiscovery' -Value 0

if (-not((Get-ItemProperty -Path $regkeypath).KeepAliveTime)) {
    New-ItemProperty -Path $regkeypath -Name 'KeepAliveTime' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'KeepAliveTime' -Value 300000

if (-not((Get-ItemProperty -Path $regkeypath).EnableDeadGWDetect)) {
    New-ItemProperty -Path $regkeypath -Name 'EnableDeadGWDetect' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'EnableDeadGWDetect' -Value 0

if (-not((Get-ItemProperty -Path $regkeypath).DisableIPSourceRouting)) {
    New-ItemProperty -Path $regkeypath -Name 'DisableIPSourceRouting' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'DisableIPSourceRouting' -Value 1

if (-not((Get-ItemProperty -Path $regkeypath).EnableMulticastForwarding)) {
    New-ItemProperty -Path $regkeypath -Name 'EnableMulticastForwarding' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'EnableMulticastForwarding' -Value 0

if (-not((Get-ItemProperty -Path $regkeypath).IPEnableRouter)) {
    New-ItemProperty -Path $regkeypath -Name 'IPEnableRouter' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'IPEnableRouter' -Value 0

if (-not((Get-ItemProperty -Path $regkeypath).EnableAddrMaskReply)) {
    New-ItemProperty -Path $regkeypath -Name 'EnableAddrMaskReply' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'EnableAddrMaskReply' -Value 0


$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
if (-not((Get-ItemProperty -Path $regkeypath).TcpMaxDataRetransmissions)) {
    New-ItemProperty -Path $regkeypath -Name 'TcpMaxDataRetransmissions' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'TcpMaxDataRetransmissions' -Value 3



$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
if (-not((Get-ItemProperty -Path $regkeypath).NoNameReleaseOnDemand)) {
    New-ItemProperty -Path $regkeypath -Name 'NoNameReleaseOnDemand' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'NoNameReleaseOnDemand' -Value 1



$regkeypath = 'HKLM:System\CurrentControlSet\Services\AFD\Parameters'
if (-not((Get-ItemProperty -Path $regkeypath).EnableDynamicBacklog)) {
    New-ItemProperty -Path $regkeypath -Name 'EnableDynamicBacklog' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'EnableDynamicBacklog' -Value 1

if (-not((Get-ItemProperty -Path $regkeypath).MinimumDynamicBacklog)) {
    New-ItemProperty -Path $regkeypath -Name 'MinimumDynamicBacklog' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'MinimumDynamicBacklog' -Value 20

if (-not((Get-ItemProperty -Path $regkeypath).MaximumDynamicBacklog)) {
    New-ItemProperty -Path $regkeypath -Name 'MaximumDynamicBacklog' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'MaximumDynamicBacklog' -Value 20000

if (-not((Get-ItemProperty -Path $regkeypath).DynamicBacklogGrowthDelta)) {
    New-ItemProperty -Path $regkeypath -Name 'DynamicBacklogGrowthDelta' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'DynamicBacklogGrowthDelta' -Value 10



# Disable Deprecated Cryptographic Algorithms

# RC4
$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
if (-not (Test-Path -Path $regkeypath\"RC4 128$([char]0x2215)128")) {
    New-Item -Path $regkeypath -Name "RC4 128$([char]0x2215)128"
    New-ItemProperty -Path $regkeypath\"RC4 128$([char]0x2215)128" -Name 'Enabled' -PropertyType DWord -Value 0
}
Set-ItemProperty -Path $regkeypath\"RC4 128$([char]0x2215)128" -Name 'Enabled' -Value 0

#3DES
$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers'
if (-not(Test-Path -Path "$regkeypath\Triple DES 168")) {
    New-Item -Path "$regkeypath\Triple DES 168"
    New-ItemProperty -Path "$regkeypath\Triple DES 168" -Name 'Enabled' -PropertyType DWord -Value 0
}
Set-ItemProperty -Path "$regkeypath\Triple DES 168" -Name 'Enabled' -Value 0


# enable LSA protection
$regkeypath = 'HKLM:SYSTEM\CurrentControlSet\Control\Lsa'
if (-not((Get-ItemProperty -Path $regkeypath).RunAsPPL)) {
    New-ItemProperty -Path $regkeypath -Name 'RunAsPPL' -PropertyType DWord
}
Set-ItemProperty -Path $regkeyPath -Name 'RunAsPPL' -Value 1




# Uninstalls Server Message Block protocol. Only SMB 1.0 can be uninstalled. SMB 1.0 is only required for communicating with Windows XP and Windows Server 2003
$ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

# it is much faster just to check if the mrxsmb10 registry key value exists or not rather than using Test-WindowsOptionalFeature
# note that mrxsmb10 still exists when Disable-WindowsOptionalFeature is used. it is not deleted until a reboot, but SMB1 also continues to work until a reboot for that case
# can't avoid the slowness of Disable-WindowsOptionalFeature, but at least by not using the Test- function, it will be as fast as it can be
#if (Test-WindowsOptionalFeature -FeatureName 'SMB1Protocol') {
if (Test-Path -Path 'hklm:\System\CurrentControlSet\Services\mrxsmb10') {
    Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart
}



# Uninstalls the PowerShell engine. Only the PowerShell 1.0/2.0 engine can be uninstalled.
# This prevents downgrading to the PowerShell 2.0 engine which can be used to
# avoid PowerShell script blocking logging introduced in PowerShell 5.0
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -NoRestart



# Disable NetBIOS on all network interfaces regardless of whether the interface is active or not.
# NetBIOS is suspectible to man-in-the-middle attacks and is not required in a domain.
$interfacePath = 'hklm:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
$valueName = 'NetbiosOptions'
$previousValueName = 'Previous_NetbiosOptions'

# https://msdn.microsoft.com/en-us/library/windows/hardware/dn923165(v=vs.85).aspx
# 0 = Use DHCP server setting, 1 = Enabled, 2 = Disabled
$disabledValue = 2

Get-ChildItem -Path $interfacePath -Recurse | Where-Object { $_.GetValue($valueName) -ne $disabledValue } | ForEach-Object {
    $currentValue = $_.GetValue($valueName)

    # create a backup value, if it doesn't exist, so that we can use it to restore the setting to the previous value
    if (-not(Test-Path -Path ('{0}\{1}\{2}' -f $interfacePath, $_.PSChildName, $previousValueName))) {
        Set-ItemProperty -Path ('{0}\{1}' -f $interfacePath, $_.PSChildName) -Name $previousValueName -Value $currentValue
    }

    Set-ItemProperty -Path ('{0}\{1}' -f $interfacePath, $_.PSChildName) -Name $valueName -Value $disabledValue
}



###### SERVICES startup ######

# Automatic

$AutoServices = @(
    'Active Directory Certificate Services',
    'Active Directory Domain Services',
    'Active Directory Web Services',
    'Background Intelligent Transfer Service',
    'Background Tasks Infrastructure Service',
    'Base Filtering Engine',
    'Certificate Propagation',
    'COM+ Event System',
    'CoreMessaging',
    'Credential Manager',
    'Cryptographic Services',
    'DCOM Server Process Launcher',
    'DFS Namespace',
    'DFS Replication',
    'DHCP Client',
    'Diagnostic Policy Service',
    'Distributed Transaction Coordinator',
    'DNS Client',
    'DNS Server',
    'Encrypting File System (EFS)',
    'File Server Resource Manager',
    'Group Policy Client',
    'Intersite Messaging',
    'IP Helper',
    'Kerberos Key Distribution Center',
    'Local Session Manager',
    'Microsoft Key Distribution Service',
    'Netlogon',
    'Network List Service',
    'Network Location Awareness',
    'Network Store Interface Service',
    'Plug and Play',
    'Power',
    'Program Compatibility Assistant Service',
    'Remote Procedure Call (RPC)',
    'RPC Endpoint Mapper',
    'Secondary Logon',
    'Security Accounts Manager',
    'Server',
    'Shell Hardware Detection',
    'System Event Notification Service',
    'System Events Broker',
    'Task Scheduler',
    'TCP/IP NetBIOS Helper',
    'Time Broker',
    'User Access Logging Service',
    'User Manager',
    'User Profile Service',
    'Windows Connection Manager',
    'Windows Defender Service',
    'Windows Event Log',
    'Windows Firewall',
    'Windows Management Instrumentation',
    'Windows Push Notifications System Service',
    'Windows Remote Management (WS-Management)',
    'Windows Time',
    'WinHTTP Web Proxy Auto-Discovery Service',
    'Workstation'
)

foreach ($svc in $AutoServices) {
    try {
        $CurrentService = Get-Service -DisplayName $svc -ErrorAction SilentlyContinue

        if ($CurrentService) {
            Set-Service -Name $CurrentService.Name -StartupType Automatic -ErrorAction SilentlyContinue
        }
    } catch {
        throw
    }
}



# Manual
$ManualServices = @(
    'Application Information',
    'Remote Desktop Configuration',
    'Remote Desktop Services'
)

foreach ($svc in $ManualServices) {
    try {
        $CurrentService = Get-Service -DisplayName $svc -ErrorAction SilentlyContinue

        if ($CurrentService) {
            Set-Service -Name $CurrentService.Name -StartupType Manual -ErrorAction SilentlyContinue
        }
    } catch {
        throw
    }
}



#Disabled
$DisabledServices = @(
    'Windows Audio Endpoint Builder',
    'Windows Audio',
    'Bluetooth Support Service',
    'Offline Files',
    'Windows Camera Frame Server',
    'Windows Mobile Hotspot Service',
    'Geolocation Service',
    'Microsoft iSCSI Initiator Service',
    'Net.Tcp Port Sharing Service',
    'File Replication',
    'Phone Service',
    'Printer Extensions and Notifications',
    'Routing and Remote Access',
    'Internet Connection Sharing (ICS)',
    'Print Spooler',
    'Windows Image Acquisition (WIA)',
    'Touch Keyboard and Handwriting Panel Service',
    'Telephony',
    'Auto Time Zone Updater',
    'Interactive Services Detection',
    'Still Image Acquisition Events',
    'Xbox Live Auth Manager',
    'Xbox Live Game Save'
)

foreach ($svc in $DisabledServices) {
    try {
        $CurrentService = Get-Service -DisplayName $svc -ErrorAction SilentlyContinue

        if ($CurrentService) {
            Set-Service -Name $CurrentService.Name -StartupType Disabled -ErrorAction SilentlyContinue
        }
    } catch {
        throw
    }
}



###############################################################################


[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Scope AllUsers -Force
Register-PSRepository -Default -Verbose
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -Verbose

#Find-Module -Name LAPS | Install-Module -Scope AllUsers -AllowClobber -Verbose
Find-Module -Name EguibarIT | Install-Module -Scope AllUsers -AllowClobber -Verbose
Find-Module -Name EguibarIT.Delegation | Install-Module -Scope AllUsers -AllowClobber -Verbose
Find-Module -Name EguibarIT.Housekeeping | Install-Module -Scope AllUsers -AllowClobber -Verbose


# Install PowerShell 7.x (latest)
################################################################################
if ($PSVersionTable.PSVersion.Major -ge 7) {

    Write-Verbose -Message 'Running on PowerShell 7 or greater. Making PowerShell 7 as the default.'

    # Not working
    #Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShellCore\7' -Name 'PowerShellVersion' -Value '7.3.4'
} else {

    Write-Verbose -Message 'Install PowerShell 7.x (latest)'
    Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI -EnablePSRemoting -Quiet"

} #enf If-Else





<#
# Install Windows Admin Center
################################################################################
$WAC_Online = 'http://aka.ms/WACDownload'
$WAC_Installer = 'C:\Temp\wac.msi'
$Port = 6516

If (-not (Test-Path 'C:\Temp')) {
    New-Item -Name Temp -Path C:\ -ItemType Directory
}

# Leave it blank if you want to generate a Self-Signed Certificate.
$CertificateThumbprint = ''
$IsAdminCenterInstalled = [bool] (Get-WmiObject -Class win32_product | Where-Object { $_.Name -eq 'Windows Admin Center' })

If ($IsAdminCenterInstalled) {
    $ReInstall = Read-Host 'Admin Center is already installed. Do you want to re-install/upgrade it? [Y/N]'
    If ( ('N', 'n') -contains $ReInstall) {
        Write-Warning 'Ok, No further action is required.'
        Exit 0
    }
}
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri $WAC_Online -OutFile $WAC_Installer
#if CertificateThumbprint is defined and installed on the system will be used during the installation
if ([bool](Get-ChildItem cert: -Recurse | Where-Object { $_.thumbprint -eq $CertificateThumbprint })) {
    msiexec /i $WAC_Installer /qn SME_PORT=$Port SME_THUMBPRINT=$CertificateThumbprint SSL_CERTIFICATE_OPTION=installed
}
else {
    msiexec /i $WAC_Installer /qn SME_PORT=$Port SSL_CERTIFICATE_OPTION=generate
}

#Post Installation Checks
do {
    if ((Get-Service ServerManagementGateway).status -ne 'Running') {
        Write-Output 'Starting Windows Admin Center (ServerManagementGateway) Service'
        Start-Service ServerManagementGateway
    }
    Start-Sleep -Seconds 5
} until ((Test-NetConnection -ComputerName 'localhost' -Port $Port).TcpTestSucceeded)

New-NetFirewallRule -DisplayName 'Allow Windows Admin Center' -Direction Inbound -Profile Domain -LocalPort $Port -Protocol TCP -Action Allow

Write-Output 'Installation completed and Windows Admin Center is running as expected.'

#>





Write-Verbose -Message 'Change Computer Name'
# Change Computer Name
If ($env:COMPUTERNAME -ne $confXML.N.PCs.DC1.Name) {
    Rename-Computer -NewName $confXML.N.PCs.DC1.Name -Force
    $Global:RebootRequired = 1
}



Write-Verbose -Message 'Windows Name and Organization'
#Windows Name and Organisation
$regkeypath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Set-ItemProperty -Path $regkeypath -Name 'RegisteredOrganization' -Value $confXML.N.RegisteredOrg
Set-ItemProperty -Path $regkeypath -Name 'RegisteredOwner' -Value $confXML.N.RegisteredOwner


#**Enable Remote Desktop**
$regkeypath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
Set-ItemProperty -Path $regkeypath -Name 'fDenyTSConnections' -Value 0
$regkeypath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
Set-ItemProperty -Path $regkeypath -Name 'MinEncryptionLevel' -Value 3


Write-Verbose -Message 'Set the Time Source'
##Time Source
$regkeypath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
Set-ItemProperty -Path $regkeyPath -Name 'NtpServer' -Value $confXML.N.NTP


Set-ItemProperty -Path $regkeyPath -Name 'Type' -Value 'NTP'


$regkeypath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config'
Set-ItemProperty -Path $regkeyPath -Name 'AnnounceFlags' -Value 5














# OS Versionless configuration - FINISH
#-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-




#Normalize the Administrator account by using name provided in the Config file
$AdminName = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE and SID like 'S-1-5-%-500'"
$AdminName | Rename-LocalUser -NewName $confXML.N.Admin.Users.Admin.Name -ErrorAction SilentlyContinue



###############################################################################
# START Set Autologon
###############################################################################
# Set the Key and the permission to AutoLogon
$regkeypath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (-not((Get-ItemProperty -Path $regkeypath).AutoAdminLogon)) {
    New-ItemProperty -Path $regkeypath -Name 'AutoAdminLogon' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'AutoAdminLogon' -Value 1

# Set the User Name
#
# We need to logon with a local admin not Administrator. We use NewAdmin (TheUgly)
# so the Administrator can be renamed to 'TheGood' and normalized
if (-not((Get-ItemProperty -Path $regkeypath).DefaultUserName)) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultUserName' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultUserName' -Value $confXML.N.Admin.Users.Admin.Name

# Set the Domain Name (Dot if local machine)
if ($null -eq (Get-ItemProperty -Path $regkeypath).DefaultDomainName) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultDomainName' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultDomainName' -Value '.'

# Set the Password
if (-not((Get-ItemProperty -Path $regkeypath).DefaultPassword)) {
    New-ItemProperty -Path $regkeypath -Name 'DefaultPassword' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'DefaultPassword' -Value $confXML.N.DefaultPassword

# Set the AutoLogon count to 1 time
if (-not((Get-ItemProperty -Path $regkeypath).AutoLogonCount)) {
    New-ItemProperty -Path $regkeypath -Name 'AutoLogonCount' -PropertyType String
}
Set-ItemProperty -Path $regkeyPath -Name 'AutoLogonCount' -Value 1

# Force Autologon
if (-not((Get-ItemProperty -Path $regkeypath).ForceAutoLogon)) {
    New-ItemProperty -Path $regkeypath -Name 'ForceAutoLogon' -PropertyType DWORD
}
Set-ItemProperty -Path $regkeyPath -Name 'ForceAutoLogon' -Value 1

###############################################################################
# END Set Autologon
###############################################################################



###############################################################################
# START 2-AddFeatures.ps1 at next Logon (Scheduled Task)
###############################################################################
If (($null -eq $DMscripts) -or ($DMscripts -eq '')) {
    $DMscripts = 'C:\PsScripts'
}

$File = '2-AddFeatures.ps1'
$NextFile = '{0}\{1}' -f $DMscripts, $file
$UserID = $confXML.N.Admin.Users.Admin.Name
$Arguments = '-NoLogo -NoExit -ExecutionPolicy Bypass -File {0}' -f $NextFile

$principal = New-ScheduledTaskPrincipal -UserId $UserID -LogonType Interactive -RunLevel Highest

$TaskAction = New-ScheduledTaskAction -Execute 'PowerShell' -Argument $Arguments

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
    Register-ScheduledTask @Splat
} catch {
    Throw
} Finally {
    # Unregister previous scheduled task
    Unregister-ScheduledTask -TaskName '1-BasicConf.ps1' -Confirm:$false -Verbose
} #end Try-Catch-Finally



###############################################################################
# END
###############################################################################



############################################################
## Configure Security Policy
############################################################

# Create a new Windows Script Shell
#$sh = New-Object -ComObject 'Wscript.Shell'



# Power config
[String]$cmd = 'powercfg -h off'
#Invoke-Expression -Command $cmd #| out-null
#$sh.Run($cmd, 1, 'true')
Start-Process -FilePath 'powercfg.exe' -Wait -Verb runas -ArgumentList @('-h', 'off' )


# Enable .Net 3.5 feature
[String]$cmd = 'Dism /Online /enable-feature /featurename:NetFX3 /all /Source:D:\sources\sxs /LimitAccess'
#Invoke-Expression -Command $cmd #| out-null
Start-Process -FilePath 'Dism.exe' -Wait -Verb runas -ArgumentList @('/Online', '/enable-feature', '/featurename:NetFX3', '/all', '/Source:D:\sources\sxs', '/LimitAccess' )


# Implement Data Execution Prevention
# https://msdn.microsoft.com/en-us/library/windows/hardware/ff542202(v=vs.85).aspx
[String]$cmd = 'bcdedit.exe /set {current} nx OptOut'
#Invoke-Expression -Command $cmd #| out-null
#$sh.Run($cmd, 1, 'true')
Start-Process -FilePath 'bcdedit.exe' -Wait -Verb runas -ArgumentList @('/set', '{current}', 'nx', 'OptOut' )



$SecTemplate = Join-Path -Path $DMscripts -ChildPath 'SecTemp.inf' -Resolve

$SecDB = Join-Path -Path $DMscripts -ChildPath 'SecDB.db'
$SecLog = Join-Path -Path $DMscripts -ChildPath 'security.log'
#Remove old db and log file if exist.
if (Test-Path -Path $SecDB) {
    Remove-Item -Path $SecDB
}
if (Test-Path -Path $SecLog) {
    Remove-Item -Path $SecLog
}

#$SecEditCmd = 'secedit /configure /db ' + [char]34 + $SecDB + [char]34 + ' /cfg ' + [char]34 + $SecTemplate + [char]34 + ' /log ' + [char]34 + $SecLog + [char]34 + ' /verbose /quiet'
#$sh.Run($SecEditCmd, 1, 'true')
Start-Process -FilePath 'SecEdit.exe' -Wait -Verb runas -ArgumentList @('/configure', '/db', $SecDB, '/cfg', $SecTemplate, '/log', $SecLog, '/verbose')






# Stop logging
Stop-Transcript

Write-Verbose -Message 'Reboot???'
Restart-Computer -Force
