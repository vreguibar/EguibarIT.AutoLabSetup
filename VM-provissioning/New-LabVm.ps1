[CmdletBinding()]
Param(

    # Param1 VM new name
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        HelpMessage = 'Name of the Virtual Machine. This name will be used for the VM name on Hyper-V and for the Windows host name.',
        Position = 0)]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(0, 20)]
    [string]
    $vmName,

    # Param2 integer representing the OS type of the VM
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        HelpMessage = 'Type of OS for the Virtual Machine.',
        Position = 1)]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Win11', 'W2k19', 'W2k19-CORE', 'W2022', 'W2022-CORE', 'W2025-CORE', 'W2025')]
    [string]
    $vmOsType,

    # Param3 Data File
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        HelpMessage = 'File containing the configuration data of the new VM (just in case VM name exists)',
        Position = 2)]
    [PSDefaultValue(Help = 'Default Value is "C:\VMs\MainData.psd1"')]
    [string]
    $DataFile = 'C:\VMs\MainData.psd1'

)
<#
.Synopsis
   Create a MOD virtual machine
.DESCRIPTION
   Create a MOD (modified) virtual machine by providing only 3 parameters.
   This script is hardcoded to use my laptop virtual environment; this must be changed to fit your own needs.
   All VMs go into C:\VMs
   Any created VM has a differential disk based on existing master disks
   Win 10, Win 11, Win 2019, Win 2019 Core, Win 2022, Win 2022 Core
   The Windows Hostname will be the same as the VM name provided.
.EXAMPLE
   To create Win 8.1 called VMWIN8
   New-LabVm -vmName VMWIN8 -vmOsType 'Win11'
.EXAMPLE
   To create Win Server 2022 Core called Srv01
   New-LabVm Srv01 'W2022-CORE'
.PARAMETER vmName
    Name of the Virtual Machine. This name will be used for the VM name on Hyper-V and for the Windows host name.
.PARAMETER vmOsType
    Type of OS for the Virtual Machine.
.PARAMETER DataFile
    File containing the configuration data of the new VM (just in case VM name exists)
.NOTES
    Version:         1.7
    DateModified:    8/Mar/2024
    LasModifiedBy:   Vicente Rodriguez Eguibar
                     vicente@eguibarIT.com
                     Eguibar Information Technology S.L.
                     http://www.eguibarit.com
#>

Set-StrictMode -Version Latest

#Check if script is running as ADMINISTRATOR
[bool]$IsAdmin = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')

If (-not $IsAdmin) {
    Write-Error -Message 'This script must be executed as ADMINISTRATOR!!!'
    Exit
}

################################################################################
# Constants
$VmFolder = 'C:\VMs'

# Verbose which data file is used.
Write-Verbose -Message ('Using {0} Data file.' -f $PSBoundParameters['DataFile'])


################################################################################
# Variables

[System.String]$VmSwitchName = 'LAN'
[System.Int32]$ProcessorCount = 2

$VM = $null
$Splat = $null
$PC = $null

[System.Int64]$MemoryStartupBytes = 1024MB
[System.Int64]$MemoryMinimum = 512MB
[System.Int64]$MemoryMaximum = 4096MB



################################################################################
# Checks

# Check if the VMs folder exists (Default folder for my VMs
If (Test-Path -Path $VmFolder) {
    # Check if the new VM name already exist
    if (-Not (Test-Path -Path $vmName)) {

        Write-Verbose -Message ('VM folder {0} does not exist. Creating it.' -f $vmName)
        # If the folder doesn't exist, then create it
        New-Item -Path $VmFolder -Value $vmName -ItemType Directory -Force | Out-Null
    }
} Else {
    # The VMs folder does not exist, then create it and the new VM folder
    Write-Verbose -Message 'Default VMs folder does not exist. Creating it.'
    New-Item -Path 'C:\' -Value 'VMs' -ItemType Folder -Force | Out-Null
    New-Item -Path $VmFolder -Value $vmName -ItemType Folder -Force | Out-Null
}


# Set the new diff path name
$vmVhdNewDisk = '{0}\{1}\{1}.vhdx' -f $VmFolder, $vmName

#Check if VmSwitch exists, otherwise create it
$VmSwitch = Get-VMSwitch -Name $VmSwitchName -ErrorAction SilentlyContinue
If (-not $VmSwitch) {
    Write-Verbose -Message 'Default vSwitch "LAN" does not exist. Creating it.'
    $Splat = @{
        Name              = $VmSwitchName
        NetAdapterName    = 'Ethernet'
        AllowManagementOS = $true
        EnableIov         = $True
        Notes             = 'vSwitch used for VM to communicate, using physical NIC for communication.'
    }
    $VmSwitch = New-VMSwitch @Splat | Set-NetConnectionProfile -NetworkCategory Private
}



################################################################################
# Set the master disk based on chosen OS Type

# Define the Root Folder where master disks reside
$MastersRoot = 'C:\VMs\Masters'
$RSATtools = @'
<SynchronousCommand wcm:action="add">
                    <CommandLine>powershell -NoLogo -sta -NoProfile -NoInteractive -Command {Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online}</CommandLine>
                    <Description>Install RSAT tools on GUI</Description>
                    <Order>5</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
'@
$GUIprofiles = @'
<SynchronousCommand wcm:action="add">
                    <CommandLine>powershell -NoLogo -sta -NoProfile -NoInteractive -File c:\PsScripts\Set-ADAllAdminPictures.ps1</CommandLine>
                    <Description>Pre-load profiles for defined existing users on GUI</Description>
                    <Order>6</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
'@

switch ($vmOsType) {

    # Option 1 -> Windows 11
    'Win11' {

        # Set the Master Disk path name
        $vmVhdParentDisk = '{0}\_OK_Win11-Jan2025.vhdx' -f $MastersRoot

    } #----- End of Option 1 -----

    # Option 2 -> Windows Server 2019 DesktopExperience
    'W2k19' {
        # Set the Master Disk path name
        $vmVhdParentDisk = '{0}\_OK_W2019-GUI-Dec-2020.vhdx' -f $MastersRoot

        #Define memory params
        $MemoryStartupBytes = 2048MB
        $MemoryMinimum = 512MB
        $MemoryMaximum = 4096MB

        #Define CPU counts
        $ProcessorCount = 4

    } #----- End of Option 2 -----

    # Option 3 -> Windows Server 2019 CORE
    'W2k19-CORE' {

        # Set the Master Disk path name
        $vmVhdParentDisk = '{0}\_OK_W2019-Core-Dec-2020.vhdx' -f $MastersRoot

        #Define memory params
        $MemoryStartupBytes = 2048MB
        $MemoryMinimum = 512MB
        $MemoryMaximum = 4096MB

        #Define CPU counts
        $ProcessorCount = 4

        # Remove RSAT tools because is core
        $RSATtools = $null

        # Remove Profiles pre-load because is core
        $GUIprofiles = $null

    } #----- End of Option 3 -----

    # Option 4 -> Windows Server 2022 DesktopExperience
    'W2022' {
        # Set the Master Disk path name
        $vmVhdParentDisk = '{0}\_OK_W2022-GUI-Dec-2023.vhdx' -f $MastersRoot

        #Define memory params
        $MemoryStartupBytes = 4096MB
        $MemoryMinimum = 4096MB
        $MemoryMaximum = 8192MB

        #Define CPU counts
        $ProcessorCount = 8

    } #----- End of Option 4 -----

    # Option 5 -> Windows Server 2022 CORE
    'W2022-CORE' {

        # Set the Master Disk path name
        $vmVhdParentDisk = '{0}\_OK_W2022-Core-Feb2024.vhdx' -f $MastersRoot

        #Define memory params
        $MemoryStartupBytes = 4096MB
        $MemoryMinimum = 4096MB
        $MemoryMaximum = 8192MB

        #Define CPU counts
        $ProcessorCount = 8

        # Remove RSAT tools because is core
        $RSATtools = $null

        # Remove Profiles pre-load because is core
        $GUIprofiles = $null

    } #----- End of Option 5 -----

    # Option 6 -> Windows Server 2025 CORE
    'W2025-CORE' {

        # Set the Master Disk path name
        $vmVhdParentDisk = '{0}\_OK_W2025-Core-Jan2025.vhdx' -f $MastersRoot

        #Define memory params
        $MemoryStartupBytes = 4096MB
        $MemoryMinimum = 4096MB
        $MemoryMaximum = 8192MB

        #Define CPU counts
        $ProcessorCount = 8

        # Remove RSAT tools because is core
        $RSATtools = $null

        # Remove Profiles pre-load because is core
        $GUIprofiles = $null

    } #----- End of Option 6 -----

    # Option 6 -> Windows Server 2025 GUI
    'W2025' {

        # Set the Master Disk path name
        $vmVhdParentDisk = '{0}\_OK_W2025-GUI-Jan2025.vhdx' -f $MastersRoot

        #Define memory params
        $MemoryStartupBytes = 4096MB
        $MemoryMinimum = 4096MB
        $MemoryMaximum = 8192MB

        #Define CPU counts
        $ProcessorCount = 8

    } #----- End of Option 6 -----

} # --- End of switch ---



#Create the new Differential Disk, having the master
Write-Host -Message '   ---------------------------------------------------------------
       Creating the new differential disk...
   ---------------------------------------------------------------
' -ForegroundColor green

# Ensure disk does not exists.
$DiskExists = Get-VHD -Path $vmVhdNewDisk -ErrorAction SilentlyContinue
If ($DiskExists) {
    Remove-Item $vmVhdNewDisk -Force | Out-Null
}

#Create the disk
$splat = @{
    Path         = $vmVhdNewDisk
    ParentPath   = $vmVhdParentDisk
    Differencing = $true
}
New-VHD @splat | Out-Null



# Create the new VM
Write-Host -Message ('   ---------------------------------------------------------------
       Creating the  {0}  virtual machine...
   ---------------------------------------------------------------
' -f $vmName) -ForegroundColor green

$splat = @{
    Name         = $vmName
    Generation   = 2
    Path         = $VmFolder
    VHDPath      = $vmVhdNewDisk
    BootDevice   = 'VHD'
    SwitchName   = $VmSwitch.Name
    ComputerName = 'localhost'
    #Version      = 11
}
$VM = New-VM @splat



# Configure Integration Services
Write-Host -Message '   ---------------------------------------------------------------
       Configuring Integration Services...
   ---------------------------------------------------------------
' -ForegroundColor green

Get-VMIntegrationService -VMName $vmName | ForEach-Object { Enable-VMIntegrationService -Name $_.Name -VMName $vmName } | Out-Null



# Configure Memory for the VM
Write-Host -Message '   ---------------------------------------------------------------
       Configuring Memory...
   ---------------------------------------------------------------
' -ForegroundColor green

$splat = @{
    VM                   = $VM
    DynamicMemoryEnabled = $true
    MinimumBytes         = $MemoryMinimum
    StartupBytes         = $MemoryStartupBytes
    MaximumBytes         = $MemoryMaximum
    Passthru             = $true
}
Set-VMMemory @splat | Out-Null



# Configure CPU for the VM
Write-Host -Message '   ---------------------------------------------------------------
       Configuring CPU...
   ---------------------------------------------------------------
   ' -ForegroundColor green

$splat = @{
    VMName   = $vmName
    Count    = $ProcessorCount
    Reserve  = 10
    Maximum  = 75
    Passthru = $true
}
Set-VMProcessor @splat | Out-Null



# Configure Memory for the VM
Write-Host -Message '   ---------------------------------------------------------------
       Configuring other parameters...
   ---------------------------------------------------------------
' -ForegroundColor green

$splat = @{
    AutomaticCheckpointsEnabled = $false
    AutomaticStartAction        = 'StartIfRunning'
    AutomaticStopAction         = 'ShutDown'
    ComputerName                = 'localhost'
    Name                        = $vmName
    Note                        = '{0} - {1}' -f $vmName, $vmOsType
    Passthru                    = $true
}
Set-VM @splat | Out-Null

# Enable SecureBoot
Set-VMFirmware -VMName $vmName -SecureBootTemplate 'MicrosoftWindows' -EnableSecureBoot On

# Add virtual TPM
$HGOwner = Get-HgsGuardian 'Hyper-VGuardian' -ErrorAction SilentlyContinue

If (-not $HGOwner) {
    $HGOwner = New-HgsGuardian -Name 'Hyper-VGuardian' -GenerateCertificates
}
$KeyProtector = New-HgsKeyProtector -Owner $HGOwner -AllowUntrustedRoot
Set-VMKeyProtector -VMName $vmName -KeyProtector $KeyProtector.RawData
Enable-VMTPM -VM $vm


#Mount the newly created VHDX file
Write-Host -Message '   ---------------------------------------------------------------
    Mount and patch differential VHDX (inject unattended.xml file)
   ---------------------------------------------------------------
' -ForegroundColor green

# This is not working on Windows 11 October 2011 version
#[System.String]$mount = (Mount-DiskImage -ImagePath $vmVhdNewDisk -StorageType VHDX -Access ReadWrite -PassThru | Get-Disk | Get-Partition | Get-Volume).DriveLetter

# Define new folder for temporary mount VHDx image
$TempMount = New-Item -Path $VmFolder -Name TempMount -ItemType Directory

# Mount VHDx image without drive letter and get the disk
$MountedVhd = Mount-DiskImage -ImagePath $vmVhdNewDisk -NoDriveLetter -PassThru | Get-Disk

# Select ONLY Basic partitions
$Partitions = $MountedVhd | Get-Partition | Where-Object { $_.Type -eq 'Basic' }

# Provide access to the mounted path (C:\VMs\TmpMount\)
$Partitions | Add-PartitionAccessPath -AccessPath $TempMount

# Generate static MAC address
<#
    the number of dynamic MAC addresses that a Hyper-V host can produce is 256.
    Suppose we have the MAC address aa-bb-cc-dd-ee-ff.

    The first 3 octets (aa-bb-cc) refer to a Microsoft Unique Identifier that is used in all Hyper-V hosts (00: 15: 5D).
    The next 2 octets (dd-ee) are generated by the last two octets of the IP address that was first set up on the Hyper-V server.
    The last octet (ff) is generated from the range 0x0 â€“ 0xFF.
#>

# Microsoft Unique Identifier that is used in all Hyper-V hosts (00: 15: 5D)
$TmpMAC = '00-15-5D-'
# next 3 octets
$TmpMAC += [BitConverter]::ToString([BitConverter]::GetBytes((Get-Random -Maximum 0xFFFFFFFFFFFF)), 0, 3)

Get-VM $vmName | Set-VMNetworkAdapter -StaticMacAddress ($TmpMAC.Replace('-', ''))

# Get VM MAC address
#$VmMacAddress = (Get-VM  $vmName | Get-VMNetworkAdapter).MacAddress -replace '..(?!$)', '$&:'


# Get and prepare IP configuration
If (Test-Path -Path $DataFile) {

    try {
        # Read the configuration file (PSD1)
        $ht = Import-PowerShellDataFile $DataFile
        Write-Verbose -Message ('Data File {0} loaded successfully' -f $DataFile)
    } catch {
        throw
    } #end Try-Catch

    # Check if newly created VM exist on the configuration
    if ($ht.AllNodes.ForEach({ $_.NodeName }).contains($VmName)) {

        # Define Hashtable to hold the values from configuration file (PSD1)
        $PC = @{
            NodeName           = [System.String]
            DefaultGatewayIpV4 = [System.String]
            DefaultGatewayIpV6 = [System.String]
            DNS1IpV4           = [System.String]
            DNS2IpV4           = [System.String]
            DNS3IpV4           = [System.String]
            DNS4IpV4           = [System.String]
            DNS5IpV4           = [System.String]
            DNS1IpV6           = [System.String]
            DNS2IpV6           = [System.String]
            DNS3IpV6           = [System.String]
            DNS4IpV6           = [System.String]
            DNS5IpV6           = [System.String]
            TimeZone           = [System.String]
            IPv4               = [System.String]
            MaskV4             = [System.String]
            IPv6               = [System.String]
            MaskV6             = [System.String]
            NetBIOSDomainName  = [System.String]
            DnsDomainName      = [System.String]
            Description        = [System.String]
            Disks              = [System.String]
        }

        # Iterate all nodes
        Foreach ($item in $ht.AllNodes) {
            # Get wildcard data (all nodes)
            If ($item.NodeName -eq '*') {
                $PC.DefaultGatewayIpV4 = $item.DefaultGatewayIpV4
                $PC.DefaultGatewayIpV6 = $item.DefaultGatewayIpV6
                $PC.DNS1IpV4 = $item.DNS1IpV4
                $PC.DNS2IpV4 = $item.DNS2IpV4
                $PC.DNS3IpV4 = $item.DNS3IpV4
                $PC.DNS4IpV4 = $item.DNS4IpV4
                $PC.DNS5IpV4 = $item.DNS5IpV4
                $PC.DNS1IpV6 = $item.DNS1IpV6
                $PC.DNS2IpV6 = $item.DNS2IpV6
                $PC.DNS3IpV6 = $item.DNS3IpV6
                $PC.DNS4IpV6 = $item.DNS4IpV6
                $PC.DNS5IpV6 = $item.DNS5IpV6
                $PC.TimeZone = $item.TimeZone
            } # End If

            # Get specific host data
            If ($item.NodeName -eq $VmName) {
                $PC.IPv4 = $item.IPv4
                $PC.IPv6 = $item.IPv6
                $PC.NetBIOSDomainName = $item.NetBIOSDomainName
                $PC.DnsDomainName = $item.DnsDomainName
                $PC.Description = $item.Description
                Try {
                    $PC.Disks = $item.Disks
                } Catch {
                    $PC.Disks = 'SingleDisk'
                }
            } # End If
        } # End Foreach
    } # End If


} # Get and prepare IP configuration

Write-Verbose -Message ('Ipv4 address:         {0}' -f $PC.IPv4)
Write-Verbose -Message ('Ipv4 Default gateway: {0}' -f $PC.DefaultGatewayIpV4)
Write-Verbose -Message ('Ipv4 Primary DNS:     {0}' -f $PC.DNS1IpV4 )
Write-Verbose -Message ('Ipv4 Secondary DNS:   {0}' -f $PC.DNS2IpV4)
Write-Verbose -Message ('Ipv4 additional DNS:  {0}, {1} and {2}' -f $PC.DNS3IpV4, $PC.DNS4IpV4, $PC.DNS5IpV4)

Write-Verbose -Message ('Ipv6 address:         {0}' -f $PC.IPv6)
Write-Verbose -Message ('Ipv6 Default gateway: {0}' -f $PC.DefaultGatewayIpV6)
Write-Verbose -Message ('Ipv6 Primary DNS:     {0}' -f $PC.DNS1IpV6 )
Write-Verbose -Message ('Ipv6 Secondary DNS:   {0}' -f $PC.DNS2IpV6)
Write-Verbose -Message ('Ipv6 additional DNS:  {0}, {1} and {2}' -f $PC.DNS3IpV6, $PC.DNS4IpV6, $PC.DNS5IpV6)

# IP configuration section of the Unattend file
if ($PC.ipv4 -or $PC.ipv6) {
    $UnattendIpConfig = @"
<component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                        <Metric>10</Metric>
                        <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>
                    </Ipv4Settings>
                    <Ipv6Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                        <Metric>10</Metric>
                        <RouterDiscoveryEnabled>false</RouterDiscoveryEnabled>
                    </Ipv6Settings>
                    <Identifier>$TmpMAC</Identifier>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$($PC.IPv4)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="2">$($PC.IPv6)</IpAddress>
                    </UnicastIpAddresses>
                    <Routes>
                        <Route wcm:action="add">
                            <Identifier>0</Identifier>
                            <Metric>10</Metric>
                            <NextHopAddress>$($PC.DefaultGatewayIpV4)</NextHopAddress>
                            <Prefix>0.0.0.0/0</Prefix>
                        </Route>
                        <Route wcm:action="add">
                            <Identifier>1</Identifier>
                            <Metric>10</Metric>
                            <NextHopAddress>$($PC.DefaultGatewayIpV6)</NextHopAddress>
                            <Prefix>::0/0</Prefix>
                        </Route>
                    </Routes>
                </Interface>
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Identifier>$TmpMAC</Identifier>
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$($PC.DNS1IpV4)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="2">$($PC.DNS2IpV4)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="3">$($PC.DNS3IpV4)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="4">$($PC.DNS4IpV4)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="5">$($PC.DNS5IpV4)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="6">$($PC.DNS1IpV6)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="7">$($PC.DNS2IpV6)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="8">$($PC.DNS3IpV6)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="9">$($PC.DNS4IpV6)</IpAddress>
                        <IpAddress wcm:action="add" wcm:keyValue="10">$($PC.DNS5IpV6)</IpAddress>
                    </DNSServerSearchOrder>
                    <DNSDomain>$($PC.DnsDomainName)</DNSDomain>
                    <DisableDynamicUpdate>false</DisableDynamicUpdate>
                    <EnableAdapterDomainNameRegistration>true</EnableAdapterDomainNameRegistration>
                </Interface>
            </Interfaces>
            <DNSSuffixSearchOrder>
                <DomainName wcm:action="add" wcm:keyValue="1">$($PC.DnsDomainName)</DomainName>
            </DNSSuffixSearchOrder>
        </component>
"@
} else {
    $UnattendIpConfig = $null
} #end If-Else


# Get Domain DN
[string]$AdDn = $PC.DnsDomainName
$AdDn = 'DC={0},DC={1}' -f $AdDn.split('.')[0], $AdDn.split('.')[1]

# Tier0 OUs
switch -wildcard ($VmName) {
    # PAWs
    'Paw0*' {
        $DestOU = ('OU=PawT0,OU=PAW,OU=Admin,{0}' -f $AdDn)
    }
    'Paw1*' {
        $DestOU = ('OU=PawT1,OU=PAW,OU=Admin,{0}' -f $AdDn)
    }
    'Paw2*' {
        $DestOU = ('OU=PawT2,OU=PAW,OU=Admin,{0}' -f $AdDn)
    }
    # Tier0
    {
        ($_ -eq 'Adfs*') -or
        ($_ -eq 'Ca*') -or
        ($_ -eq 'Dsc*') -or
        ('Linux1', 'Linux2' -contains $_) -or
        ($_ -eq 'Mdt*') -or
        ($_ -eq 'Sccm*') -or
        ($_ -eq 'Scom*') -or
        ('SQL1', 'SQL2' -contains $_) -or
        ('Srv1', 'Srv2', 'Srv3', 'Srv4' -contains $_) -or
        ($_ -eq 'Vmm*') -or
        ($_ -eq 'Wac*') -or
        ($_ -eq 'Wsus*')
    } {
        $DestOU = ('OU=InfraT0,OU=Infra,OU=Admin,{0}' -f $AdDn)
    }

    #Tier2
    { 'PC1', 'PC4', 'PC7', 'PC10' -Contains $_ } {
        $DestOU = ('OU=Desktops,OU=BAAD,OU=Sites,{0}' -f $AdDn)
    }
    { 'PC2', 'PC5', 'PC8', 'PC11' -Contains $_ } {
        $DestOU = ('OU=Desktops,OU=GOOD,OU=Sites,{0}' -f $AdDn)
    }
    { 'PC3', 'PC6', 'PC9', 'PC12' -Contains $_ } {
        $DestOU = ('OU=Desktops,OU=UGLY,OU=Sites,{0}' -f $AdDn)
    }
    { 'Lap1', 'Lap4', 'Lap7' -Contains $_ } {
        $DestOU = ('OU=Laptops,OU=BAAD,OU=Sites,{0}' -f $AdDn)
    }
    { 'Lap2', 'Lap5', 'Lap8' -Contains $_ } {
        $DestOU = ('OU=Laptops,OU=GOOD,OU=Sites,{0}' -f $AdDn)
    }
    { 'Lap3', 'Lap6', 'Lap9' -Contains $_ } {
        $DestOU = ('OU=Laptops,OU=UGLY,OU=Sites,{0}' -f $AdDn)
    }
    Default {
        $DestOU = ('OU=Quarantine-PC,{0}' -f $AdDn)
    }
} #end Switch

# Domain Controllers
If ($VmName -like 'DC') {
    $DestOU = ('OU=InfraStaging,OU=Infra,OU=Admin,{0}' -f $AdDn)
} #end If

# Tier1 OU
If ('Srv5', 'Srv6', 'Srv7', 'Srv8', 'Srv9', 'Srv10', 'Srv11', 'Srv12', 'Srv13', 'Srv14', 'Srv15', 'Srv16', 'Srv17', 'Srv18', 'Srv19', 'Srv20' -Contains $vmName) {
    $DestOU = ('OU=Servers,{0}' -f $AdDn)
} #end If

If ('SQL3', 'Srv4' -Contains $vmName) {
    $DestOU = ('OU=Sql,OU=Servers,{0}' -f $AdDn)
} #end If

If ('Linux3', 'Linux4', 'Linux5', 'Linux6' -Contains $vmName) {
    $DestOU = ('OU=Linux,OU=Servers,{0}' -f $AdDn)
} #end If


# Domain Join section of the Unattend file
If ($VmName -ne ('DC1' -or 'DC5' -or 'DC9')) {

    Write-Verbose -Message ('Destination OU for {0} will be "{1}"' -f $VmName, $DestOU)

    $UnattendDomainJoin = @"
<component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Identification>
                <Credentials>
                    <Domain>$($PC.DnsDomainName)</Domain>
                    <Password>P@ssword 123456</Password>
                    <Username>TheUgly</Username>
                </Credentials>
                <JoinDomain>$($PC.DnsDomainName)</JoinDomain>
                <MachineObjectOU>$DestOU</MachineObjectOU>
            </Identification>
        </component>
"@

} else {

    Write-Verbose -Message ('VM {0} will not be joined to any domain' -f $VmName)

    $UnattendDomainJoin = $null

} #end If-Else


# Generate Unattend file
$unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>0c0a:0000040a</InputLocale>
            <SystemLocale>es-ES</SystemLocale>
            <UILanguageFallback>es-ES</UILanguageFallback>
            <UserLocale>es-ES</UserLocale>
            <UILanguage>en-US</UILanguage>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComplianceCheck>
                <DisplayReport>OnError</DisplayReport>
            </ComplianceCheck>
            <Display>
                <HorizontalResolution>1920</HorizontalResolution>
                <VerticalResolution>1080</VerticalResolution>
            </Display>
            <DynamicUpdate>
                <Enable>true</Enable>
            </DynamicUpdate>
            <UserData>
                <AcceptEula>true</AcceptEula>
                <FullName>Vicente R. Eguibar</FullName>
                <Organization>Eguibar IT</Organization>
            </UserData>
        </component>
    </settings>
    <settings pass="offlineServicing">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OfflineUserAccounts>
                <OfflineAdministratorPassword>
                    <Value>UABAAHMAcwB3AG8AcgBkACAAMQAyADMANAA1ADYATwBmAGYAbABpAG4AZQBBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAFAAYQBzAHMAdwBvAHIAZAA=</Value>
                    <PlainText>false</PlainText>
                </OfflineAdministratorPassword>
            </OfflineUserAccounts>
            <RegisteredOrganization>Eguibar IT</RegisteredOrganization>
            <RegisteredOwner>Vicente R. Eguibar</RegisteredOwner>
            <ComputerName>$VmName</ComputerName>
        </component>
        <component name="Microsoft-Windows-LUA-Settings" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <EnableLUA>false</EnableLUA>
        </component>
    </settings>
    <settings pass="generalize">
        <component name="Microsoft-Windows-Security-SPP" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SkipRearm>1</SkipRearm>
        </component>
        <component name="Microsoft-Windows-PnpSysprep" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RegisteredOrganization>Eguibar IT</RegisteredOrganization>
            <RegisteredOwner>Vicente R. Eguibar</RegisteredOwner>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>0c0a:0000040a</InputLocale>
            <SystemLocale>es-ES</SystemLocale>
            <UILanguageFallback>es-ES</UILanguageFallback>
            <UserLocale>es-ES</UserLocale>
            <UILanguage>en-US</UILanguage>
        </component>
        <component name="Microsoft-Windows-Security-SPP-UX" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SkipAutoActivation>true</SkipAutoActivation>
        </component>
        <component name="Microsoft-Windows-SQMApi" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <CEIPEnabled>0</CEIPEnabled>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Display>
                <HorizontalResolution>1920</HorizontalResolution>
                <VerticalResolution>1080</VerticalResolution>
            </Display>
            <ComputerName>$VmName</ComputerName>
            <RegisteredOrganization>Eguibar IT</RegisteredOrganization>
            <RegisteredOwner>Vicente R. Eguibar</RegisteredOwner>
            <TimeZone>Romance Standard Time</TimeZone>
        </component>
        $UnattendIpConfig
        $UnattendDomainJoin
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>1</ProtectYourPC>
                <SkipMachineOOBE>true</SkipMachineOOBE>
                <SkipUserOOBE>true</SkipUserOOBE>
            </OOBE>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>powershell -NoLogo -sta -NoProfile -NoInteractive -Command {Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force}</CommandLine>
                    <Description>Set Execution Policy to RemoteSigned</Description>
                    <Order>1</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>powershell -NoLogo -sta -NoProfile -NoInteractive -Command {Enable-PSRemoting -SkipNetworkProfileCheck -Force}</CommandLine>
                    <Description>Enable PsRemoting</Description>
                    <Order>2</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>powercfg /HIBERNATE OFF</CommandLine>
                    <Description>Remove hibernation on the computer</Description>
                    <Order>3</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>winrm quickconfig -q -force</CommandLine>
                    <Description>Enable WinRM</Description>
                    <Order>4</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                $RSATtools
                $GUIprofiles
            </FirstLogonCommands>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>UABAAHMAcwB3AG8AcgBkACAAMQAyADMANAA1ADYAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBQAGEAcwBzAHcAbwByAGQA</Value>
                    <PlainText>false</PlainText>
                </AdministratorPassword>
            </UserAccounts>
            <Display>
                <HorizontalResolution>1920</HorizontalResolution>
                <VerticalResolution>1080</VerticalResolution>
            </Display>
            <RegisteredOrganization>Eguibar IT</RegisteredOrganization>
            <RegisteredOwner>Vicente R. Eguibar</RegisteredOwner>
            <TimeZone>Romance Standard Time</TimeZone>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64"
            publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
            xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>0c0a:0000040a</InputLocale>
            <SystemLocale>es-ES</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>es-ES</UILanguageFallback>
            <UserLocale>es-ES</UserLocale>
        </component>
    </settings>
</unattend>
"@

# Copy the above unattend to VHDX C:\Windows\Panther\unattend.xml (Alternatively to C:\Windows\System32\Sysprep\Unattend.xml)
# Set-Content -Value $unattend -Path ('{0}:\Windows\Panther\unattend.xml' -f $mount.Trim())
Write-Verbose -Message 'Creating Unattend.xml file on new VM.'
Set-Content -Value $unattend -Path ('{0}\Windows\Panther\unattend.xml' -f $TempMount) -Force
Set-Content -Value $unattend -Path ('{0}\Windows\System32\Sysprep\unattend.xml' -f $TempMount) -Force

Write-Verbose -Message ('
    Copy of Unattend.xml file created on
    {0}' -f ('C:\VMs\Unattend_{0}_{1}.xml' -f $VmName, (Get-Date -Format 'dd-MMM-yyyy'))
)
Set-Content -Value $unattend -Path ('C:\VMs\Unattend_{0}_{1}.xml' -f $VmName, (Get-Date -Format 'dd-MMM-yyyy'))

# Make windows to use the unattend.xml file
#Use-WindowsUnattend -Path ('{0}:\' -f $mount.Trim()) -UnattendPath ('{0}:\Windows\Panther\unattend.xml' -f $mount.Trim()) -LogLevel WarningsInfo
Write-Verbose -Message 'Sealing image after apply Unattend.xml'
Use-WindowsUnattend -Path $TempMount -UnattendPath ('{0}\Windows\System32\Sysprep\unattend.xml' -f $TempMount) -LogLevel WarningsInfo

# Remove cached unattend.xml file from C:\WINDOWS\Panther folder
Remove-Item -Path ('{0}\Windows\Panther\unattend.xml' -f $TempMount) -Force

#Dismount Image
Dismount-DiskImage -ImagePath $vmVhdNewDisk -StorageType VHDX

# Remove the mountPoint
Remove-Item $TempMount -Force

# Configure additional disks on DC
If ($PC.Disks -eq 'Multiple-Disks') {
    Write-Verbose -Message 'Creating additional disk for DomainController'
    $DcDisks = @(
        'N-NTDS',
        'L-NTDSlogs',
        'S-SYSVOL',
        'P-Pagefile',
        'T-Temp',
        'E-EventLogs'
    )
    Foreach ($Disk in $DcDisks) {
        # Get the current disk path
        $CurrentDisk = '{0}\{1}\{2}.vhdx' -f $VmFolder, $vmName, $Disk

        #Check if current disk exists
        $DiskExists = Get-VHD -Path $CurrentDisk -ErrorAction SilentlyContinue
        If ($DiskExists) {
            Remove-Item $CurrentDisk -Force | Out-Null
        }

        #Create the disk
        $splat = @{
            Path      = $CurrentDisk
            SizeBytes = 32GB
            Dynamic   = $true
        }
        New-VHD @splat | Out-Null

        # Attach the disk
        Add-VMHardDiskDrive -VMName $vmName -Path $CurrentDisk -ControllerType SCSI
    }
}

# Starting VM
Write-Host -Message '   ---------------------------------------------------------------
       Starting VM
   ---------------------------------------------------------------
' -ForegroundColor green

Start-VM -VM $VM
Wait-VM -VM $vm -For Heartbeat




Wait-VM -VM $vm -For Heartbeat

Write-Host -Message '#########################################################################
#                                                                       #
#      Virtual Machine created. Now you can start playing with it.      #
#                                                                       #
#########################################################################
' -ForegroundColor green



# $VmSwitchName = New-VMSwitch -Name 'LAN' -SwitchType External -Notes 'vSwitch (LAN) used for VM to communicate, having physical host ICS enabled for this switch'

# GET-VM | GET-VMNetworkAdapter | Connect-VMNetworkAdapter -Switchname 'vSwitch'

# Set-NetConnectionProfile -InterfaceAlias 'LAN' -NetworkCategory Private
