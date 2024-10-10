<#
    .Script purpose

    .NOTES
        Version:         1.0
        DateModified:    2/Oct/2018
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
Start-Transcript -Path ('{0}\LAPS-Extension-{1}.log' -f $DMscripts, (Get-Date -Format 'dd-MMM-yyyy')) -NoClobber -Append -Force
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

$AllModules = @(
    'ActiveDirectory',
    'EguibarIT',
    'EguibarIT.DelegationPS',
    'ServerManager',
    'LAPS'
)
foreach ($item in $AllModules) {
    Write-Verbose -Message ('Importing module {0}' -f $Item)
    $Splat = @{
        name    = $item
        Force   = $true
        Verbose = $false
    }
    Import-Module @Splat | Out-Null

}
[System.Environment]::NewLine



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



If ( -Not (Test-Path Variable:Variables)) {
    Get-AttributeSchemaHashTable
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
Set-ItemProperty -Path $regkeyPath -Name 'DefaultUserName' -Value $confXML.N.Admin.Users.NewAdmin.Name

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
###############################################################################
# END Set Autologon
###############################################################################

# Check if schema is extended for LAPS. Extend it if not.
Try {

    # Look for old LAPS attribute
    #if ($null -eq $Variables.guidmap['ms-Mcs-AdmPwd']) {
    if ($null -eq $Variables.guidmap['msLAPS-Password']) {
        Write-Verbose -Message 'LAPS is NOT supported on this environment. Proceeding to configure it by extending the Schema.'


        # Make the user a Domain Admin
        Add-ADGroupMember -Identity 'Domain Admins' -Members $env:username

        # Check if user can change schema
        if (-not (Get-ADGroupMember -Identity 'Schema Admins' | Where-Object { $_.name -eq $env:USERNAME })) {

            Write-Verbose -Message 'Member is not a Schema Admin... adding it.'
            Add-ADGroupMember -Identity 'Schema Admins' -Members $env:username

            Write-Verbose -Message '5 second pause to give Win a chance to catch up and reboot'
            Start-Sleep -Seconds 5

            # Stop Logging
            Stop-Transcript

            Write-Verbose -Message 'Reboot???'
            Restart-Computer -Force
        } #end If

        # Modify Schema
        try {
            Write-Verbose -Message 'Modify the schema...!'

            <#

            Remove LEGACY LAPS

            Write-Verbose -Message 'Modifying old LAPS (AdmPwd.PS)'
            Update-AdmPwdADSchema -Verbose

            [System.Environment]::NewLine
            [System.Environment]::NewLine

            #>

            Write-Verbose -Message 'Modifying Windows LAPS'
            Update-LapsADSchema -Confirm:$false -Verbose


        } catch {
            throw
        } finally {
            # If Schema extension OK, remove user from Schema Admin
            Remove-ADGroupMember -Identity 'Schema Admins' -Members $env:username -Confirm:$false
        } #end Try-Catch-Finally

    } else {

        ###############################################################################
        # START 4-ConfigureDom.ps1 at next Logon (Scheduled Task)
        ###############################################################################

        If (($null -eq $DMscripts) -or ($DMscripts -eq '')) {
            $DMscripts = 'C:\PsScripts'
        }

        $File = '4-ConfigureDom.ps1'
        $NextFile = '{0}\{1}' -f $DMscripts, $file
        $UserID = $confXML.N.Admin.Users.NewAdmin.Name
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
            verbose     = $true
        }
        try {
            Register-ScheduledTask @Splat
        } catch {
            throw
        } finally {
            # Unregister previous scheduled task
            Unregister-ScheduledTask -TaskName 'LAPS-Extension.ps1' -Confirm:$false -Verbose
        } #end Try-Catch-Finally


        ###############################################################################
        # END
        ###############################################################################

        Write-Verbose -Message '5 second pause to give Win a chance to catch up and reboot'
        Start-Sleep -Seconds 5

    } #end If-Else

} catch {
    Throw
}

# Stop Logging
Stop-Transcript

Write-Verbose -Message 'Reboot???'
Restart-Computer -Force
