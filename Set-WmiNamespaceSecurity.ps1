# Copyright (c) Microsoft Corporation.  All rights reserved.
# For personal use only.  Provided AS IS and WITH ALL FAULTS.

# Set-WmiNamespaceSecurity.ps1
# Example: Set-WmiNamespaceSecurity root/cimv2 add steve Enable,RemoteAccess

# Taken from https://live.paloaltonetworks.com/t5/Management-Articles/PowerShell-Script-for-setting-WMI-Permissions-for-User-ID/ta-p/53646
# Modified by Stuart Clarkson (https://github.com/Tras2)
# Modified by Kirill Nikolaev (exchange12rocks athttps://gist.github.com/exchange12rocks/950aa29f66e6369d2c02fa8583bb3a75)

Param (
    [parameter(Mandatory = $true, Position = 0)]
    [String] $namespace,

    [parameter(Mandatory = $true, Position = 1)]
    [ValidateSet('Add', 'Delete')]
    [String] $operation,

    [parameter(Mandatory = $true, Position = 2)]
    [string] $account,

    [parameter(Mandatory = $true, Position = 3)]
    [ValidateSet('Enable', 'MethodExecute', 'FullWrite', 'PartialWrite', 'ProviderWrite', 'RemoteAccess', 'ReadSecurity', 'WriteSecurity')]
    [string[]] $permissions,

    [parameter(Mandatory = $true, Position = 4)]
    [Parameter()][ValidateSet('User', 'Group')]
    [String]$AccountType,

    [parameter(Mandatory = $false, Position = 5)]
    [Switch]$allowInherit,

    [parameter(Mandatory = $false, Position = 6)]
    [Switch]$deny,

    [parameter(Mandatory = $false, Position = 7)]
    [string] $computerName = '.',

    [parameter(Mandatory = $false, Position = 8)]
    [System.Management.Automation.PSCredential] $credential = $null
)

Begin {

    $ErrorActionPreference = 'Stop'

    $remoteparams = [Hashtable]::New()
    $OBJECT_INHERIT_ACE_FLAG = 0x1
    $CONTAINER_INHERIT_ACE_FLAG = 0x2
    $ACCESS_ALLOWED_ACE_TYPE = 0x0
    $ACCESS_DENIED_ACE_TYPE = 0x1

    Function Get-AccessMaskFromPermission($permissions) {
        $WBEM_ENABLE = 1
        $WBEM_METHOD_EXECUTE = 2
        $WBEM_FULL_WRITE_REP = 4
        $WBEM_PARTIAL_WRITE_REP = 8
        $WBEM_WRITE_PROVIDER = 0x10
        $WBEM_REMOTE_ACCESS = 0x20
        $WBEM_RIGHT_SUBSCRIBE = 0x40
        $WBEM_RIGHT_PUBLISH = 0x80
        $READ_CONTROL = 0x20000
        $WRITE_DAC = 0x40000

        $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE, $WBEM_METHOD_EXECUTE, $WBEM_FULL_WRITE_REP, `
            $WBEM_PARTIAL_WRITE_REP, $WBEM_WRITE_PROVIDER, $WBEM_REMOTE_ACCESS, `
            $READ_CONTROL, $WRITE_DAC
        $WBEM_RIGHTS_STRINGS = 'Enable', 'MethodExecute', 'FullWrite', 'PartialWrite', `
            'ProviderWrite', 'RemoteAccess', 'ReadSecurity', 'WriteSecurity'

        $permissionTable = @{}

        for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
            $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
        } #end For

        $accessMask = 0

        foreach ($permission in $permissions) {
            if (-not $permissionTable.ContainsKey($permission.ToLower())) {
                throw "Unknown permission: $permission`nValid permissions: $($permissionTable.Keys)"
            }
            $accessMask += $permissionTable[$permission.ToLower()]
        } #end ForEach

        $accessMask
    } #end Function

    if ($PSBoundParameters.ContainsKey('Credential')) {
        $remoteparams.Add('Credential', $credential )
    } #end If

    If ($PSBoundParameters.ContainsKey('computerName')) {
        $remoteparams.Add('ComputerName', $computerName)
    } else {
        $remoteparams.Add('ComputerName', $env:COMPUTERNAME)
    } #end If-Else

} #end Begin
Process {


    $cimSession = New-CimSession $remoteparams

    $SecurityDescriptor = Invoke-CimMethod -CimSession $CimSession -Namespace $Namespace -ClassName '__SystemSecurity' -MethodName 'GetSecurityDescriptor'

    if (-not $SecurityDescriptor) {
        throw "Failed to get the current security descriptor for namespace $Namespace."
        throw "GetSecurityDescriptor failed: $($SecurityDescriptor.ReturnValue)"
    } #end If

    $acl = $SecurityDescriptor.Descriptor

    $computerName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name

    if ($account.Contains('\')) {
        $domainaccount = $account.Split('\')
        $domain = $domainaccount[0]
        if (($domain -eq '.') -or ($domain -eq 'BUILTIN')) {
            $domain = $computerName
        }
        $accountname = $domainaccount[1]
    } elseif ($account.Contains('@')) {
        $domainaccount = $account.Split('@')
        $domain = $domainaccount[1].Split('.')[0]
        $accountname = $domainaccount[0]
    } else {
        $domain = $computerName
        $accountname = $account
    } #end If-ElseIf-Else


    switch ($operation) {
        'Add' {
            if ($permissions -eq $null) {
                throw '-Permissions must be specified for an add operation'
            }
            $accessMask = Get-AccessMaskFromPermission($permissions)

            $ace = New-CimInstance (Get-CimClass -ClassName 'Win32_ACE') -ClientOnly

            $ace.AccessMask = $accessMask

            if ($allowInherit) {
                $ace.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
            } else {
                $ace.AceFlags = 0
            }

            $trustee = New-CimInstance (Get-CimClass Win32_Trustee) -ClientOnly
            $trustee.SidString = (Get-ADGroup -Identity SL_DcManagement).sid.value.tostring()
            $trustee.Domain = $domain
            $trustee.Name = $accountname
            $ace.Trustee = $trustee

            if ($deny) {
                $ace.AceType = $ACCESS_DENIED_ACE_TYPE
            } else {
                $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
            }

            $acl.DACL += $ace
        }

        'Delete' {
            if ($permissions -ne $null) {
                throw 'Permissions cannot be specified for a delete operation'
            }

            [System.Management.ManagementBaseObject[]]$newDACL = @()
            foreach ($ace in $acl.DACL) {
                if ($ace.Trustee.SidString -ne $win32account.Sid) {
                    $newDACL += $ace.psobject.immediateBaseObject
                }
            }

            $acl.DACL = $newDACL.psobject.immediateBaseObject
        }

        default {
            throw "Unknown operation: $operation`nAllowed operations: add delete"
        }
    } #end Switch

    $result = Invoke-CimMethod -CimSession $CimSession -Namespace $Namespace -ClassName '__SystemSecurity' -MethodName 'SetSecurityDescriptor' -Arguments @{ Descriptor = $acl }


    if ($result.ReturnValue -ne 0) {
        throw "SetSecurityDescriptor failed: $($output.ReturnValue)"
    } #end If
} #end Process
