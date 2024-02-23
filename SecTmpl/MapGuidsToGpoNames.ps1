# Map GUIDs to GPO display names
<#
.SYNOPSIS

.DESCRIPTION

.PARAMETER rootdir

.EXAMPLE

#>

param(
    [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 0)]
    [String]$rootdir
    )
Begin {
    $results = @{}
    If(-not $rootdir) {
        $rootdir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
        Write-Verbose -Message ('Root path is: {0}' -f $rootdir)
    }
}

Process {
    Get-ChildItem -Recurse -Include backup.xml $rootdir |ForEach-Object{
        $guid = $_.Directory.Name
        $x = [xml](get-content $_)
        $dn = $x.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
        # $dn + "`t" + $guid
        $results.Add($dn, $guid)
    }
}

End {
    $results | format-table Name, Value -AutoSize
}



