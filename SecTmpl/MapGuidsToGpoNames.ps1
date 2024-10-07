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
    $results = [ordered]@{}

    If (-not $rootdir) {
        $rootdir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
        Write-Verbose -Message ('Root path is: {0}' -f $rootdir)
    }
}

Process {
    $AllElements = Get-ChildItem -Recurse -Include backup.xml $rootdir

    Foreach ($item in $AllElements) {

        try {
            $guid = $item.Directory.Name
            $x = [xml](Get-Content $item)
            $dn = $x.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
            $results.Add($dn, $guid)
        } catch {
            Write-Error -Message ('
                Something went wrong.
                Policy GUID: {0}
                Policy Name: {1}
                {2}' -f
                $guid, $dn, $_
            )
        }
    } #end Foreach
    Write-Output ('Found {0} GPO backups' -f $results.Count)
}

End {
    $results.GetEnumerator() | Sort-Object -Property name | Format-Table Name, Value -AutoSize
}



