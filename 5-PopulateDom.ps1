<#
    .Script purpose
        Populate domain
            Create Sites
            Create Users
            Create Service Accounts
            Configure Service Accounts
            Configure Groups and membership
            Configure Shares and LocalGroups
            Create and Configure Semi-Privileged Admins
            Configure Housekeeping
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

# Get Folder where all Delegation Model scripts & files
$DMscripts = ('{0}\PsScripts' -f $env:SystemDrive)

# Logging all output
Start-Transcript -Path ('{0}\5-PopulateDom-{1}.log' -f $DMscripts, (Get-Date -Format 'dd-MMM-yyyy')) -NoClobber -Append -Force
#$DebugPreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'
#$InformationPreference = 'Continue'
#$ErrorActionPreference = 'Continue'

# Clear any previous error
$error.clear()

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

$VerbosePreference = 'SilentlyContinue'

Import-Module -Name ServerManager -Verbose:$false | Out-Null
Import-Module -Name GroupPolicy -SkipEditionCheck -Verbose:$false | Out-Null

$AllModules = @(
    'ActiveDirectory',
    'EguibarIT',
    'EguibarIT.DelegationPS',
    'EguibarIT.HousekeepingPS'
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
$VerbosePreference = 'Continue'
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
    if (-not (Test-Path -Path $DMscripts\Config.xml)) {
        throw 'Config.xml file not found'
    }
} #end try-catch-finally



# Naming conventions hashtable
$NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix
    'sg'     = $confXML.n.NC.GlobalGroupPreffix
    'su'     = $confXML.n.NC.UniversalGroupPreffix
    'Delim'  = $confXML.n.NC.Delimiter
    'T0'     = $confXML.n.NC.AdminAccSufix0
    'T1'     = $confXML.n.NC.AdminAccSufix1
    'T2'     = $confXML.n.NC.AdminAccSufix2
}

#('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
# SG_PAWM_T0


###############################################################################
# START Create Sites OU's (as defined on the CSV file)
###############################################################################
$OUsToCreate, $existingOU, $i, $parameters = $null

[System.Environment]::NewLine
Write-Verbose -Message 'Start creating SITEs OU'
[System.Environment]::NewLine

# Get the Unique records of the OU field on the users CSV file
$OUsToCreate = Import-Csv -Delimiter ';' -Path (Join-Path -Path $DMscripts -ChildPath $confXML.n.userCSVfile -Resolve) | Select-Object -Property OU | Sort-Object -Property OU -Unique

# Will be used below again
# Iterate through the array of OU's
ForEach ($Ou in $OUsToCreate) {
    $i ++

    $parameters = @{
        Activity         = 'Creating a total of {0} New Sites' -f $OUsToCreate.Count
        Status           = 'Creating Site number {0}. ' -f $i
        PercentComplete  = ($i / $OUsToCreate.Count) * 100
        CurrentOperation = 'Processing site: {0}' -f $Ou.ou
    }
    Write-Progress @parameters

    # Check if the OU already exist. Unique name. Has to be using -Filter to avoid error.
    $OuDistinguishedName = 'OU={0},OU={1},{2}' -f $Ou.ou, $confXML.n.Sites.OUs.SitesOU.Name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()

    $existingOU = Get-ADOrganizationalUnit -Filter { DistinguishedName -like $OuDistinguishedName } -ErrorAction SilentlyContinue
    $error.clear()

    if (-not($existingOU)) {

        Write-Verbose -Message ('Creating {0} OU' -f $Ou.ou)

        # Create site OU
        $Splat = @{
            ouName        = $Ou.ou
            ouDescription = '{0} Site root' -f $Ou.ou
            CreateLAPS    = $true
            GpoBackupPath = Join-Path -Path $DMscripts -ChildPath SecTmpl
            ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
            Verbose       = $true
        }
        New-DelegateSiteOU @Splat
    } else {
        Write-Verbose -Message ('OU {0} already exists. Skipping.' -f $Ou.ou)
    }
}
###############################################################################
# END  Create Sites OU's
###############################################################################





###############################################################################
# START Populating AD Users from CSV
###############################################################################
$UserList, $i, $parameters = $null

[System.Environment]::NewLine
Write-Verbose -Message 'Start creating Users in their corresponding OU'
[System.Environment]::NewLine

#Import users CSV
$UserList = Import-Csv -Delimiter ';' -Path (Join-Path -Path $DMscripts -ChildPath $confXML.n.userCSVfile -Resolve)


#Loop through all items in the CSV
ForEach ($item In $UserList) {
    $i ++

    $parameters = @{
        Activity         = 'Creating a total of {0} Users' -f $UserList.Count
        Status           = 'Creating User number {0}  ' -f $i
        PercentComplete  = ($i / $UserList.Count) * 100
        CurrentOperation = '      Processing User...: {0}' -f $item.DisplayName
    }
    Write-Progress @parameters

    # Create correct UPN using givenName.SurName
    If ($null -ne $item.givenName) {
        If ($null -ne $item.surname) {
            $correctName = '{0}.{1}' -f $item.givenName, $item.surname
        }
    } else {
        $correctName = $item.SamAccountName

        # Remove any invalid character here
        $correctName = $correctName.Replace('.', '')
    }

    $correctName = $correctName.TrimEnd('.')

    # Create final DN for the existingOU
    $finalOU = 'OU=Users,OU={0},OU={1},{2}' -f $item.ou, $confXML.n.Sites.OUs.SitesOU.Name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()

    # Create final DN for the existingOU
    $finalUPN = '{0}@{1}' -f $CorrectName, $env:userdnsdomain

    #Set the HomeDirectory
    $HomeDirectory = '\\{0}\{1}\{2}' -f $env:USERDNSDOMAIN, $confXML.N.Shares.HomeFoldersName, $item.SamAccountName

    $parameters = @{
        Path                  = $finalOU
        AccountPassword       = (ConvertTo-SecureString -String $confXML.N.DefaultPassword -AsPlainText -Force)
        ChangePasswordAtLogon = $false
        Enabled               = $true
        UserPrincipalName     = $finalUPN
        SamAccountName        = $item.SamAccountName
        HomeDirectory         = $HomeDirectory
        OtherAttributes       = @{employeeType = $item.employeetype }
    }

    # Create the user
    $item | New-ADUser @parameters


    $newHomeFolder = '{0}\{1}\{2}' -f $confXML.N.Shares.ShareLocation, $confXML.N.Shares.HomeFoldersName, $item.SamAccountName

    If (-not(Test-Path -Path $newHomeFolder)) {
        # Create the new HomeFolder Directory
        New-Item -Path $newHomeFolder -ItemType Directory

    }

    Revoke-Inheritance -path $newHomeFolder -RemoveInheritance -KeepPermissions
    Revoke-NTFSPermissions -path $newHomeFolder -object EVERYONE -permission 'FullControl, ChangePermissions'
    Grant-NTFSPermission -path $newHomeFolder -object $item.Name -permission 'FullControl, ChangePermissions'

    # Add the corresponding Photo to the user
    # Read the path and file name
    $PhotoFile = '{0}\Pic\{1}.jpg' -f $DMScripts, $item.SamAccountName
    # Get the content of the JPG file
    #$photo = [byte[]](Get-Content -Path $PhotoFile -AsByteStream -Raw)
    [byte[]]$photo = [System.IO.File]::ReadAllBytes($PhotoFile)
    # Set the Photo to the AD user
    Set-ADUser -Identity $item.SamAccountName -Replace @{thumbnailPhoto = $photo }

}
###############################################################################
# END Populating AD Users from CSV
###############################################################################









# <<<<<< Not working on W2k8. CMDlet is different >>>>>>
###############################################################################
# START creating Managed Service Accounts from CSV
###############################################################################
$SvcAccList, $TmpOuDN, $TierGroup, $parameters = $null

[System.Environment]::NewLine
Write-Verbose -Message 'Start creating gMSAs on its corresponding Tier'
[System.Environment]::NewLine

$SvcAccPath = 'OU={0},OU={1},{2}' -f $confXML.n.Admin.OUs.ItServiceAccountsOU.name, $confXML.n.Admin.OUs.ItAdminOU.name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()


# Create the KDS Root Key (only once per domain).  This is used by the KDS service on DCs (along with other information) to generate passwords
# http://blogs.technet.com/b/askpfeplat/archive/2012/12/17/windows-server-2012-group-managed-service-accounts.aspx
# If working in a test environment with a minimal number of DCs and the ability to guarantee immediate replication, please use:
#    Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10))
Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))

#Import ServiceAccounts CSV
$SvcAccList = Import-Csv -Delimiter ';' -Path (Join-Path -Path $DMscripts -ChildPath $confXML.n.svcaccCSVfile -Resolve)

$i = 0

ForEach ($item In $SvcAccList) {
    $i ++

    $parameters = @{
        Activity         = 'Creating a total of {0} Managed Service Accounts' -f $SvcAccList.Count
        Status           = 'Creating Managed Service Account number {0}  ' -f $i
        PercentComplete  = ($i / $SvcAccList.Count) * 100
        CurrentOperation = '      Processing Managed Service Account...: {0}' -f $item.Name
    }
    Write-Progress @parameters

    $TmpOuDN = $null
    $TierGroup = $null

    # Check which tier the SA belongs to
    switch ($item.Tier) {
        0 {
            $TmpOuDN = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $SvcAccPath; $TierGroup = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name
        }
        1 {
            $TmpOuDN = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT1OU.name, $SvcAccPath; $TierGroup = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name
        }
        2 {
            $TmpOuDN = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT2OU.name, $SvcAccPath; $TierGroup = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
        }
    }




    $params = @{
        Name                   = $item.name
        SamAccountName         = $item.name
        DNSHostName            = ('{0}.{1}' -f $item.name, $env:USERDNSDOMAIN)
        AccountNotDelegated    = $true
        Description            = $item.Description
        DisplayName            = $item.DisplayName
        KerberosEncryptionType = 'AES128,AES256'
        Path                   = $TmpOuDN
        enabled                = $True
        TrustedForDelegation   = $false
        ServicePrincipalName   = ('HOST/{0}.{1}' -f $item.name, $env:USERDNSDOMAIN)
    }

    $ReplaceParams = @{
        Replace = @{
            'c'                 = 'MX'
            'co'                = 'Mexico'
            'company'           = $confXML.n.RegisteredOrg
            'department'        = 'IT'
            'employeeType'      = 'T{0}' -f $item.Tier
            'employeeID'        = 'ServiceAccount'
            'info'              = $item.Description
            'l'                 = 'Puebla'
            'mail'              = 'CEO@eguibarIT.com'
            'title'             = $item.DisplayName
            'userPrincipalName' = '{0}@{1}' -f $item.Name, $env:USERDNSDOMAIN
        }
    }

    try {
        New-ADServiceAccount @params | Set-ADServiceAccount @ReplaceParams
    } catch {
        throw
    }




    Add-ADGroupMember -Identity $TierGroup -Members ('{0}$' -f $Item.Name)
}

# Add all managed service accounts to the group
#Get-ADServiceAccount -filter * -SearchBase $SvcAccPath | ForEach-Object { Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.name) -Members $_ }

# Add all un-managed service accounts to the group
#Get-ADUser -filter * -SearchBase $SvcAccPath | ForEach-Object { Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.name) -Members $_ }

###############################################################################
# END creating ServiceAcc from CSV
###############################################################################









###############################################################################
# START Creating AD Groups/Membership from CSV
###############################################################################
$GroupList, $i, $parameters = $null

[System.Environment]::NewLine
Write-Verbose -Message 'Start creating Groups and GroupMembership in their corresponding OU'
[System.Environment]::NewLine

#Import Groups CSV
$GroupList = Import-Csv -Delimiter ';' -Path (Join-Path -Path $DMscripts -ChildPath $confXML.n.groupCSVfile -Resolve)

$i = 0

#Loop through all items in the CSV
ForEach ($item In $GroupList) {
    $i ++

    $parameters = @{
        Activity         = 'Creating a total of {0} Groups' -f $GroupList.Count
        Status           = 'Creating Group number {0}  ' -f $i
        PercentComplete  = ($i / $GroupList.Count) * 100
        CurrentOperation = '      Processing Group...: {0}' -f $item.Name
    }
    Write-Progress @parameters
    If ($item.OU -eq 'Global') {
        $path = 'OU={0},OU={1},OU={2},{3}' -f $confXML.n.Sites.OUs.OuSiteGlobalGroups.Name, $confXML.n.Sites.OUs.OuSiteGlobal.Name, $confXML.n.Sites.OUs.SitesOU.Name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()

        [string]$TMPname = $item.name.ToString()
        if (-not (Get-ADGroup -Filter { (Name -like $TMPname) })) {
            # Create the Group in the GLOBAL container
            $item | New-ADGroup -GroupCategory Security -GroupScope Global -Path $path
        }
    } else {
        $path = 'OU={0},OU={1},OU={2},{3}' -f $confXML.n.Sites.OUs.OuSiteGroup.Name, $item.ou, $confXML.n.Sites.OUs.SitesOU.Name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()

        [string]$TMPname = $item.name.ToString()
        if (-not (Get-ADGroup -Filter { (Name -like $TMPname) })) {
            # Create the Group within the corresponding site
            $item | New-ADGroup -GroupCategory Security -GroupScope Global -Path $path
        }
    }

    $AllStates = @('Alberta', 'Asturias', 'Bahia', 'British Columbia', 'Calabria', 'Dijon', 'Gauteng', 'Jalisco', 'Limpopo', 'Lyon', 'Madrid', 'Okinawa', 'Osaka', 'Puebla', 'Rio de Janeiro', 'Sao Paulo', 'Saskachewan', 'Sicily', 'Tokio', 'Tolouse', 'Toscana', 'Valencia', 'Veracruz', 'Western Cape')

    # Add the users to the group by filtering by country
    If ($AllStates -contains $item.name) {
        # Set the 2 letter ISO code for the country
        switch ( $item.name) {
            { @('Alberta', 'British Columbia', 'Saskachewan') -contains $_ } {
                $strCountry = 'CA'
            }
            { @('Asturias', 'Madrid', 'Valencia') -contains $_ } {
                $strCountry = 'ES'
            }
            { @('Dijon', 'Lyon', 'Tolouse') -contains $_ } {
                $strCountry = 'FR'
            }
            { @('Gauteng', 'Limpopo', 'Western Cape') -contains $_ } {
                $strCountry = 'SA'
            }
            { @('Okinawa', 'Osaka', 'Tokio') -contains $_ } {
                $strCountry = 'JP'
            }
            { @('Jalisco', 'Puebla', 'Veracruz') -contains $_ } {
                $strCountry = 'MX'
            }
            { @('Bahia', 'Rio de Janeiro', 'Sao Paulo') -contains $_ } {
                $strCountry = 'BR'
            }
            { @('Calabria', 'Sicily', 'Toscana') -contains $_ } {
                $strCountry = 'IT'
            }
        }
        Add-ADGroupMember -Identity $item.name -Members (Get-ADUser -Filter * -Properties * | Where-Object { $_.Country -eq $strCountry }) -ErrorAction SilentlyContinue

    }


    <#
    $AllCities = @(
        'A New Hope',
        'Ahch-To',
        'Alberta',
        'Alderaan',
        'Aleen',
        'Asturias',
        'Attack of the Clones',
        'BAAD',
        'Besalisk',
        'Canto Bight',
        'Cerean',
        'Chagrian',
        'Clawdite',
        'Contractor',
        'Corellia',
        'Coruscant',
        'Dagobah',
        'Dantoonie',
        'Death Star',
        'Devaron',
        'Dijon',
        "D'Qar",
        'Droid',
        'Dug',
        'Eadu',
        'Earth',
        'Endor',
        'Ewok',
        'Florrum',
        'Freelance',
        'Galactic Republic',
        'Gauteng',
        'Geonosian',
        'Geonosis',
        'GOOD',
        'Gungan',
        'Hoth',
        'Human',
        'Hutt',
        'Ibaar',
        'Iego',
        'Iktotchi',
        'Interim',
        'Jakku',
        'Jalath',
        'Jedha',
        'Kaleesh',
        'Kamino',
        'Kaminoan',
        'Kashyyyk',
        'Kel Dor',
        'Kessel',
        "Lah'Mu",
        'Lothal',
        'Malachor',
        'Malastare',
        'Mirialan',
        'Mon Calamari',
        'Mustafar',
        'Muun',
        'Mykapo',
        'Naboo',
        'Nautolan',
        'Neimodian',
        'Oba Diah',
        'Okinawa',
        'Onderon',
        'Otoh Gunga',
        "Pau'an"
        'Permanent',
        'Pillio',
        'Polis Massa',
        'Puebla',
        'Quermian',
        'Raxus',
        'Return of the Jedi',
        'Revenge of the Sith',
        'Ringo Vinda',
        'Rodian',
        'Rodian',
        'Sao Paulo',
        'Scarif',
        'Serenno',
        'Skakoan',
        'Starkiller Base',
        'Stygeon Prime',
        'Sullustan',
        'Svareen',
        'Takodana',
        'Tatooine',
        'The Empire Strikes Back',
        'The Force Awakens',
        'The Phantom Menace',
        'Tholothian',
        'Togruta',
        'Toong',
        'Toscana',
        'Toydarian',
        'Trandoshan',
        'Tuanul',
        "Twi'lek",
        'UGLY',
        'Vandor',
        'Vulptereen',
        'Wobani',
        'Wookiee',
        'Xexto',
        'Yavin 4',
        "Yoda's species",
        'Zabrak',
        'Zanbar',
        'Zygerria')

    # Add the users to the group by filtering by City
    If ($AllCities -contains $item.name)
    {
        Add-ADGroupMember -Identity $item.name -Members (Get-ADUser -Filter * -Properties * | where-object { $_.City -eq $item.name }) -ErrorAction SilentlyContinue
    }
    #>


    If (($item.name -eq 'Broker') -or `
        ($item.name -eq 'Contractor') -or `
        ($item.name -eq 'Freelance') -or `
        ($item.name -eq 'Interim') -or `
        ($item.name -eq 'Permanent')) {
        Add-ADGroupMember -Identity $item.name -Members (Get-ADUser -Filter * -Properties * | Where-Object { $_.employeeType -eq $item.name }) -ErrorAction SilentlyContinue

    }



    # Use same as in OU creation
    ForEach ($Ou in $OUsToCreate) {
        If ( $item.name -eq $Ou) {
            $searchBaseOU = 'OU={0},OU={1},OU={2},{3}' -f $confXML.n.Sites.OUs.OuSiteUser.Name, $item.ou, $confXML.n.Sites.OUs.SitesOU.Name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()
            Add-ADGroupMember -Identity $item.name -Members (Get-ADUser -Filter * -SearchBase $searchBaseOU) -ErrorAction SilentlyContinue

        }
    }

}
###############################################################################
# END Creating AD Groups/Membership from CSV
###############################################################################










###############################################################################
# START Creating Shares and LocalGroups from CSV
###############################################################################
$ShareList, $i, $parameters = $null

[System.Environment]::NewLine
Write-Verbose -Message 'Start creating Shares and LocalGroups in their corresponding OU'
[System.Environment]::NewLine

#Import shares CSV
$ShareList = Import-Csv -Delimiter ';' -Path (Join-Path -Path $DMscripts -ChildPath $confXML.n.shareCSVfile -Resolve)

$i = 0

#Loop through all share items in the CSV
ForEach ($item In $ShareList) {
    $i ++

    $parameters = @{
        Activity         = 'Creating a total of {0} Shares' -f $ShareList.Count
        Status           = 'Creating Share number {0}  ' -f $i
        PercentComplete  = ($i / $ShareList.Count) * 100
        CurrentOperation = '      Processing Share...: {0}' -f $item.ShareName
    }
    Write-Progress @parameters

    #Create the new Area Share
    $parameters = @{
        ShareName          = $item.ShareName
        readGroup          = '{0}_READ_{1}' -f $NC['sl'], $item.ShareName
        changeGroup        = '{0}_CHANGE_{1}' -f $NC['sl'], $item.ShareName
        SG_SiteAdminsGroup = '{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $confXML.n.Sites.lg.SiteRight.Name, $item.OU
        sitePath           = 'OU={0},OU={1},OU={2},{3}' -f $confXML.n.Sites.OUs.OuSiteGroup.Name, $item.ou, $confXML.n.Sites.OUs.SitesOU.Name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()
        ShareLocation      = $confXML.n.Shares.ShareLocation
        AreasName          = $confXML.n.Shares.AreasName
    }
    New-AreaShareNTFS @parameters

    $parameters = @{
        Name            = '{0} - Volume' -f $item.ShareName
        Type            = 'Volume'
        Path            = 'OU={0},OU={1},OU={2},{3}' -f $confXML.n.Sites.OUs.OuSiteShares.Name, $item.ou, $confXML.n.Sites.OUs.SitesOU.Name, ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()
        OtherAttributes = @{
            uNCName = '\\{0}\{1}' -f $env:userdnsdomain, $item.ShareName
        }
    }
    New-ADObject @parameters

    # Nest groups
    If (($item.ShareName -eq 'Alberta') -or `
        ($item.ShareName -eq 'Asturias') -or `
        ($item.ShareName -eq 'Dijon') -or `
        ($item.ShareName -eq 'Gauteng') -or `
        ($item.ShareName -eq 'Okinawa') -or `
        ($item.ShareName -eq 'Puebla') -or `
        ($item.ShareName -eq 'Sao Paulo') -or `
        ($item.ShareName -eq 'Toscana')) {
        switch ($item.ShareName) {
            Alberta {
                $strCountry = 'CA'
            }
            Asturias {
                $strCountry = 'ES'
            }
            Dijon {
                $strCountry = 'FR'
            }
            Gauteng {
                $strCountry = 'SA'
            }
            Okinawa {
                $strCountry = 'JP'
            }
            Puebla {
                $strCountry = 'MX'
            }
            'Sao Paulo' {
                $strCountry = 'BR'
            }
            Toscana {
                $strCountry = 'IT'
            }
        }
        Add-ADGroupMember -Identity ('{0}_CHANGE_{1}' -f $NC['sl'], $item.ShareName) -Members (Get-ADUser -Filter * -Properties SamAccountName, Country | Where-Object { $_.Country -eq $strCountry }) -ErrorAction SilentlyContinue

    }
}
###############################################################################
# END  Creating Shares and LocalGroups from CSV
###############################################################################





#('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
# SG_PAWM_T0




###############################################################################
# START Define OU Administrator
###############################################################################

[System.Environment]::NewLine
Write-Verbose -Message 'Start creating Semi-Privileged users.'
[System.Environment]::NewLine

[string]$AdDn = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext

# IT Admin OU Distinguished Name
$ItAdminOuDn = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItAdminOU.name, $AdDn

# It Admin Users OU Distinguished Name
$ItUsersAdminOuDn = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItAdminAccountsOU.name, $ItAdminOuDn

# Store Passsword as a Secure string
$SecurePWD = ConvertTo-SecureString -AsPlainText $confXML.n.DefaultPassword -Force

# BAAD
Write-Verbose -Message 'Start creating BAAD Semi-Privileged users.'
New-SemiPrivilegedUser -SamAccountName damaul -AccountType T2 -AdminUsersDN $ItUsersAdminOuDn -Verbose
New-SemiPrivilegedUser -SamAccountName dasidi -AccountType T1 -AdminUsersDN $ItUsersAdminOuDn -Verbose
New-SemiPrivilegedUser -SamAccountName davade -AccountType T0 -AdminUsersDN $ItUsersAdminOuDn -Verbose
#GOOD
Write-Verbose -Message 'Start creating GOOD Semi-Privileged users.'
New-SemiPrivilegedUser -SamAccountName luskyw -AccountType T2 -AdminUsersDN $ItUsersAdminOuDn -Verbose
New-SemiPrivilegedUser -SamAccountName obiwan -AccountType T1 -AdminUsersDN $ItUsersAdminOuDn -Verbose
New-SemiPrivilegedUser -SamAccountName yoda -AccountType T0 -AdminUsersDN $ItUsersAdminOuDn -Verbose
#UGLY
Write-Verbose -Message 'Start creating UGLY Semi-Privileged users.'
New-SemiPrivilegedUser -SamAccountName bofett -AccountType T2 -AdminUsersDN $ItUsersAdminOuDn -Verbose
New-SemiPrivilegedUser -SamAccountName jabink -AccountType T1 -AdminUsersDN $ItUsersAdminOuDn -Verbose
New-SemiPrivilegedUser -SamAccountName chwook -AccountType T0 -AdminUsersDN $ItUsersAdminOuDn -Verbose

# Add to SG_Tier0Admins
Write-Verbose -Message 'Start granting Tier0 roles to Semi-Privileged users.'
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.admin.gg.tier0admins.name) -Members chwook_T0, davade_T0, yoda_T0
# Add to SG_Tier1Admins
Write-Verbose -Message 'Start granting Tier1 roles to Semi-Privileged users.'
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.admin.gg.tier1admins.name) -Members dasidi_T1, jabink_T1, obiwan_T1
# Add to SG_Tier2Admins
Write-Verbose -Message 'Start granting Tier2 roles to Semi-Privileged users.'
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.admin.gg.tier2admins.name) -Members damaul_T2, luskyw_T2, bofett_T2

# Add to Site Admins
Write-Verbose -Message 'Start granting Site Management roles roles to Semi-Privileged users.'
Add-ADGroupMember -Identity ('{0}{2}{1}{2}BAAD' -f $NC['sg'], $confXML.n.Sites.GG.SiteAdmins.Name, $NC['Delim']) -Members damaul_T2
Add-ADGroupMember -Identity ('{0}{2}{1}{2}GOOD' -f $NC['sg'], $confXML.n.Sites.GG.SiteAdmins.Name, $NC['Delim']) -Members luskyw_T2
Add-ADGroupMember -Identity ('{0}{2}{1}{2}UGLY' -f $NC['sg'], $confXML.n.Sites.GG.SiteAdmins.Name, $NC['Delim']) -Members bofett_T2

# Add to Server Admins
Write-Verbose -Message 'Start granting Server Management roles to Semi-Privileged users.'
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name) -Members dasidi_T1
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name) -Members jabink_T1
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name) -Members obiwan_T1

# Add to AD Admins
Write-Verbose -Message 'Start granting Active Directory roles to Semi-Privileged users.'
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.DfsAdmins.Name) -Members chwook_T0
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name) -Members davade_T0
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.InfraAdmins.Name) -Members yoda_T0

Write-Verbose -Message 'Set "standard" password to key users.'
Set-ADAccountPassword -Identity damaul_T2 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity luskyw_T2 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity bofett_T2 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity dasidi_T1 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity obiwan_T1 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity jabink_T1 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity davade_T0 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity yoda_T0 -NewPassword $SecurePWD
Set-ADAccountPassword -Identity chwook_T0 -NewPassword $SecurePWD

Write-Verbose -Message 'Avoid password expire to key users.'
Set-ADUser -Identity damaul_T2 -PasswordNeverExpires $True
Set-ADUser -Identity dasidi_T1 -PasswordNeverExpires $True
Set-ADUser -Identity davade_T0 -PasswordNeverExpires $True
Set-ADUser -Identity luskyw_T2 -PasswordNeverExpires $True
Set-ADUser -Identity obiwan_T1 -PasswordNeverExpires $True
Set-ADUser -Identity yoda_T0 -PasswordNeverExpires $True
Set-ADUser -Identity bofett_T2 -PasswordNeverExpires $True
Set-ADUser -Identity jabink_T1 -PasswordNeverExpires $True
Set-ADUser -Identity chwook_T0 -PasswordNeverExpires $True

Set-ADUser -Identity damaul -PasswordNeverExpires $True
Set-ADUser -Identity dasidi -PasswordNeverExpires $True
Set-ADUser -Identity davade -PasswordNeverExpires $True
Set-ADUser -Identity luskyw -PasswordNeverExpires $True
Set-ADUser -Identity obiwan -PasswordNeverExpires $True
Set-ADUser -Identity yoda -PasswordNeverExpires $True
Set-ADUser -Identity bofett -PasswordNeverExpires $True
Set-ADUser -Identity jabink -PasswordNeverExpires $True
Set-ADUser -Identity chwook -PasswordNeverExpires $True

Set-ADUser -Identity $confXML.n.admin.Users.Admin.Name -PasswordNeverExpires $True
Set-ADUser -Identity $confXML.n.admin.Users.NEWAdmin.Name -PasswordNeverExpires $True

# Pre-Stage PAWs
Write-Verbose -Message 'Pre-Stage one PAW for Tier0, Tier1 and Tier2'
New-ADComputer -Name Paw01 -Path ('OU={0},OU={1},{2}' -f $confXML.n.Admin.OUs.ItPawT0OU.Name, $confXML.n.Admin.OUs.ItPawOU.Name, $ItAdminOuDn)
New-ADComputer -Name Paw11 -Path ('OU={0},OU={1},{2}' -f $confXML.n.Admin.OUs.ItPawT1OU.Name, $confXML.n.Admin.OUs.ItPawOU.Name, $ItAdminOuDn)
New-ADComputer -Name Paw21 -Path ('OU={0},OU={1},{2}' -f $confXML.n.Admin.OUs.ItPawT2OU.Name, $confXML.n.Admin.OUs.ItPawOU.Name, $ItAdminOuDn)
###############################################################################
# END Define OU Administrator and backup admin
###############################################################################







###############################################################################
# START Scheduled Tasks
###############################################################################

Write-Verbose -Message 'Grant gMSA_AdTskSchd roles to manage users and groups.'

# Get the gMSA to run scheduled tasks on DCs
$SvcAcc = Get-ADServiceAccount -Filter { name -like 'gMSA_AdTskSchd' }

# Make Service Account member of PUM, PGM, UM & GM so it can manage users and groups (PRivileged and Semi-Privileged)
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.lg.pum.name) -Members $SvcAcc
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.lg.pgm.name) -Members $SvcAcc
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.lg.um.name) -Members $SvcAcc
Add-ADGroupMember -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.lg.gm.name) -Members $SvcAcc


#Configure gMSA so all members of group "Domain Controllers" can retrieve the password
Set-ADServiceAccount $SvcAcc -PrincipalsAllowedToRetrieveManagedPassword 'Domain Controllers'

# The ServiceAccount cannot contain $ at the end.
Write-Verbose -Message 'Set housekeeping for User AdminCount.'
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; Set-AllUserAdminCount }"') | Out-Null
$Splat = @{
    TaskName    = 'Clear AdminCount on Users'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '09:00'
    TimesPerDay = 4
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that will look for all users who have AdminCount attribute set to 1. Considering an Exclusion list, will get all these users and set attribute to 0. Additionally it will reset inheritance on the permissions, so inheritance gets applied.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





Write-Verbose -Message 'Set housekeeping for Group AdminCount.'
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; Set-AllGroupAdminCount }"') | Out-Null
$Splat = @{
    TaskName    = 'Clear AdminCount on Groups'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '10:00'
    TimesPerDay = 4
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that will look for all groups who have AdminCount attribute set to 1. Considering an Exclusion list, will get all these groups and set attribute to 0. Additionally it will reset inheritance on the permissions, so inheritance gets applied.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





Write-Verbose -Message 'Set housekeeping for Privileged Users.'
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-PrivilegedUsersHousekeeping ') | Out-Null
$TaskAction.Append(('-AdminUsersDN "{0}" ' -f $ItUsersAdminOuDn)) | Out-Null
$TaskAction.Append('-Tier0Group "SG_Tier0Admins" ') | Out-Null
$TaskAction.Append('-Tier1Group "SG_Tier1Admins" ') | Out-Null
$TaskAction.Append('-Tier2Group "SG_Tier2Admins" ') | Out-Null
$TaskAction.Append('-ExcludeList @("TheGood", "TheUgly") ') | Out-Null
$TaskAction.Append('-DisableNonStandardUsers }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Privileged Users'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '11:00'
    TimesPerDay = 12
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that will look for all Users within a OU (Usually Users within Administration OU), verify if those are assigned to a given tier (either by EmployeeType attribute or by 3 last characters od the SamAccountName) and add them to the matching tier group.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





Write-Verbose -Message 'Set housekeeping for Non-Privileged Groups.'
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-NonPrivilegedGroupHousekeeping ') | Out-Null
$TaskAction.Append(('-AdminUsersDN "{0}" ' -f $ItUsersAdminOuDn)) | Out-Null
$TaskAction.Append('-Tier0RootOuDN "{0}" ' -f $ItAdminOuDn) | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Non-Privileged Groups'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '11:00'
    TimesPerDay = 3
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that will look for all Users within a OU (Usually Users within Administration OU), and verify those are not added to any group outside scope of Tier0 (Any other group not in Admin/Tier0 OU).'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





Write-Verbose -Message 'Set housekeeping for Privileged Computers.'
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-PrivilegedComputerHousekeeping ') | Out-Null
$TaskAction.Append('-SearchRootDN "{0}" ' -f $ItAdminOuDn) | Out-Null
$TaskAction.Append('-InfraGroup "SL_InfrastructureServers" ') | Out-Null
$TaskAction.Append('-PawGroup "SL_PAWs" ') | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Privileged Computers'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '5:00'
    TimesPerDay = 4
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that will look for all Computers within a OU (Usually Users within Administration OU), and add it to its corresponding group (Servers and/or PAWs).'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





Write-Verbose -Message 'Set housekeeping for Privileged Groups.'
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-PrivilegedGroupsHousekeeping ') | Out-Null
$TaskAction.Append('-AdminGroupsDN "{0}" ' -f $ItAdminOuDn) | Out-Null
$TaskAction.Append('-ExcludeList @("TheGood", "TheUgly") ') | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Privileged Groups'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '4:00'
    TimesPerDay = 3
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that audits groups in a specified Admin OU (Tier 0) and ensures that they only contain authorized users. Authorized users are those with a SamAccountName ending in _T0, _T1, or _T2 or those who have the EmployeeType as T0 or T1 or T2. Any users not matching this criteria or not explicitly excluded are removed from these groups.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat






Write-Verbose -Message 'Set housekeeping for Privileged users based on Non-Privileged user Key-Pair.'
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-SemiPrivilegedKeyPairCheck ') | Out-Null
$TaskAction.Append('-AdminUsersDN "{0}" ' -f $ItUsersAdminOuDn) | Out-Null
$TaskAction.Append('-ExcludeList @("TheGood", "TheUgly") ') | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Non-Privileged user Pair-Key'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '23:00'
    TimesPerDay = 48
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that processes a list of semi-privileged users in Active Directory, checks exclusion lists, and either disables or deletes users based on the associated non-privileged user status.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





# Tier0 SA
Write-Verbose -Message 'Set housekeeping for Tier0 Service Accounts & gMSA.'
$ServiceAccountDN = 'OU={0},{1}' -f $confXML.n.Admin.GG.Tier0ServiceAccount.name, $SvcAccPath
$SAGroupName = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.name
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-ServiceAccountHousekeeping ') | Out-Null
$TaskAction.Append('-ServiceAccountDN "{0}" ' -f $ServiceAccountDN) | Out-Null
$TaskAction.Append('-ServiceAccountGroupName "{0}" ' -f $SAGroupName) | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Tier0 Service Accounts & gMSA'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '23:00'
    TimesPerDay = 48
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that processes Tier0 Service Accounts & gMSA It ensures that all accounts in the OU are members of a specified group and sets their employeeID attribute to ServiceAccount. If the account does not exist within the OU, it will get removed from the group.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





#Tier1 SA
Write-Verbose -Message 'Set housekeeping for Tier1 Service Accounts & gMSA.'
$ServiceAccountDN = 'OU={0},{1}' -f $confXML.n.Admin.GG.Tier1ServiceAccount.name, $SvcAccPath
$SAGroupName = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.name
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-ServiceAccountHousekeeping ') | Out-Null
$TaskAction.Append('-ServiceAccountDN "{0}" ' -f $ServiceAccountDN) | Out-Null
$TaskAction.Append('-ServiceAccountGroupName "{0}" ' -f $SAGroupName) | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Tier1 Service Accounts & gMSA'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '22:30'
    TimesPerDay = 48
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that processes Tier1 Service Accounts & gMSA It ensures that all accounts in the OU are members of a specified group and sets their employeeID attribute to ServiceAccount. If the account does not exist within the OU, it will get removed from the group.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat





# Tier2 SA
Write-Verbose -Message 'Set housekeeping for Tier2 Service Accounts & gMSA.'
$ServiceAccountDN = 'OU={0},{1}' -f $confXML.n.Admin.GG.Tier2ServiceAccount.name, $SvcAccPath
$SAGroupName = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.name
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-ServiceAccountHousekeeping ') | Out-Null
$TaskAction.Append('-ServiceAccountDN "{0}" ' -f $ServiceAccountDN) | Out-Null
$TaskAction.Append('-ServiceAccountGroupName "{0}" ' -f $SAGroupName) | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Tier2 Service Accounts & gMSA'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '21:15'
    TimesPerDay = 48
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that processes Tier2 Service Accounts & gMSA It ensures that all accounts in the OU are members of a specified group and sets their employeeID attribute to ServiceAccount. If the account does not exist within the OU, it will get removed from the group.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat







Write-Verbose -Message 'Set housekeeping for Tier2 Service Accounts & gMSA.'
$ServiceAccountDN = 'OU={0},{1}' -f $confXML.n.Admin.GG.Tier2ServiceAccount.name, $SvcAccPath
$SAGroupName = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.name
$TaskAction = [System.Text.StringBuilder]::new()
$TaskAction.Append('-ExecutionPolicy ByPass ') | Out-Null
$TaskAction.Append('-NoLogo ') | Out-Null
$TaskAction.Append('-Command "{ Set-ExecutionPolicy -ExecutionPolicy bypass; ') | Out-Null
$TaskAction.Append('Import-Module EguibarIT.HousekeepingPS; ') | Out-Null
$TaskAction.Append('Set-AdLocalAdminHousekeeping ') | Out-Null
$TaskAction.Append('-LDAPPath "{0}" ' -f $ItAdminOuDn) | Out-Null
$TaskAction.Append(' }"') | Out-Null
$Splat = @{
    TaskName    = 'Housekeeping for Tier0 Service Accounts & gMSA'
    TaskAction  = $TaskAction
    ActionPath  = 'pwsh.exe'
    gMSAAccount = $SvcAcc
    TriggerType = 'Daily'
    StartTime   = '14:20'
    TimesPerDay = 48
    Description = 'PowerShell Function (from EguibarIT.HousekeepingPS Module) that processes Tier2 Service Accounts & gMSA It ensures that all accounts in the OU are members of a specified group and sets their employeeID attribute to ServiceAccount. If the account does not exist within the OU, it will get removed from the group.'
    Confirm     = $false
}
New-gMSAScheduledTask @Splat

###############################################################################
# END Scheduled Tasks
###############################################################################









###############################################################################
# Start DevSrv config
###############################################################################

New-ADOrganizationalUnit -Name 'No Policy'
New-ADComputer -Name DevSrv -Path ('OU=No Policy,{0}' -f $AdDn)

###############################################################################
# END DevSrv config
###############################################################################









###############################################################################
# START Remove Autologon
###############################################################################
# Set the Key and the permission to AutoLogon
$regkeypath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

try {
    Remove-ItemProperty -Path $regkeypath -Name 'AutoAdminLogon'

    Remove-ItemProperty -Path $regkeypath -Name 'DefaultUserName'

    Remove-ItemProperty -Path $regkeypath -Name 'DefaultPassword'

    Remove-ItemProperty -Path $regkeypath -Name 'AutoLogonCount'

    Remove-ItemProperty -Path $regkeypath -Name 'AutoLogonSID'
} catch {
    throw
}
###############################################################################
# END Remove Autologon
###############################################################################


# Unregister previous scheduled task
Unregister-ScheduledTask -TaskName '5-PopulateDom.ps1' -Confirm:$false -Verbose


# Stop Logging
Stop-Transcript
