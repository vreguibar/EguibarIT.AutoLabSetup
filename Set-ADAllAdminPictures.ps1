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
$All = @(
    'bofett_T2',
    'damaul_T2',
    'luskyw_T2',
    'dasidi_T1',
    'jabink_T1',
    'obiwan_T1',
    'davade_T0',
    'chwook_T0',
    'yoda_T0',
    'TheUgly',
    'TheGood',
    'bofett',
    'damaul',
    'dasidi',
    'davade',
    'jabink',
    'luskyw',
    'obiwan',
    'chwook',
    'yoda'
)

$image_sizes = @(32, 40, 48, 96, 192, 200, 240, 448)

ForEach ($item in $All) {

    Write-Verbose -Message ('Processing user: {0}' -f $item)

    #$item = "obiwan_t1"
    [String]$Filter = "(&(objectCategory=User)(SAMAccountName=$item))"
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher($objDomain)
    $objSearcher.SearchRoot = $objDomain
    #$objSearcher.PageSize = 1000
    $objSearcher.Filter = $Filter
    $objSearcher.SearchScope = 'Subtree'
    $objSearcher.PropertiesToLoad.Add('thumbnailphoto')

    $user = $objSearcher.FindOne().Properties

    # Get user photo from AD using ADSI
    #$user = ([ADSISearcher]"(&(objectCategory=User)(SAMAccountName=$item))").FindOne().Properties

    If ($user.thumbnailphoto) {
        Write-Verbose -Message ('Thumbnail photo found on AD for user: {0}' -f $item)
        [byte[]]$user_photo = $user.thumbnailphoto[0]
    } else {
        # Read Default.jpg stored on NETLOGON folder
        Write-Verbose -Message 'Thumbnail photo NOT found Using default'

        $pic = '\\EguibarIT.local\NETLOGON\Default.jpg' -f $env:USERDNSDOMAIN
        #$user_photo = [byte[]](Get-Content -Path $pic -Encoding byte)
        [byte[]]$user_photo = [System.IO.File]::ReadAllBytes($Pic)
    }


    # Get user SID using ADSI
    try {
        Write-Verbose -Message 'Getting user SID'
        $x = New-Object System.Security.Principal.NTAccount($item)
        $sid = $x.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $dir = 'C:\ProgramData\AccountPictures\{0}' -f $sid
    } Catch {
        throw
    }

    # Ensure the directory exists and is hidden
    if (-not(Test-Path -Path $dir)) {

        $null = New-Item -Path $dir -ItemType Directory -Force
        $dirInfo = Get-Item $dir
        $dirInfo.Attributes = 'Hidden'
    }

    # Create registry key
    $reg_key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\{0}' -f $sid
    If (-not (Test-Path -Path $reg_key)) {
        New-Item -Path $reg_key
    }

    ForEach ($size in $image_sizes) {
        # Save photo to disk, overwrite existing files
        $path = '{0}\Image{1}.jpg' -f $dir, $size
        Write-Verbose -Message ('  saving file: {0}' -f $path)
        #$user_photo | Set-Content -Path $path -Encoding Byte -Force
        [IO.File]::WriteAllBytes($path, $user_photo)

        # Save the path in registry, overwrite existing entries
        $name = 'Image{0}' -f $size
        New-ItemProperty -Path $reg_key -Name $name -Value $path -Force

    }

}
