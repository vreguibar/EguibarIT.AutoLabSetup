<#
    .SYNOPSIS
        Get picture stored on AD
    .DESCRIPTION
        This script downloads and sets the Active Directory profile photograph and sets it as your profile picture in Windows
    .INPUTS
        NONE
    .EXAMPLE
        .\Set-ADPicture.ps1
    .NOTES
        Version:        1.3
        DateModified:   19/Jul/2015
        LastModifiedBy: Vicente Rodriguez Eguibar
            vicente@eguibarit.com
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
[CmdletBinding(ConfirmImpact = 'Low')]
Param()

function Test-Null($InputObject) {
    return !([bool]$InputObject)
}

# Get sid and photo for current user
$user = ([ADSISearcher]"(&(objectCategory=User)(SAMAccountName=$env:username))").FindOne().Properties
$user_photo = $user.thumbnailphoto
$user_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Continue if an image was returned
If ((Test-Null -InputObject $user_photo) -eq $false) {
    Write-Verbose -Message 'Photo exists in Active Directory.'
}
# If no image was found in profile, use one from network share.
Else {
    Write-Verbose -Message "No photo found in Active Directory for $env:username, using the default image instead"
    #$user_photo = [byte[]](Get-Content -Path "\\$env:USERDNSDOMAIN\NETLOGON\default.jpg" -ReadCount -Encoding byte)
    [byte[]]$user_photo = [System.IO.File]::ReadAllBytes("\\$env:USERDNSDOMAIN\NETLOGON\default.jpg")
}

# Set up image sizes and base path
$image_sizes = @(32, 40, 48, 96, 192, 200, 240, 448)

# Set up registry
$reg_key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\{0}' -f $user_sid

If ((Test-Path -Path $reg_key) -eq $false) {
    New-Item -Path $reg_key
}

# Save images, set reg keys
Try {
    ForEach ($size in $image_sizes) {
        # Create hidden directory, if it doesn't exist
        $dir = '{0}\AccountPictures\{1}' -f $env:ProgramData, $user_sid
        If ((Test-Path -Path $dir) -eq $false) {
            New-Item -Path $dir -ItemType Directory | ForEach-Object { $_.Attributes = 'hidden' }
        }

        # Save photo to disk, overwrite existing files
        $path = '{0}\Image{1}.jpg' -f $dir, $size
        Write-Verbose -Message ('  saving: Image{0}.jpg' -f $size)
        #$user_photo | Set-Content -Path $path -Encoding Byte -Force
        [IO.File]::WriteAllBytes($path, $user_photo)

        # Save the path in registry, overwrite existing entries
        $name = 'Image{0}' -f $size
        $null = New-ItemProperty -Path $reg_key -Name $name -Value $path -Force
    }
} Catch {
    Write-Error -Message "Profile picture for $env:username cannot be created."
    Write-Error -Message 'Check prompt elevation and permissions to files/registry.'
}
