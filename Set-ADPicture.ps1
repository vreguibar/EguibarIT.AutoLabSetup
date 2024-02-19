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
[CmdletBinding(ConfirmImpact='Low')]
Param()

function Test-Null($InputObject) { return !([bool]$InputObject) }
 
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
    $user_photo = [byte[]](Get-Content -Path "\\$env:USERDNSDOMAIN\NETLOGON\default.jpg" -ReadCount -Encoding byte)
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
            New-Item -path $dir -ItemType Directory | ForEach-Object { $_.Attributes = "hidden" }
        }
 
        # Save photo to disk, overwrite existing files
        $path = '{0}\Image{1}.jpg' -f $dir, $size
        Write-Verbose -Message ('  saving: Image{0}.jpg' -f $size)
        $user_photo | Set-Content -Path $path -Encoding Byte -Force
 
        # Save the path in registry, overwrite existing entries
        $name = 'Image{0}' -f $size
        $value = New-ItemProperty -Path $reg_key -Name $name -Value $path -Force
    }
} Catch {
    Write-Error -Message "Profile picture for $env:username cannot be created."
    Write-Error -Message 'Check prompt elevation and permissions to files/registry.'
}

# SIG # Begin signature block
# MIIaPwYJKoZIhvcNAQcCoIIaMDCCGiwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDfAfr2C1cv9wpz
# /5oXNBm/KkjaVQ6+nDR9+pWFjeWr16CCFK4wggTQMIIDuKADAgECAgEHMA0GCSqG
# SIb3DQEBCwUAMIGDMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEG
# A1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xMTAv
# BgNVBAMTKEdvIERhZGR5IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIw
# HhcNMTEwNTAzMDcwMDAwWhcNMzEwNTAzMDcwMDAwWjCBtDELMAkGA1UEBhMCVVMx
# EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
# EUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRk
# eS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBALngyxDUr3a91JNi6zBkuIEIbMME2WIXji//PmXPj85i5jxSHNoWRUtV
# q3hrY4NikM4PaWyZyBoUi0zMRTPqiNyeo68r/oBhnXlXxM8u9D8wPF1H/JoWvMM3
# lkFRjhFLVPgovtCMvvAwOB7zsCb4Zkdjbd5xJkePOEdT0UYdtOPcAOpFrL28cdmq
# bwDb280wOnlPX0xH+B3vW8LEnWA7sbJDkdikM07qs9YnT60liqXG9NXQpq50BWRX
# iLVEVdQtKjo++Li96TIKApRkxBY6UPFKrud5M68MIAd/6N8EOcJpAmxjUvp3wRvI
# dIfIuZMYUFQ1S2lOvDvTSS4f3MHSUvsCAwEAAaOCARowggEWMA8GA1UdEwEB/wQF
# MAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRAwr0njsw0gzCiM9f7bLPw
# tCyAzjAfBgNVHSMEGDAWgBQ6moUHEGcotu/2vQVBbiDBlNoP3jA0BggrBgEFBQcB
# AQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzA1BgNV
# HR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkcm9vdC1nMi5j
# cmwwRgYDVR0gBD8wPTA7BgRVHSAAMDMwMQYIKwYBBQUHAgEWJWh0dHBzOi8vY2Vy
# dHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAAh+
# bJMQyDi4lqmQS/+hX08E72w+nIgGyVCPpnP3VzEbvrzkL9v4utNb4LTn5nliDgyi
# 12pjczG19ahIpDsILaJdkNe0fCVPEVYwxLZEnXssneVe5u8MYaq/5Cob7oSeuIN9
# wUPORKcTcA2RH/TIE62DYNnYcqhzJB61rCIOyheJYlhEG6uJJQEAD83EG2LbUbTT
# D1Eqm/S8c/x2zjakzdnYLOqum/UqspDRTXUYij+KQZAjfVtL/qQDWJtGssNgYIP4
# fVBBzsKhkMO77wIv0hVU7kQV2Qqup4oz7bEtdjYm3ATrn/dhHxXch2/uRpYoraEm
# fQoJpy4Eo428+LwEMAEwggUAMIID6KADAgECAgEHMA0GCSqGSIb3DQEBCwUAMIGP
# MQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRz
# ZGFsZTElMCMGA1UEChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjEyMDAG
# A1UEAxMpU3RhcmZpZWxkIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIw
# HhcNMTEwNTAzMDcwMDAwWhcNMzEwNTAzMDcwMDAwWjCBxjELMAkGA1UEBhMCVVMx
# EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoT
# HFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9j
# ZXJ0cy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5LzE0MDIGA1UEAxMrU3Rh
# cmZpZWxkIFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOWQZkvs+UZxqSCDvulsv0rJSGmBdU5t
# JPbLFxP4sHFZhHprK4WkNLUW5cvM6UFwLKQu1voyfeGo3pQQrDHBwNhq/1knq3bW
# /At0a7inrj/EVPS0MUTdk1aMpExem4nLJIOb4ld9t9gSH8mFbfTRgPFQm4eu1AsQ
# BfsnuihtF+kO1k25OVUG/wokBX4vxh1ybNSLKYxXfdrZ62Ya00+n339SxDDFpckO
# AsVTv3c4aAYkw2bIN34wHkVxIzX/kNgqnY3nsJJNPH8qCpPczRZGZfdghIt2S5En
# cxSS4OrujxbqjQ4+dhe/fYmAgERD5y3gQwl12jborduJOvVdEo4jBIMCAwEAAaOC
# ASwwggEoMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW
# BBQlRYFoUCY4PTstLL7Natm2PbNmYzAfBgNVHSMEGDAWgBR8DDIfp9kwf8R9aKNi
# qKHOqwdbJzA6BggrBgEFBQcBAQQuMCwwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3Nw
# LnN0YXJmaWVsZHRlY2guY29tLzA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3Js
# LnN0YXJmaWVsZHRlY2guY29tL3Nmcm9vdC1nMi5jcmwwTAYDVR0gBEUwQzBBBgRV
# HSAAMDkwNwYIKwYBBQUHAgEWK2h0dHBzOi8vY2VydHMuc3RhcmZpZWxkdGVjaC5j
# b20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAFZlyv7zPwqok4sYx95D
# aRM0IL5OX3ioa5zbak1B28ET7NwxACJe9wCeDOA0ZTT5sTpOSMgSgYhcWz4IU3r3
# GmTfuFBhzFNRQClLwvSuOl/kyq0mzE5hQ+X9V6Y3cM5DK7CUw5Lp4V+qEEm3aeTg
# 0B9kpCvNH2+g+IQkGM55PamRv1QYE4mZVBENVcUmC3lPWhxu+WPbFICkB6v6sqW5
# iN2R/mU7pKN5volN4dCw9MgXDAqWFHwJt2zhwthV1BigqkFpcCSjue/pWtw+65RK
# 8LfeXw52+vv7aQNFQFDucgykEoaBzRPRTsQ8yk4N0ibxALe0pqLhbnqB/TCseh/H
# WXswggVRMIIEOaADAgECAgkAmco7zATLE8cwDQYJKoZIhvcNAQELBQAwgbQxCzAJ
# BgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxl
# MRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2Nl
# cnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBT
# ZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTkxMjI2MTEzMDU2
# WhcNMjEwMjIzMDQwOTAwWjCBkTELMAkGA1UEBhMCRVMxEjAQBgNVBAgTCUJhcmNl
# bG9uYTEWMBQGA1UEBxMNQ2FzdGVsbGRlZmVsczEqMCgGA1UEChMhRWd1aWJhciBJ
# bmZvcm1hdGlvbiBUZWNobm9sb2d5IFNMMSowKAYDVQQDEyFFZ3VpYmFyIEluZm9y
# bWF0aW9uIFRlY2hub2xvZ3kgU0wwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQD3R+pEd+cdKJE3Wl7Mvwie5pxbWX4RLwDVORVgd+SY+CUWD5FP83ZOI1DK
# aepq1nvLux76jcLIdAzQ8OHJXDnwqr0gniGD1O/BL5VfMY7u5NARTS1BPmIqmyb2
# DbcKk7xH0lbJfjx7XnUVqflMOYMG6n/UY563qZKBijFf3vxgcW/ru0+KpSiwPSCF
# /h1zMwBRWKD43Esi11O0ajiHo2OM9UaZWnBBR/+siIVMJCGA0WL9Xc54d8mOtXVZ
# MwWWY3wfmRbbQhBj4p6YNL5ZuU9I5Gqm2jkL/2yb7B54c/bR0alGSqjm7lR4CpqK
# bmsdf3CjsYBld7oN9ZQCu8SHE03pAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAs
# MCqgKKAmhiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNS5jcmwwXQYD
# VR0gBFYwVDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2Vy
# dGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2Bggr
# BgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29t
# LzBABggrBgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9y
# ZXBvc2l0b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPw
# tCyAzjAdBgNVHQ4EFgQUEG2qFmI7EMDGJRTF0yd066K40bAwDQYJKoZIhvcNAQEL
# BQADggEBAFIA0kIa/z82rJSYtq35NyzhRK3ab9tcyEVClHcvUYYOzfYWd5k429o6
# Qyqu2G2KW52NGOU6NZ1MJvqiPAJLfaCeVCI+Fp+MmVvYqKyLVZ0PHQBdOyDRoX+j
# cmep6kBQVMzxhaJgtAkrIx5OGzJCAb5+Q7OkeeAZes6tN67gLb3O6FPMH6qdynQs
# Ksnr0LZ28jeXrZzPBI2CCvA4ZKBTO3fCr9gLAQ5HsdgMCMtsRO4LJ5RUxuCD+Izw
# 278DST3A3SzO5Ck6OncuUlF2YtmU7YiSv91p827H0a2OHi7xB73LN4yZ+twRr824
# d9OJzvbIJ/jOGKEyaCja1FdYo+Nuy6swggV9MIIEZaADAgECAgkAhft3suFZEZcw
# DQYJKoZIhvcNAQELBQAwgcYxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25h
# MRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5v
# bG9naWVzLCBJbmMuMTMwMQYDVQQLEypodHRwOi8vY2VydHMuc3RhcmZpZWxkdGVj
# aC5jb20vcmVwb3NpdG9yeS8xNDAyBgNVBAMTK1N0YXJmaWVsZCBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTkwOTE3MDcwMDAwWhcNMjQwOTE3
# MDcwMDAwWjCBhzELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNV
# BAcTClNjb3R0c2RhbGUxJDAiBgNVBAoTG1N0YXJmaWVsZCBUZWNobm9sb2dpZXMs
# IExMQzErMCkGA1UEAxMiU3RhcmZpZWxkIFRpbWVzdGFtcCBBdXRob3JpdHkgLSBH
# MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK4xUTO5KWat61iuWRSC
# 5ZZmabnSZI6Vtu0PpstcIj28n0OXPfK7z02vmXgEqTuJdMcJb1bNz12KeVox7CBt
# pFpbY4IovD7awY77EBJbrwThtzWk6EYJo5Z1IUzS9we0ZdwXpH5YXkfwv4eNKhgq
# bBpgnqs8vq6c7ZTMiAY8oh+F8wRPBnnb3oQe6PerXPpV8/Mi9/Vy1cM0RDzk3nZm
# yYMT0SR8KeIcOe5qxbOQUCkSsVVfLriPseQDwSgFTXqTPWF4BQ4x3n32IO4ke0d7
# x/M0PigRnZnGIPDNpEnwXCEUVxcCXxEQajDmhTdmZ7jTNkerqjjP5M3/rE+liUYg
# TVUCAwEAAaOCAakwggGlMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgbAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBRnhH6XGXwCXC+V6/gJnDOS
# 0i3ZrDAfBgNVHSMEGDAWgBQlRYFoUCY4PTstLL7Natm2PbNmYzCBhAYIKwYBBQUH
# AQEEeDB2MCoGCCsGAQUFBzABhh5odHRwOi8vb2NzcC5zdGFyZmllbGR0ZWNoLmNv
# bS8wSAYIKwYBBQUHMAKGPGh0dHA6Ly9jcmwuc3RhcmZpZWxkdGVjaC5jb20vcmVw
# b3NpdG9yeS9zZl9pc3N1aW5nX2NhLWcyLmNydDBUBgNVHR8ETTBLMEmgR6BFhkNo
# dHRwOi8vY3JsLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkvbWFzdGVyc3Rh
# cmZpZWxkMmlzc3VpbmcuY3JsMFAGA1UdIARJMEcwRQYLYIZIAYb9bgEHFwIwNjA0
# BggrBgEFBQcCARYoaHR0cDovL2NybC5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0
# b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAgYxDPXocopQPzJmnA6Hli348wi3xRL0b
# DHxwPdPdbLi/C9OZqUBg2IbEdSc9tatchgtjYENct1gGbOpd8QzNWr1QBUrrkbf0
# ZbnZbqhXjATyDs8qZ6tDwrcLZkj/WJV21FO0G61mWnmnHwpHohhNnr7B8gpTtCC/
# AyO9mBYBx/AKjtqs0eTw4xVmC2Z5XOW5Vn+ftHjvRg7SH/6Uib/NouFlknIrpYDf
# bQmbEHjJcEJhsn8MSdct1TwGztJhFthCLxYAT9T5xcsc8/PW/rEtJiFMVh2uJ0Ym
# g6vxA2rOsvNbMWFNa6rndTngtBIMiQ3oKvtf7QDXVFHfm2FITCyWMDGCBOcwggTj
# AgEBMIHCMIG0MQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UE
# BxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4xLTArBgNV
# BAsTJGh0dHA6Ly9jZXJ0cy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzEzMDEGA1UE
# AxMqR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyAgkA
# mco7zATLE8cwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgclu/br0qnGPZ2aS7SfijM6Qc
# OOeTgPaSXzTAwPLswSIwDQYJKoZIhvcNAQEBBQAEggEAvMsvbDQbv17rq6Hf2blf
# 8lQDZKezEU/hdRKOm7TosVqCe8vnICdGGs5J9BDfSyXHR3JPDDat3HYIF9HVZbAW
# yH+3URoez20JkysJcXOAyokGit0AlMIO2grdqyKf6y4pGfWMO0afbweQsXVRPmnc
# WCOjCBbyFDQZpjqNFxs/mwn6zBsrSpud0+659Dtb1VDjVgL+QRu4fEEzrSz119W8
# rKb/H7/QBWpH6BrfrirQie7Ls8N6P/U5ZKcOZK4JLzuJpWHPs3ZqWHh+r0cEeA5V
# JrnSnE2big14sRcYb5oeOT8LwNhyj50pWzuzg/r4XHQbB3Cv+8NSfIQZgI/XswXR
# NKGCAm4wggJqBgkqhkiG9w0BCQYxggJbMIICVwIBATCB1DCBxjELMAkGA1UEBhMC
# VVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNV
# BAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4xMzAxBgNVBAsTKmh0dHA6
# Ly9jZXJ0cy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5LzE0MDIGA1UEAxMr
# U3RhcmZpZWxkIFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIJAIX7
# d7LhWRGXMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0xOTEyMjYxMjA2NTNaMCMGCSqGSIb3DQEJBDEWBBTUx1Bt
# BcE/Tf0WDvFr91phyCRtLjANBgkqhkiG9w0BAQEFAASCAQCDSL5Ekl3DawN8XSiu
# cBZbbs+WxwduLukeE8axRaLDDxIfhn9BXDZ+zuu/gEc86Xe9Ojkka6+uWO8yTqcn
# oIXJmwwPDYIIYlAMI0Qbbc9e/OMCQXt41jjfceFO5m7Bg/lgBSmvEmNPsQixr73U
# 8M3K+voTGyb0XR3G3XuuEIp+VUvDdHd2WqcBgdZ3kdY9HrB0hzTH7wN2+pTHWnbV
# 85mZYnHsOrc9oKwc4m0avH2i4C6Vjd/HmXdWSj4exFMIp3PF/bNSStkrGGYjKF4I
# g/9e4+w7cL7ui68pZobBZ5qmKpQB4Rh0jBs36JkYzSWi7m3fJn+C2oPK74oKUVp6
# +2Tz
# SIG # End signature block
