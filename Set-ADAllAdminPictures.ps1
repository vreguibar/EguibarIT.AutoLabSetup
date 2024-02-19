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
$All = 'bofett_T2','damaul_T2','luskyw_T2','dasidi_T1','jabink_T1','obiwan_T1','davade_T0','chwook_T0','yoda_T0','TheUgly','TheGood','bofett','damaul','dasidi','davade','jabink','luskyw','obiwan','chwook','yoda'

$image_sizes = @(32, 40, 48, 96, 192, 200, 240, 448)

ForEach($item in $All) {

    #$item = "obiwan_t1"
    [String]$Filter = "(&(objectCategory=User)(SAMAccountName=$item))"
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher($objDomain)
    $objSearcher.SearchRoot = $objDomain
    #$objSearcher.PageSize = 1000
    $objSearcher.Filter = $Filter
    $objSearcher.SearchScope = "Subtree"
    $objSearcher.PropertiesToLoad.Add("thumbnailphoto")

    $user = $objSearcher.FindOne().Properties

    # Get user photo from AD using ADSI
    #$user = ([ADSISearcher]"(&(objectCategory=User)(SAMAccountName=$item))").FindOne().Properties
    
    If($user.thumbnailphoto) {
        $user_photo = $user.thumbnailphoto
    } else {
        # Read Default.jpg stored on NETLOGON folder
        $pic = '\\EguibarIT.local\NETLOGON\Default.jpg' -f $env:USERDNSDOMAIN
        $user_photo = [byte[]](Get-Content -Path $pic -Encoding byte)
    }
    

    # Get user SID using ADSI
    $x = New-Object System.Security.Principal.NTAccount($item)
    $dir = 'C:\ProgramData\AccountPictures\{0}' -f $x.Translate([System.Security.Principal.SecurityIdentifier]).Value

    # Create hidden folder
    If ((Test-Path -Path $dir) -eq $false) {
        New-Item -path $dir -ItemType Directory | ForEach-Object { $_.Attributes = "hidden" }
    }
    
    # Create registry key
    $reg_key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\{0}' -f $x.Translate([System.Security.Principal.SecurityIdentifier]).Value
    If ((Test-Path -Path $reg_key) -eq $false) {
        New-Item -Path $reg_key
    }

    ForEach($size in $image_sizes)  {
        # Save photo to disk, overwrite existing files
        $path = '{0}\Image{1}.jpg' -f $dir, $size
        Write-Verbose -Message ('  saving: {0}' -f $path)
        $user_photo | Set-Content -Path $path -Encoding Byte -Force

        # Save the path in registry, overwrite existing entries
        $name = 'Image{0}' -f $size
        New-ItemProperty -Path $reg_key -Name $name -Value $path -Force

    }
    
}
# SIG # Begin signature block
# MIIaPQYJKoZIhvcNAQcCoIIaLjCCGioCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfoZWrqklZEXTk
# Qtaad+SM41DWEn9xkvb4kStFrqD7qaCCFK0wggTQMIIDuKADAgECAgEHMA0GCSqG
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
# WXswggVQMIIEOKADAgECAggiz5BMLGAXxjANBgkqhkiG9w0BAQsFADCBtDELMAkG
# A1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUx
# GjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2Vy
# dHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNl
# Y3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xODAyMjMwNDA5MDBa
# Fw0xOTAyMjMwNDA5MDBaMIGRMQswCQYDVQQGEwJFUzESMBAGA1UECBMJQmFyY2Vs
# b25hMRYwFAYDVQQHEw1DYXN0ZWxsZGVmZWxzMSowKAYDVQQKEyFFZ3VpYmFyIElu
# Zm9ybWF0aW9uIFRlY2hub2xvZ3kgU0wxKjAoBgNVBAMTIUVndWliYXIgSW5mb3Jt
# YXRpb24gVGVjaG5vbG9neSBTTDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKacU6LBotUrsKIXT1y9csgzvlT1CuhDy5OBiqNLwTFMHb5lHw24UGMNJTQ1
# J2Vz2V1xPv5KMXUWzB+LXHaaChgOwp3yWY0hX5ZgB0PX6KB3MUUeKmYWWrhq+Hi0
# BpLx5jBDDjQsbE1e6LSaFpy2mzk7qTAyJ5ifEI0wyPNa0LhHwwnzSgmfsbaYyH3x
# ljO6k1FlAHgqDLkHePJ5gz4pyeo0OVy7vRFQ+xcya1hRYRq8mLgcdYiXB/tX9mWg
# FdPDV+k1pXeoZy9PvV3goDnOGBhCPWv75Af2031L7urhcfxAXz/4H1iPQH9v2799
# bUhza5aDLmIMrS1/IMVl98iaVEcCAwEAAaOCAYUwggGBMAwGA1UdEwEB/wQCMAAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMDUGA1UdHwQuMCww
# KqAooCaGJGh0dHA6Ly9jcmwuZ29kYWRkeS5jb20vZ2RpZzJzNS0zLmNybDBdBgNV
# HSAEVjBUMEgGC2CGSAGG/W0BBxcCMDkwNwYIKwYBBQUHAgEWK2h0dHA6Ly9jZXJ0
# aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQQBMHYGCCsG
# AQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29kYWRkeS5jb20v
# MEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3Jl
# cG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSDMKIz1/tss/C0
# LIDOMB0GA1UdDgQWBBQh7EzA7yabGMhtRyz7vB34TpbJ2jANBgkqhkiG9w0BAQsF
# AAOCAQEAQSQInD/EwGPK//1OAEossHfSJQVKj7kHIbw4wmvS58LzWYVbdvubkxyF
# pjMY0Lqs36qczNX8ucvaKICkUoVhYv+EgptT0qhu1on17I4Q0dwfdtmQMgZrGfde
# oMM/VXRj5Wn30YsPuL2xh9i2Gvk53D6hij/RmFV+Utrm1NjeZNFxNO/nDdFeoA/B
# TRVnEC1GNzezGZTD1exvSZkTz3jJaTP0PEQXZt0HKe6BsVIuunQqwcgRLnL5z8BD
# kVqSNB25KUaZv98+eDTbKvKDBLmabDNSXRGlL6iJ93V1LVw6gdM9q7P2ABa9bf9i
# COnoSOoy991Ou34PpKNCu5dUqiimRDCCBX0wggRloAMCAQICCQDvlcL0gOMbkzAN
# BgkqhkiG9w0BAQsFADCBxjELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmEx
# EzARBgNVBAcTClNjb3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9s
# b2dpZXMsIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0cy5zdGFyZmllbGR0ZWNo
# LmNvbS9yZXBvc2l0b3J5LzE0MDIGA1UEAxMrU3RhcmZpZWxkIFNlY3VyZSBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xNzExMTQwNzAwMDBaFw0yMjExMTQw
# NzAwMDBaMIGHMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UE
# BxMKU2NvdHRzZGFsZTEkMCIGA1UEChMbU3RhcmZpZWxkIFRlY2hub2xvZ2llcywg
# TExDMSswKQYDVQQDEyJTdGFyZmllbGQgVGltZXN0YW1wIEF1dGhvcml0eSAtIEcy
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5u99Crt0j8hGobYmn8k4
# UjErxlRcOiYQa2JEGDnB9dEo4hEUVi59ww+dYrFmQyK5MZk3cv8xLdptKn9qHRpO
# ykT3juzjJRG3hkuAnNdR+zr8RulUgAxW2E5K4BkRHg4BcTwPFs3miWBVcCau5HKB
# Uhje/e4RzqGLHfxpA/4qpxIzX2EVHCnWh/W/2M48I7Xurm2uSHqZbDcdHl1lPs8u
# 2339tUG9R0ND9FU7mAm74kSZJ4SjmSkhrjYUPQhQ8zEG3G7G8sd/qL/4jGiBqezR
# zZZP+IUdaxRZjMD0U/5tdtyfMRqaGATzzDh8pNeWxf9ZWkd5AK934W49DkKFDlBS
# AQIDAQABo4IBqTCCAaUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBsAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFJ3PHID+Ctai/FgYPqfTVEDu
# 1hRhMB8GA1UdIwQYMBaAFCVFgWhQJjg9Oy0svs1q2bY9s2ZjMIGEBggrBgEFBQcB
# AQR4MHYwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vY3NwLnN0YXJmaWVsZHRlY2guY29t
# LzBIBggrBgEFBQcwAoY8aHR0cDovL2NybC5zdGFyZmllbGR0ZWNoLmNvbS9yZXBv
# c2l0b3J5L3NmX2lzc3VpbmdfY2EtZzIuY3J0MFQGA1UdHwRNMEswSaBHoEWGQ2h0
# dHA6Ly9jcmwuc3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS9tYXN0ZXJzdGFy
# ZmllbGQyaXNzdWluZy5jcmwwUAYDVR0gBEkwRzBFBgtghkgBhv1uAQcXAjA2MDQG
# CCsGAQUFBwIBFihodHRwOi8vY3JsLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRv
# cnkvMA0GCSqGSIb3DQEBCwUAA4IBAQBSRoHzylZjmuQVGBpIM4GVBwDw1QsQNKA1
# h9BOfpUAdA5Qx4L+RujuCbtnai/UwCX4UQEtIvj2l8Czlm8/8sWXPY6QjQ21ViES
# GXcc170e3Tkr0T4FhcVtTLIqedcrPU0Fdsm1QMgPgo1cLjTgC2Fq09mYUARKeO5W
# 7C0WoOFcGKcnVZG3ymuBIGnftFdEh0K1scJzGo/+z0/m/FopYU8U0VzVpcUZUPvc
# JWuUqsJ+T8Gn3icL+nhkupygtNHETw0OlgwqOOlYTo5Jr+dCfqPd6fSzNoZBbqET
# K0eTtw/GXINY22m+K0w0/n/lp+XmJ/T8G2Ae3uFjI0Wn8pZuRNx6MYIE5jCCBOIC
# AQEwgcEwgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH
# EwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UE
# CxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQD
# EypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzICCCLP
# kEwsYBfGMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKEC
# gAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJ7S4ao4jMmWdWhktJ1S8ZEJ4MwY
# WHqYSWVMcGopuRQmMA0GCSqGSIb3DQEBAQUABIIBAHVew4YirHDBKzKH7WC4+ptJ
# 2XSmYrBkO91Z/GrtSkOvL6GgyXNCBxwk62p3nImVKjHxnbTl2593XO1iTf/fuq4+
# XkTHF3FiXFASwfPrpw8d8qI+adFR8ynILD4YHZqW1oZiatjC5+/h2meb73rRiaT+
# 67TvkDYhNAeJ5fTWfYl5UiBmlAXTtH/FJ/IerkX9q8o1E3czHRq/WiERE2CEMmQu
# FsmjaY/oefOx6XWeQRD5/Tf/fdt8l6SoLVw4iI+Cbuxct2lMWbga7SP4Evp74DYJ
# A6iP/Qsqd/mEdlzqkoK+/yaNG0U9Hiy6ixXSbIyfsO/6xN8vczuBCbjNUTLADCCh
# ggJuMIICagYJKoZIhvcNAQkGMYICWzCCAlcCAQEwgdQwgcYxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQK
# ExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTMwMQYDVQQLEypodHRwOi8v
# Y2VydHMuc3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8xNDAyBgNVBAMTK1N0
# YXJmaWVsZCBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzICCQDvlcL0
# gOMbkzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMTgwNzI0MTU0NDE5WjAjBgkqhkiG9w0BCQQxFgQUgq+lWkPq
# /g29zZrMkT9FzIVWmzkwDQYJKoZIhvcNAQEBBQAEggEAJCRvzyXjVrC/tcZb+7If
# kn5cH2lCzOKFWWgmcTLRPfaFM09Hc+ahsWczUqq9qKYRjQM85W6+vr9SeU0/gsYm
# LN+vkpwMB3wA46v7JrbZ0Zb3mF8UUHsrJMC8rOIqzPUzkahPvDYT7RWb29boOQqz
# /bN5BVSwEDcC5NLQbPhyDSvBrPwAhDh8U+cHDESk9yANEObZyEUUDFLy86gm67z8
# AOWpX1FUtEaVCklJGyvjM/bjKT2KiYKNJQT+k7viXkC1MhsfqIPiMkHDio6IgzKa
# pD5LtFcIY3lTQdyzo4KxwXgTwXVgRNYXgvDV7+z0kfsheyiPW+HurREzrQKEbX8i
# eQ==
# SIG # End signature block
