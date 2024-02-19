﻿#========================================================================
# Generated By: Anders Wahlqvist
# Website: DollarUnderscore (http://dollarunderscore.azurewebsites.net)
#========================================================================

function ConvertTo-ADThumbnail {
    <#
    .SYNOPSIS
    This script cmdlet converts a image file for use in Active Directory.

    .DESCRIPTION
    It converts a file to a byte variable that can be written to the Active Directory thumbnail attribute. The size is also change to < 9 kb (default).

    .PARAMETER PictureFile
    Provide the path to the picture file here.

    .PARAMETER PictureSize
    Set the picture size in KB here. Default is 9 kb. (to work with Office 365)

    .PARAMETER OutputDir
    Specify the folder where you want the copy of the original file (but now smaller) stored.

    .EXAMPLE
    ConvertTo-ADThumbnail -PictureFile '.\MyPicture.jpg'

    .EXAMPLE
    ConvertTo-ADThumbnail -PictureFile '.\MyPicture.jpg' -PictureSize 100

    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Fullname')]
        [string] $PictureFile,
        [Parameter(Mandatory = $false)]
        [string] $OutputDir = $(Get-Location | Select-Object -ExpandProperty Path),
        [Parameter(Mandatory = $false)]
        [Alias('Size')]
        [int] $PictureSize = 9)

    BEGIN {
        # Load the assembly we need
        [reflection.assembly]::LoadWithPartialName('System.Drawing') | Out-Null
        $SupportedExtensions = @()
        $SupportedExtensions = '.jpeg', '.jpg', '.gif', '.bmp', '.png'
    }

    PROCESS {

        # Get the file object
        $PictureFileObj = Get-ChildItem $PictureFile

        if ($PictureFileObj.Extension -in $SupportedExtensions) {

            # Create the image object
            $OriginalPicture = [System.Drawing.Bitmap]::FromFile( $PictureFile )

            # Get the size in KB
            $PictureFileSize = ($PictureFileObj | Select-Object -ExpandProperty Length) / 1KB

            # Set a new file name
            $NewPictureName = "$($PictureFileObj.BaseName)-ADThumbnail.jpg"

            # Set path
            if ($OutputDir -like "`.\*") {
                $CurrentDirectory = $(Get-Location | Select-Object -ExpandProperty Path)
                $PathToResolve = "$CurrentDirectory$OutputDir"
                $OutputPath = [System.IO.Path]::GetFullPath($PathToResolve)
            } else {
                $OutputPath = [System.IO.Path]::GetFullPath($OutputDir)
            }


            $OutFile = "$OutputPath\$NewPictureName"

            # Check if it the picture is to big
            if ($PictureFileSize -gt $PictureSize) {

                $NewPictureFileSize = $PictureFileSize

                [decimal] $ShrinkFactorImage = 1.00
                $ShrinkNr = 0

                while ($NewPictureFileSize -gt $PictureSize) {

                    $ShrinkNr++
                    [decimal] $ShrinkFactorImage = (1.00 - ($ShrinkNr * 0.01))

                    Remove-Item $OutFile -Force -ErrorAction SilentlyContinue

                    [int] $NewPictureWidth = $OriginalPicture.Width * $ShrinkFactorImage
                    [int] $NewPictureHeight = $OriginalPicture.Height * $ShrinkFactorImage

                    # Create a new bitmap
                    $NewPicture = New-Object System.Drawing.Bitmap $NewPictureWidth, $NewPictureHeight

                    # Start drawing, with high quality
                    $NewPictureDrawing = [System.Drawing.Graphics]::FromImage($NewPicture)
                    $NewPictureDrawing.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

                    # Convert the old picture to the new size
                    $NewPictureDrawing.DrawImage($OriginalPicture, 0, 0, $NewPictureWidth, $NewPictureHeight)


                    # Verify that the file does not exist, delete it if it does
                    $FileExist = Test-Path $OutFile

                    if ($FileExist) {
                        Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
                    }

                    # Save the file
                    try {
                        $NewPicture.Save($OutFile, ([system.drawing.imaging.imageformat]::jpeg))
                    } catch {
                        # Something bugs...
                    }

                    # Ok, We're done with these, let's not eat up all the memory...
                    $NewPicture.Dispose()
                    $NewPictureDrawing.Dispose()

                    # Load the new filesize, if this fails, the image can't be converted.
                    try {
                        $NewPictureFileSize = (Get-ChildItem $OutFile -ErrorAction Stop | Select-Object -ExpandProperty Length) / 1KB
                    } catch {
                        return
                    }
                }

                $ByteArray = [byte[]](Get-Content $OutFile -AsByteStream -Raw)

            } else {
                $ByteArray = [byte[]](Get-Content $PictureFile -AsByteStream -Raw)
                Copy-Item $PictureFile $OutFile -Force

                $NewPictureFileSize = $PictureFileSize
                $NewPictureWidth = $OriginalPicture.Width
                $NewPictureHeight = $OriginalPicture.Height
            }

            $returnObject = New-Object System.Object
            $returnObject | Add-Member -Type NoteProperty -Name OrgFilename -Value $PictureFile
            $returnObject | Add-Member -Type NoteProperty -Name OrgFileSize -Value $PictureFileSize
            $returnObject | Add-Member -Type NoteProperty -Name OrgFileWidth -Value $OriginalPicture.Width
            $returnObject | Add-Member -Type NoteProperty -Name OrgFileHeight -Value $OriginalPicture.Height
            $returnObject | Add-Member -Type NoteProperty -Name NewFilename -Value $OutFile
            $returnObject | Add-Member -Type NoteProperty -Name NewFileSize -Value $NewPictureFileSize
            $returnObject | Add-Member -Type NoteProperty -Name NewFileWidth -Value $NewPictureWidth
            $returnObject | Add-Member -Type NoteProperty -Name NewFileHeight -Value $NewPictureHeight
            $returnObject | Add-Member -Type NoteProperty -Name ThumbnailByteArray -Value $ByteArray

            Write-Output $returnObject

            $OriginalPicture.Dispose()
            $ByteArray = $null


            #            [GC]::Collect()
        }
    }
    END {
    }
}


#ConvertTo-ADThumbnail -PictureFile 'C:\Users\RODRIGUEZEGUIBARVice\OneDrive-EguibarIT\_Scripts\LabSetup\SourceDC\Pic\dampoe.jpg'

# rename files from xxxx-ADThumbnail.jpg to xxxx.jpg
# Get-ChildItem | Rename-Item -NewName { $_.Name -replace "-ADThumbnail","" }
