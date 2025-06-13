#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates a bootable ISO from WIM files with minimal source structure
.DESCRIPTION
    This script creates a bootable ISO image with both BIOS and UEFI support
    from WIM files. It can work with just a sources/boot.wim file or a full ISO structure.
.PARAMETER SourceFolder
    Path to the folder containing WIM files (can be minimal structure)
.PARAMETER IsoName
    Name for the output ISO file (without .iso extension)
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$SourceFolder,
    
    [Parameter(Mandatory=$false)]
    [string]$IsoName
)

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to install ADK and verify all required components
function Install-ADK {
    Write-Host "Checking for Windows ADK installation..." -ForegroundColor Yellow
    
    $adkPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
    $oscdimgPath = "$adkPath\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    
    # Verify all required files exist
    $requiredFiles = @(
        "$oscdimgPath",
        "$adkPath\Deployment Tools\amd64\Oscdimg\etfsboot.com",
        "$adkPath\Deployment Tools\amd64\Oscdimg\efisys.bin",
        "${env:SystemRoot}\Boot\DVD\PCAT\boot.sdi",
        "${env:SystemRoot}\Boot\PCAT\bootmgr",
        "${env:SystemRoot}\Boot\EFI\bootmgfw.efi"
    )
    
    $allFilesExist = $true
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "Missing required file: $file" -ForegroundColor Yellow
            $allFilesExist = $false
        }
    }
    
    if ($allFilesExist) {
        Write-Host "ADK and all required boot files are present." -ForegroundColor Green
        return $oscdimgPath
    }
    
    Write-Host "Required files missing. Installing Windows ADK..." -ForegroundColor Yellow
    
    # Download and install main ADK
    $adkUrl = "https://download.microsoft.com/download/2/d/9/2d9c8902-3fcd-48a6-a22a-432b08bed61e/ADK/adksetup.exe"
    $adkInstaller = "$env:TEMP\adksetup.exe"
    
    Write-Host "Downloading ADK installer..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $adkUrl -OutFile $adkInstaller -UseBasicParsing
    } catch {
        Write-Error "Failed to download ADK installer: $_"
        exit 1
    }
    
    Write-Host "Installing ADK (this may take several minutes)..." -ForegroundColor Yellow
    $adkProcess = Start-Process -FilePath $adkInstaller -ArgumentList "/quiet", "/features", "OptionId.DeploymentTools" -Wait -PassThru
    
    if ($adkProcess.ExitCode -ne 0) {
        Write-Error "ADK installation failed with exit code: $($adkProcess.ExitCode)"
        exit 1
    }
    
    # Download and install WinPE add-on
    $winpeUrl = "https://download.microsoft.com/download/5/5/6/556e01ec-9d78-417d-b1e1-d83a2eff20bc/ADKWinPEAddons/adkwinpesetup.exe"
    $winpeInstaller = "$env:TEMP\adkwinpesetup.exe"
    
    Write-Host "Downloading WinPE add-on..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $winpeUrl -OutFile $winpeInstaller -UseBasicParsing
    } catch {
        Write-Error "Failed to download WinPE add-on: $_"
        exit 1
    }
    
    Write-Host "Installing WinPE add-on..." -ForegroundColor Yellow
    $winpeProcess = Start-Process -FilePath $winpeInstaller -ArgumentList "/quiet", "/features", "+" -Wait -PassThru
    
    if ($winpeProcess.ExitCode -ne 0) {
        Write-Error "WinPE add-on installation failed with exit code: $($winpeProcess.ExitCode)"
        exit 1
    }
    
    # Clean up installers
    Remove-Item $adkInstaller -Force -ErrorAction SilentlyContinue
    Remove-Item $winpeInstaller -Force -ErrorAction SilentlyContinue
    
    Write-Host "ADK installation completed successfully." -ForegroundColor Green
    
    # Verify all required files now exist
    $allFilesExist = $true
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            Write-Error "Required file still missing after ADK installation: $file"
            $allFilesExist = $false
        }
    }
    
    if ($allFilesExist) {
        return $oscdimgPath
    } else {
        Write-Error "ADK installation verification failed. Required files missing."
        exit 1
    }
}

# Function to create complete boot structure from scratch
function New-BootStructure {
    param(
        [string]$WorkDir,
        [string]$IsoName,
        [array]$WimFiles
    )
    
    Write-Host "Creating complete boot structure from scratch..." -ForegroundColor Yellow
    
    # Create directory structure
    $bootDir = Join-Path $WorkDir "boot"
    $efiBootDir = Join-Path $WorkDir "efi\boot"
    $efiMsBootDir = Join-Path $WorkDir "efi\microsoft\boot"
    $sourcesDir = Join-Path $WorkDir "sources"
    
    New-Item -ItemType Directory -Path $bootDir -Force | Out-Null
    New-Item -ItemType Directory -Path $efiBootDir -Force | Out-Null
    New-Item -ItemType Directory -Path $efiMsBootDir -Force | Out-Null
    New-Item -ItemType Directory -Path $sourcesDir -Force | Out-Null
    
    # Copy WIM files to sources directory if they're not already there
    foreach ($wimFile in $WimFiles) {
        $wimName = Split-Path $wimFile.FullName -Leaf
        $targetPath = Join-Path $sourcesDir $wimName
        
        if ($wimFile.FullName -ne $targetPath) {
            Write-Host "Copying $wimName to sources directory..." -ForegroundColor Yellow
            Copy-Item $wimFile.FullName -Destination $targetPath -Force
        }
    }
    
    # Get ADK paths
    $adkPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
    $oscdimgPath = "$adkPath\Deployment Tools\amd64\Oscdimg"
    
    # Copy boot files from ADK
    Write-Host "Copying boot files from ADK..." -ForegroundColor Yellow
    
    # Copy etfsboot.com for BIOS boot
    $etfsbootSource = Join-Path $oscdimgPath "etfsboot.com"
    $etfsbootDest = Join-Path $bootDir "etfsboot.com"
    if (Test-Path $etfsbootSource) {
        Copy-Item $etfsbootSource -Destination $etfsbootDest -Force
    } else {
        Write-Error "etfsboot.com not found in ADK at: $etfsbootSource"
        exit 1
    }
    
    # Copy efisys.bin for UEFI boot
    $efisysSource = Join-Path $oscdimgPath "efisys.bin"
    $efisysDest = Join-Path $efiMsBootDir "efisys.bin"
    if (Test-Path $efisysSource) {
        Copy-Item $efisysSource -Destination $efisysDest -Force
    } else {
        Write-Error "efisys.bin not found in ADK at: $efisysSource"
        exit 1
    }
    
    # Copy bootmgr files from system
    Write-Host "Copying bootmgr files from system..." -ForegroundColor Yellow
    
    # BIOS bootmgr
    $bootmgrSource = "${env:SystemRoot}\Boot\PCAT\bootmgr"
    $bootmgrDest = Join-Path $WorkDir "bootmgr"
    if (Test-Path $bootmgrSource) {
        Copy-Item $bootmgrSource -Destination $bootmgrDest -Force
    } else {
        Write-Error "BIOS bootmgr not found at: $bootmgrSource"
        exit 1
    }
    
    # UEFI bootmgr
    $bootmgrEfiSource = "${env:SystemRoot}\Boot\EFI\bootmgfw.efi"
    $bootmgrEfiDest = Join-Path $WorkDir "bootmgr.efi"
    $bootx64Dest = Join-Path $efiBootDir "bootx64.efi"
    
    if (Test-Path $bootmgrEfiSource) {
        Copy-Item $bootmgrEfiSource -Destination $bootmgrEfiDest -Force
        Copy-Item $bootmgrEfiSource -Destination $bootx64Dest -Force
    } else {
        Write-Error "UEFI bootmgr not found at: $bootmgrEfiSource"
        exit 1
    }
    
    # Create BCD store
    Write-Host "Creating BCD store..." -ForegroundColor Yellow
    $bcdPath = Join-Path $bootDir "bcd"
    
    # Create the BCD store
    & bcdedit /createstore $bcdPath | Out-Null
    
    if (-not (Test-Path $bcdPath)) {
        Write-Error "Failed to create BCD store at: $bcdPath"
        exit 1
    }
    
    # Configure bootmgr entry
    $bootmgrGuid = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"
    # Replace the current BCD configuration with this more robust version:
    & bcdedit /store $bcdPath /create $bootmgrGuid /d "Windows Boot Manager" | Out-Null
    & bcdedit /store $bcdPath /set $bootmgrGuid device boot | Out-Null
    & bcdedit /store $bcdPath /set $bootmgrGuid path \bootmgr | Out-Null
    & bcdedit /store $bcdPath /set $bootmgrGuid inherit {bootloadersettings} | Out-Null
    & bcdedit /store $bcdPath /set $bootmgrGuid locale en-US | Out-Null
    & bcdedit /store $bcdPath /set $bootmgrGuid integrityservices Enable | Out-Null 
    & bcdedit /store $bcdPath /set $bootmgrGuid recoverysequence $osLoaderGuid | Out-Null
    & bcdedit /store $bcdPath /set $bootmgrGuid recoveryenabled Yes | Out-Null
    & bcdedit /store $bcdPath /set $bootmgrGuid isolatedcontext Yes | Out-Null
    
    # Create ramdisk options
    $ramdiskGuid = "{7619dcc8-fafe-11d9-b411-000476eba25f}"
    & bcdedit /store $bcdPath /create $ramdiskGuid /d "Ramdisk Options" | Out-Null
    & bcdedit /store $bcdPath /set $ramdiskGuid ramdisksdidevice boot | Out-Null
    & bcdedit /store $bcdPath /set $ramdiskGuid ramdisksdipath \boot\boot.sdi | Out-Null
    
    # Create boot entry for each WIM file
    $displayOrder = @()
    foreach ($wimFile in $WimFiles) {
        $wimName = Split-Path $wimFile.FullName -Leaf
        $wimRelativePath = "\sources\$wimName"
        
        Write-Host "Creating boot entry for: $wimName" -ForegroundColor Yellow
        
        # Create OS loader entry
        $osLoaderOutput = & bcdedit /store $bcdPath /create /d "$IsoName - $wimName" /application osloader
        $osLoaderGuid = ($osLoaderOutput | Select-String -Pattern "\{[^}]+\}").Matches[0].Value
        
        if ($osLoaderGuid) {
        # For each WIM boot entry, add these critical parameters:
        & bcdedit /store $bcdPath /set $osLoaderGuid device "ramdisk=[$wimRelativePath],$ramdiskGuid" | Out-Null
        & bcdedit /store $bcdPath /set $osLoaderGuid osdevice "ramdisk=[$wimRelativePath],$ramdiskGuid" | Out-Null
        & bcdedit /store $bcdPath /set $osLoaderGuid systemroot \Windows | Out-Null
        & bcdedit /store $bcdPath /set $osLoaderGuid winpe yes | Out-Null
        & bcdedit /store $bcdPath /set $osLoaderGuid detecthal yes | Out-Null
        & bcdedit /store $bcdPath /set $osLoaderGuid nx OptIn | Out-Null
        & bcdedit /store $bcdPath /set $osLoaderGuid pae ForceEnable | Out-Null
            
            $displayOrder += $osLoaderGuid
        }
    }
    
    # Set display order and default
    if ($displayOrder.Count -gt 0) {
        $displayOrderString = $displayOrder -join " "
        & bcdedit /store $bcdPath /displayorder $displayOrderString | Out-Null
        & bcdedit /store $bcdPath /default $displayOrder[0] | Out-Null
    }
    
    # Create boot.sdi file
    $bootSdiSource = "${env:SystemRoot}\Boot\DVD\PCAT\boot.sdi"
    $bootSdiDest = Join-Path $bootDir "boot.sdi"
    
    if (Test-Path $bootSdiSource) {
        Copy-Item $bootSdiSource -Destination $bootSdiDest -Force
    } else {
        # Try alternative location
        $bootSdiAlt = Join-Path $oscdimgPath "boot.sdi"
        if (Test-Path $bootSdiAlt) {
            Copy-Item $bootSdiAlt -Destination $bootSdiDest -Force
        } else {
            Write-Error "boot.sdi not found in any expected locations."
            exit 1
        }
    }
    
    Write-Host "Boot structure created successfully." -ForegroundColor Green
    
    return @{
        EtfsbootPath = $etfsbootDest
        EfisysPath = $efisysDest
        BcdPath = $bcdPath
        BootSdiPath = $bootSdiDest
    }
}

# Function to verify boot files in ISO
function Test-BootFiles {
    param(
        [string]$IsoPath,
        [hashtable]$BootPaths
    )
    
    try {
        Write-Host "Verifying boot files in ISO..." -ForegroundColor Yellow
        
        # Mount the ISO
        $mountResult = Mount-DiskImage -ImagePath $IsoPath -PassThru -ErrorAction Stop
        $driveLetter = ($mountResult | Get-Volume).DriveLetter
        
        # Check critical boot files
        $requiredFiles = @(
            "$($driveLetter):\boot\bcd",
            "$($driveLetter):\boot\boot.sdi",
            "$($driveLetter):\boot\etfsboot.com",
            "$($driveLetter):\efi\microsoft\boot\bootmgfw.efi",
            "$($driveLetter):\efi\microsoft\boot\efisys.bin",
            "$($driveLetter):\sources\boot.wim"
        )
        
        $allFilesPresent = $true
        foreach ($file in $requiredFiles) {
            if (-not (Test-Path $file)) {
                Write-Warning "Boot file missing in ISO: $file"
                $allFilesPresent = $false
            }
        }
        
        # Dismount the ISO
        Dismount-DiskImage -ImagePath $IsoPath | Out-Null
        
        if ($allFilesPresent) {
            Write-Host "All required boot files verified in ISO." -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Some boot files are missing from the ISO."
            return $false
        }
    } catch {
        Write-Warning "Failed to verify boot files: $_"
        return $false
    }
}

# Main script execution
try {
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
    
    # Get source folder if not provided
    if (-not $SourceFolder) {
        $SourceFolder = Read-Host "Enter the path to the source folder containing WIM files"
    }
    
    # Clean up the path - remove quotes if present
    $SourceFolder = $SourceFolder.Trim('"').Trim("'")
    
    # Validate source folder
    if (-not (Test-Path $SourceFolder)) {
        Write-Error "Source folder does not exist: $SourceFolder"
        Write-Host "Please check the path and try again. Current path: '$SourceFolder'" -ForegroundColor Yellow
        exit 1
    }
    
    # Find WIM files
    $wimFiles = Get-ChildItem -Path $SourceFolder -Filter "*.wim" -Recurse
    if ($wimFiles.Count -eq 0) {
        Write-Error "No WIM files found in the source directory: $SourceFolder"
        exit 1
    }
    
    Write-Host "Found $($wimFiles.Count) WIM file(s):" -ForegroundColor Green
    foreach ($wim in $wimFiles) {
        Write-Host "  - $($wim.FullName)" -ForegroundColor Cyan
    }
    
    # Get ISO name from user if not provided
    if (-not $IsoName) {
        $IsoName = Read-Host "Enter the name for the ISO (without .iso extension)"
        if ([string]::IsNullOrWhiteSpace($IsoName)) {
            Write-Error "ISO name cannot be empty."
            exit 1
        }
    }
    
    # Remove invalid filename characters
    $IsoName = $IsoName -replace '[<>:"/\\|?*]', '_'
    
    Write-Host "Creating bootable ISO: $IsoName.iso" -ForegroundColor Cyan
    Write-Host "Source folder: $SourceFolder" -ForegroundColor Cyan
    
    # Install ADK if needed
    $oscdimgPath = Install-ADK
    
    # Create working directory
    $parentDir = Split-Path $SourceFolder -Parent
    $workDir = Join-Path $env:TEMP "ISO_$IsoName"
    $outputIso = Join-Path $parentDir "$IsoName.iso"
    
    # Clean up any existing work directory
    if (Test-Path $workDir) {
        Remove-Item $workDir -Recurse -Force
    }
    
    Write-Host "Setting up working directory..." -ForegroundColor Yellow
    
    # Copy existing structure if it's a complete ISO structure
    $hasBootStructure = (Test-Path (Join-Path $SourceFolder "boot")) -or 
                       (Test-Path (Join-Path $SourceFolder "bootmgr")) -or
                       (Test-Path (Join-Path $SourceFolder "BOOTMGR"))
    
    if ($hasBootStructure) {
        Write-Host "Existing boot structure detected, copying entire structure..." -ForegroundColor Yellow
        Copy-Item $SourceFolder -Destination $workDir -Recurse -Force
        
        # Ensure boot files exist
        $etfsbootPath = Join-Path $workDir "boot\etfsboot.com"
        $efisysPath = Join-Path $workDir "efi\microsoft\boot\efisys.bin"
        $bcdPath = Join-Path $workDir "boot\bcd"
        $bootSdiPath = Join-Path $workDir "boot\boot.sdi"
        
        $adkPath = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
        $oscdimgBootPath = "$adkPath\Deployment Tools\amd64\Oscdimg"
        
        # Verify and fix boot files
        if (-not (Test-Path $etfsbootPath)) {
            $etfsbootSource = Join-Path $oscdimgBootPath "etfsboot.com"
            if (Test-Path $etfsbootSource) {
                New-Item -ItemType Directory -Path (Split-Path $etfsbootPath -Parent) -Force | Out-Null
                Copy-Item $etfsbootSource -Destination $etfsbootPath -Force
            } else {
                Write-Error "etfsboot.com not found in ADK at: $etfsbootSource"
                exit 1
            }
        }
        
        if (-not (Test-Path $efisysPath)) {
            $efisysSource = Join-Path $oscdimgBootPath "efisys.bin"
            if (Test-Path $efisysSource) {
                New-Item -ItemType Directory -Path (Split-Path $efisysPath -Parent) -Force | Out-Null
                Copy-Item $efisysSource -Destination $efisysPath -Force
            } else {
                Write-Error "efisys.bin not found in ADK at: $efisysSource"
                exit 1
            }
        }
        
        if (-not (Test-Path $bcdPath)) {
            Write-Host "Creating new BCD store..." -ForegroundColor Yellow
            $bootPaths = New-BootStructure -WorkDir $workDir -IsoName $IsoName -WimFiles $wimFiles
        } else {
            $bootPaths = @{
                EtfsbootPath = $etfsbootPath
                EfisysPath = $efisysPath
                BcdPath = $bcdPath
                BootSdiPath = $bootSdiPath
            }
        }
    } else {
        Write-Host "No existing boot structure detected, creating from scratch..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
        
        # Copy any existing files
        Get-ChildItem -Path $SourceFolder -Recurse | ForEach-Object {
            $relativePath = $_.FullName.Substring($SourceFolder.Length + 1)
            $destPath = Join-Path $workDir $relativePath
            
            if ($_.PSIsContainer) {
                New-Item -ItemType Directory -Path $destPath -Force | Out-Null
            } else {
                $destDir = Split-Path $destPath -Parent
                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                Copy-Item $_.FullName -Destination $destPath -Force
            }
        }
        
        # Create complete boot structure
        $bootPaths = New-BootStructure -WorkDir $workDir -IsoName $IsoName -WimFiles $wimFiles
    }
    
    Write-Host "Creating ISO image..." -ForegroundColor Yellow
    
    # Create the ISO using oscdimg with proper boot configuration
    if ((Test-Path $bootPaths.EtfsbootPath) -and (Test-Path $bootPaths.EfisysPath)) {
        Write-Host "Using dual boot configuration (BIOS and UEFI)..." -ForegroundColor Green
        
        $oscdimgArgs = @(
            "-m",           # Ignore maximum image size
            "-o",           # Optimize storage
            "-u2",          # UDF file system
            "-udfver102",   # UDF version 1.02
            "-l$IsoName",   # Volume label
            "-bootdata:2#p0,e,b`"$($bootPaths.EtfsbootPath)`"#pEF,e,b`"$($bootPaths.EfisysPath)`"",
            "`"$workDir`"",
            "`"$outputIso`""
        )
    } elseif (Test-Path $bootPaths.EtfsbootPath) {
        Write-Host "Using BIOS-only boot configuration..." -ForegroundColor Yellow
        
        $oscdimgArgs = @(
            "-m",
            "-o",
            "-u2",
            "-udfver102",
            "-l$IsoName",
            "-b`"$($bootPaths.EtfsbootPath)`"",
            "`"$workDir`"",
            "`"$outputIso`""
        )
    } else {
        Write-Error "No boot files found. Cannot create bootable ISO."
        exit 1
    }
    
    # Execute oscdimg
    Write-Host "Running oscdimg with arguments:" -ForegroundColor Yellow
    Write-Host ($oscdimgArgs -join " ") -ForegroundColor Cyan
    
    $oscdimgProcess = Start-Process -FilePath $oscdimgPath -ArgumentList $oscdimgArgs -Wait -PassThru -NoNewWindow
    
    if ($oscdimgProcess.ExitCode -eq 0) {
        Write-Host "ISO created successfully: $outputIso" -ForegroundColor Green
        
        # Display file size
        $isoSize = (Get-Item $outputIso).Length
        $isoSizeMB = [math]::Round($isoSize / 1MB, 2)
        Write-Host "ISO size: $isoSizeMB MB" -ForegroundColor Green
        
        # Verify boot files in ISO
        $bootVerified = Test-BootFiles -IsoPath $outputIso -BootPaths $bootPaths
        
        if ($bootVerified) {
            Write-Host "ISO includes all required boot files and should be bootable." -ForegroundColor Green
        } else {
            Write-Warning "ISO created but boot verification failed. It may not boot properly."
        }
        
    } else {
        Write-Error "Failed to create ISO. oscdimg exit code: $($oscdimgProcess.ExitCode)"
        Write-Host "oscdimg arguments used:" -ForegroundColor Yellow
        Write-Host ($oscdimgArgs -join " ") -ForegroundColor Yellow
        exit 1
    }
    
    # Clean up working directory
    Write-Host "Cleaning up temporary files..." -ForegroundColor Yellow
    Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "Process completed successfully!" -ForegroundColor Green
    Write-Host "Your bootable ISO is ready at: $outputIso" -ForegroundColor Cyan
    
} catch {
    Write-Error "An error occurred: $_"
    exit 1
}
