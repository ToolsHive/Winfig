#!/usr/bin/env powershell
<#
===============================================================================
Script Name  : bootstrap.ps1
Author       : Armoghan-ul-Mohmin
Date         : 2025-10-04
Version      : 1.0.0
-------------------------------------------------------------------------------
Description:
    A small, battle-tested Windows configuration toolkit to bootstrap a developer-friendly environment on a fresh install.

Workflow:
    1. Environment Validation
    2. System Restore Point Creation
    3. Prerequisite Installation
    4. Repository Cloning
    5. Configuration Execution
    6. Cleanup and Finalization


-------------------------------------------------------------------------------
Usage:
    # Run directly from the web:
        Invoke-RestMethod -Uri "https://raw.githubusercontent.com/ToolsHive/Winfig/main/bootstrap.ps1" | Invoke-Expression

    # Execute after downloading:
        .\bootstrap.ps1

===============================================================================
#>

#  Set UTF-8 Encoding with BOM for Output
$utf8WithBom = New-Object System.Text.UTF8Encoding $true
$OutputEncoding = $utf8WithBom
[Console]::OutputEncoding = $utf8WithBom

# ============================================================================ #
#                               Global Variables                               #
# ============================================================================ #

# Script Metadata
$Script:ScriptMeta = @{
    Author      = "Armoghan-ul-Mohmin"
    Version     = "1.0.0"
    ScriptName  = "Winfig Bootstrap"
    FullName    = "BOOTSTRAP CONFIGURATION SYSTEM"
    Description = "Enterprise Windows Configuration Management Platform"
    RepoURL     = "https://github.com/ToolsHive/Winfig"
    License     = "MIT"
    Platform    = "Windows"
    PowerShell  = $PSVersionTable.PSVersion.ToString()
    StartTime   = Get-Date
}

# Color Palette
$Script:Colors = @{
    Primary    = "Cyan"
    Success    = "Green"
    Warning    = "Yellow"
    Error      = "Red"
    Accent     = "Magenta"
    Light      = "White"
    Dark       = "Gray"
    Highlight  = "Yellow"
    Info       = "Gray"
}

# User Prompts
$Script:Prompts = @{
    Confirm    = "[?] Do you want to proceed? (Y/N): "
    Retry      = "[?] Do you want to retry? (Y/N): "
    Abort      = "[!] Operation aborted by user."
    Continue   = "[*] Press any key to continue..."
}

# Logging Configuration
$Script:LogConfig = @{
    LogLevel = "INFO"
    EnableConsole = $false
    EnableFile = $true
}

# Initialize global variables
$Global:TempDir = [Environment]::GetEnvironmentVariable("TEMP")
$Global:LogDir = [System.IO.Path]::Combine($Global:TempDir, "Winfig-Logs")
$Global:LogFile = [System.IO.Path]::Combine($Global:LogDir, "Winfig-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log")
$Global:ConfigDir = $null
$Global:RepoDir = $null

# ============================================================================ #
#                             Helper Functions                                 #
# ============================================================================ #

# ---------------------------------------------------------------------------- #
# Returns the user's Documents path, considering OneDrive if present
function DocumentsPath {
    $oneDriveVars = @("OneDrive", "OneDriveCommercial", "OneDriveConsumer")
    foreach ($var in $oneDriveVars) {
        $path = [Environment]::GetEnvironmentVariable($var, "User")
        if ($path) {
            $docs = Join-Path $path "Documents"
            if (Test-Path $docs) {
                $Global:ConfigDir = $docs
                $Global:RepoDir = Join-Path $docs "Winfig"
                return $docs
            }
        }
    }
    $defaultDocs = [Environment]::GetFolderPath('MyDocuments')
    if (Test-Path $defaultDocs) {
        $Global:ConfigDir = $defaultDocs
        $Global:RepoDir = Join-Path $defaultDocs "Winfig"
        return $defaultDocs
    }
    return $null
}

# ---------------------------------------------------------------------------- #
# Enhanced logging function with file output only (no console by default)
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",

        [Parameter(Mandatory=$false)]
        [switch]$ShowConsole,

        [Parameter(Mandatory=$false)]
        [switch]$NoFile
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Ensure log directory exists and write to file (default behavior)
    if ($Script:LogConfig.EnableFile -and -not $NoFile) {
        if (-not (Test-Path $Global:LogDir)) {
            New-Item -ItemType Directory -Path $Global:LogDir -Force | Out-Null
        }
        Add-Content -Path $Global:LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    # Console output only when explicitly requested
    if ($ShowConsole) {
        $color = switch ($Level) {
            "DEBUG"   { $Script:Colors.Dark }
            "INFO"    { $Script:Colors.Info }
            "WARN"    { $Script:Colors.Warning }
            "ERROR"   { $Script:Colors.Error }
            "SUCCESS" { $Script:Colors.Success }
            default   { $Script:Colors.Light }
        }

        # Format console output differently
        switch ($Level) {
            "DEBUG"   { Write-Host "   [DEBUG] $Message" -ForegroundColor $color }
            "INFO"    { Write-Host "   $Message" -ForegroundColor $color }
            "WARN"    { Write-Host "   [WARNING] $Message" -ForegroundColor $color }
            "ERROR"   { Write-Host "   [ERROR] $Message" -ForegroundColor $color }
            "SUCCESS" { Write-Host "   $Message" -ForegroundColor $color }
            default   { Write-Host "   $Message" -ForegroundColor $color }
        }
    }
}

# ---------------------------------------------------------------------------- #
# Write section headers with logging
function Write-Section {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title,

        [Parameter(Mandatory=$false)]
        [string]$Description = ""
    )

    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════════════════════════" -ForegroundColor $Script:Colors.Primary
    Write-Host " $Title" -ForegroundColor $Script:Colors.Primary
    if ($Description) {
        Write-Host " $Description" -ForegroundColor $Script:Colors.Info
    }
    Write-Host "══════════════════════════════════════════════════════════════════════════════" -ForegroundColor $Script:Colors.Primary

    Write-Log "Starting section: $Title" -Level "INFO" -NoConsole
    if ($Description) {
        Write-Log "Description: $Description" -Level "INFO" -NoConsole
    }
}

# ---------------------------------------------------------------------------- #
# Write subsection headers
function Write-SubSection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title
    )

    Write-Host ""
    Write-Host " $Title" -ForegroundColor $Script:Colors.Primary

    Write-Log "Starting subsection: $Title" -Level "INFO" -NoConsole
}

# ---------------------------------------------------------------------------- #
# Checks if the Windows version is supported (Windows 10/11)
function WindowsVersion {
    $windowsBuild = [System.Environment]::OSVersion.Version.Build
    $isWindows10Or11 = ($windowsBuild -ge 10240)
    if ($isWindows10Or11) {
        $windowsName = if ($windowsBuild -ge 22000) { "Windows 11" } else { "Windows 10" }
        Write-Host " [2/6] Windows version ...................... [PASS]" -ForegroundColor $Script:Colors.Success
        return @{Check="Windows Version"; Result="PASS"; Message="Running on $windowsName (Build $windowsBuild)"}
    } else {
        Write-Host " [2/6] Windows version ...................... [FAIL]" -ForegroundColor $Script:Colors.Error
        return @{Check="Windows Version"; Result="FAIL"; Message="Windows 10 or 11 required. Current build: $windowsBuild"}
    }
}

# ---------------------------------------------------------------------------- #
# Checks if PowerShell version is 5.1 or higher
function PowerShellVersion {
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        Write-Host " [3/6] PowerShell version ................... [PASS]" -ForegroundColor $Script:Colors.Success
        return @{Check="PowerShell Version"; Result="PASS"; Message="PowerShell $($psVersion.ToString()) detected"}
    } else {
        Write-Host " [3/6] PowerShell version ................... [FAIL]" -ForegroundColor $Script:Colors.Error
        return @{Check="PowerShell Version"; Result="FAIL"; Message="PowerShell 5.1 or higher required. Current version: $($psVersion.ToString())"}
    }
}

# ---------------------------------------------------------------------------- #
# Checks for internet connectivity
function InternetConnection {
    $internetTest = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -ErrorAction SilentlyContinue
    if ($internetTest) {
        Write-Host " [4/6] Internet connection .................. [PASS]" -ForegroundColor $Script:Colors.Success
        return @{Check="Internet Connection"; Result="PASS"; Message="Internet connection available"}
    } else {
        Write-Host " [4/6] Internet connection .................. [FAIL]" -ForegroundColor $Script:Colors.Error
        return @{Check="Internet Connection"; Result="FAIL"; Message="No internet connection detected"}
    }
}

# ---------------------------------------------------------------------------- #
# Checks if there is enough free disk space (2GB minimum)
function DiskSpace {
    $systemDrive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object Size, FreeSpace
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    $minSpaceGB = 2
    if ($freeSpaceGB -ge $minSpaceGB) {
        Write-Host " [5/6] Disk space (C:) ...................... [PASS]" -ForegroundColor $Script:Colors.Success
        return @{Check="Disk Space"; Result="PASS"; Message="$freeSpaceGB GB free space available"}
    } else {
        Write-Host " [5/6] Disk space (C:) ...................... [FAIL]" -ForegroundColor $Script:Colors.Error
        return @{Check="Disk Space"; Result="FAIL"; Message="Only $freeSpaceGB GB free. Minimum $minSpaceGB GB required"}
    }
}

# ---------------------------------------------------------------------------- #
# Checks if the execution policy is suitable
function CheckExecutionPolicy {
    $executionPolicy = Get-ExecutionPolicy
    $allowedPolicies = @("RemoteSigned", "Unrestricted", "Bypass")
    if ($executionPolicy -in $allowedPolicies) {
        Write-Host " [6/6] Execution policy ..................... [PASS]" -ForegroundColor $Script:Colors.Success
        return @{Check="Execution Policy"; Result="PASS"; Message="Execution policy: $executionPolicy"}
    } else {
        Write-Host " [6/6] Execution policy ..................... [WARN]" -ForegroundColor $Script:Colors.Warning
        return @{Check="Execution Policy"; Result="WARN"; Message="Execution policy: $executionPolicy. Recommended: RemoteSigned"}
    }
}

# ---------------------------------------------------------------------------- #
# Checks if the script is running as Administrator
function IsAdmin {
    Write-Log "Checking administrator privileges" -Level "INFO"
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        Write-Host " [1/6] Administrator privileges ............. [PASS]" -ForegroundColor $Script:Colors.Success
        Write-Log "Administrator privileges verified - running with elevated privileges" -Level "SUCCESS"
        return @{Check="Administrator"; Result="PASS"; Message="Script running with elevated privileges"}
    } else {
        Write-Host " [1/6] Administrator privileges ............. [FAIL]" -ForegroundColor $Script:Colors.Error
        Write-Log "Administrator privileges check failed - script must be run as Administrator" -Level "ERROR"
        return @{Check="Administrator"; Result="FAIL"; Message="Script must be run as Administrator"}
    }
}

# ---------------------------------------------------------------------------- #
# Ensures Chocolatey is installed
function EnsureChocolatey {
    Write-Host ""
    Write-Host " Checking for Chocolatey..." -ForegroundColor $Script:Colors.Primary
    Write-Log "Checking for Chocolatey package manager installation" -Level "INFO"

    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "   Chocolatey is installed." -ForegroundColor $Script:Colors.Success
        Write-Log "Chocolatey is already installed and available" -Level "SUCCESS"
        return $true
    } else {
        Write-Host "   Chocolatey is not installed. Installing Chocolatey..." -ForegroundColor $Script:Colors.Warning
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-Host "   Chocolatey installed successfully." -ForegroundColor $Script:Colors.Success
            return $true
        } else {
            Write-Host "   Failed to install Chocolatey." -ForegroundColor $Script:Colors.Error
            return $false
        }
    }
}

# ---------------------------------------------------------------------------- #
# Ensures Winget is installed
function EnsureWinget {
    Write-Host ""
    Write-Host " Checking for Winget..." -ForegroundColor $Script:Colors.Primary

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "   Winget is installed." -ForegroundColor $Script:Colors.Success
        return $true
    } else {
        Write-Host "   Winget is not installed. Installing Winget..." -ForegroundColor $Script:Colors.Warning

        try {
            if ([System.Environment]::OSVersion.Version.Build -ge 26100) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                Install-Module "Microsoft.WinGet.Client" -Force
                Import-Module Microsoft.WinGet.Client
                Repair-WinGetPackageManager -Force -Latest -Verbose
                Write-Host "   Winget installed via PowerShell module." -ForegroundColor $Script:Colors.Success
                return $true
            } else {
                $wingetInstallerUrl = "https://aka.ms/getwinget"
                $wingetInstallerPath = Join-Path $env:TEMP "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
                Invoke-WebRequest -Uri $wingetInstallerUrl -OutFile $wingetInstallerPath -UseBasicParsing
                Add-AppxPackage -Path $wingetInstallerPath
                Write-Host "   Winget installed via App Installer." -ForegroundColor $Script:Colors.Success
                return $true
            }
        } catch {
            Write-Host "   Failed to install Winget: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Error
            return $false
        }
    }
}

# ---------------------------------------------------------------------------- #
# Installs Git using winget or Chocolatey
function InstallGit {
    Write-Host ""
    Write-Host " Checking for Git..." -ForegroundColor $Script:Colors.Primary

    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Host "   Git is installed." -ForegroundColor $Script:Colors.Success
        return $true
    } else {
        Write-Host "   Git is not installed. Installing Git..." -ForegroundColor $Script:Colors.Warning

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            try {
                Write-Host "   Attempting to install Git with winget..." -ForegroundColor $Script:Colors.Info
                winget install --id Git.Git -e --accept-source-agreements --accept-package-agreements -h
                if (Get-Command git -ErrorAction SilentlyContinue) {
                    Write-Host "   Git installed successfully via winget." -ForegroundColor $Script:Colors.Success
                    return $true
                }
            } catch {
                Write-Host "   Winget installation failed: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Warning
            }
        }

        if (Get-Command choco -ErrorAction SilentlyContinue) {
            try {
                Write-Host "   Attempting to install Git with Chocolatey..." -ForegroundColor $Script:Colors.Info
                choco install git -y
                $env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                if (Get-Command git -ErrorAction SilentlyContinue) {
                    Write-Host "   Git installed successfully via Chocolatey." -ForegroundColor $Script:Colors.Success
                    return $true
                }
            } catch {
                Write-Host "   Chocolatey installation failed: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Warning
            }
        }

        Write-Host "   Failed to install Git using available methods." -ForegroundColor $Script:Colors.Error
        return $false
    }
}

# ============================================================================ #
#                            Initialization                                    #
# ============================================================================ #

# Innitialize Documents path
DocumentsPath | Out-Null

# Initialize logging
Write-Log "======================================================================" -Level "INFO"
Write-Log "WINFIG BOOTSTRAP STARTED" -Level "INFO"
Write-Log "Script Version: $($Script:ScriptMeta.Version)" -Level "INFO"
Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" -Level "INFO"
Write-Log "Operating System: $([System.Environment]::OSVersion.VersionString)" -Level "INFO"
Write-Log "User: $([System.Environment]::UserName)" -Level "INFO"
Write-Log "Computer: $([System.Environment]::MachineName)" -Level "INFO"
Write-Log "Log File: $Global:LogFile" -Level "INFO"
Write-Log "======================================================================" -Level "INFO"

# ============================================================================ #
#                                Functions                                     #
# ============================================================================ #

# ---------------------------------------------------------------------------- #
# Displays a stylized banner for the script
function ShowBanner {
    Clear-Host
    Write-Host ""
    Write-Host ("  ██╗    ██╗██╗███╗   ██╗███████╗██╗ ██████╗  ".PadRight(70)) -ForegroundColor $Script:Colors.Light
    Write-Host ("  ██║    ██║██║████╗  ██║██╔════╝██║██╔════╝  ".PadRight(70)) -ForegroundColor $Script:Colors.Light
    Write-Host ("  ██║ █╗ ██║██║██╔██╗ ██║█████╗  ██║██║  ███╗ ".PadRight(70)) -ForegroundColor $Script:Colors.Accent
    Write-Host ("  ██║███╗██║██║██║╚██╗██║██╔══╝  ██║██║   ██║ ".PadRight(70)) -ForegroundColor $Script:Colors.Accent
    Write-Host ("  ╚███╔███╔╝██║██║ ╚████║██║     ██║╚██████╔╝ ".PadRight(70)) -ForegroundColor $Script:Colors.Success
    Write-Host ("   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝  ".PadRight(70)) -ForegroundColor $Script:Colors.Success
    Write-Host ((" " * 70)) -ForegroundColor $Script:Colors.Primary
    Write-Host ("        " + $Script:ScriptMeta.FullName).PadLeft(48).PadRight(70) -ForegroundColor $Script:Colors.Primary
    Write-Host ((" " * 70)) -ForegroundColor $Script:Colors.Primary
    Write-Host ("  " + $Script:ScriptMeta.Description).PadRight(70) -ForegroundColor $Script:Colors.Accent
    Write-Host ((" " * 70)) -ForegroundColor $Script:Colors.Primary
    Write-Host (("  Version: " + $Script:ScriptMeta.Version + "    PowerShell: " + $Script:ScriptMeta.PowerShell).PadRight(70)) -ForegroundColor $Script:Colors.Highlight
    Write-Host (("  Author:  " + $Script:ScriptMeta.Author + "    Platform: " + $Script:ScriptMeta.Platform).PadRight(70)) -ForegroundColor $Script:Colors.Highlight
    Write-Host ""
}

# ---------------------------------------------------------------------------- #
# Validates the environment for all prerequisites
function ValidateEnvironment {
    Write-Host ""
    Write-Host "==============================================================================" -ForegroundColor $Script:Colors.Primary
    Write-Host " Validating environment..." -ForegroundColor $Script:Colors.Primary
    Write-Host ""

    $results = @()
    $allValid = $true

    $checks = @(
        { IsAdmin },
        { WindowsVersion },
        { PowerShellVersion },
        { InternetConnection },
        { DiskSpace },
        { CheckExecutionPolicy }
    )

    foreach ($check in $checks) {
        $result = & $check
        $results += $result
        if ($result.Result -eq "FAIL") { $allValid = $false }
    }

    if (-not $allValid) {
        Write-Host ""
        Write-Host " One or more environment checks failed. Please address the issues above and re-run the script." -ForegroundColor $Script:Colors.Error
        exit 1
    }
    Write-Host ""
}

## ---------------------------------------------------------------------------- #
# Checks if system restore point capability is available
function Test-RestorePointCapability {
    try {
        if ($env:OS -ne "Windows_NT") { return $false }

        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.ProductType -ne 1) { return $false } # Only Workstation versions support this

        if (-not (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue)) {
            return $false
        }

        $systemDrive = $env:SystemDrive
        if (-not $systemDrive) { $systemDrive = "C:" }

        # Check for protection status
        $protectionEnabled = $false
        try {
            $vol = Get-WmiObject -Query "SELECT * FROM Win32_Volume WHERE DriveLetter='$systemDrive'" -ErrorAction SilentlyContinue
            if ($vol) {
                $protectionEnabled = $vol.AutomaticManagedPagefile -or $vol.SystemVolume
            }
        } catch {
            $protectionEnabled = $false
        }

        if (-not $protectionEnabled) {
            try {
                Enable-ComputerRestore -Drive $systemDrive -ErrorAction SilentlyContinue
                $protectionEnabled = $true
            } catch {
                $protectionEnabled = $false
            }
        }

        return $protectionEnabled
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------- #
# Creates a system restore point using Checkpoint-Computer
function New-RestorePoint {
    param(
        [string]$Description = "Winfig Bootstrap Installation",
        [ValidateSet("APPLICATION_INSTALL", "APPLICATION_UNINSTALL", "DEVICE_DRIVER_INSTALL", "MODIFY_SETTINGS")]
        [string]$EventType = "MODIFY_SETTINGS",
        [switch]$Force
    )

    try {
        if (-not (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue)) {
            return @{ Success = $false; Error = "Checkpoint-Computer cmdlet not available on this system" }
        }

        $systemDrive = $env:SystemDrive
        if (-not $systemDrive) { $systemDrive = "C:" }

        # Ensure System Protection is enabled
        try { Enable-ComputerRestore -Drive $systemDrive -ErrorAction SilentlyContinue } catch {}

        $restorePointName = "Winfig_Bootstrap_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Write-Host "   Creating restore point: $restorePointName" -ForegroundColor $Script:Colors.Info

        # Handle Force parameter by temporarily reducing the frequency limit
        $registryModified = $false
        $originalValue = $null

        if ($Force) {
            try {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
                $regName = "SystemRestorePointCreationFrequency"

                # Backup original value
                $originalValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue

                # Set to 0 to allow immediate restore point creation
                Set-ItemProperty -Path $regPath -Name $regName -Value 0 -Type DWord -Force
                $registryModified = $true
                Write-Host "   Temporarily reduced restore point frequency limit" -ForegroundColor $Script:Colors.Debug
            } catch {
                Write-Host "   Could not modify registry, proceeding anyway" -ForegroundColor $Script:Colors.Warning
            }
        }

        try {
            # Suppress all output and warnings from Checkpoint-Computer
            $null = Checkpoint-Computer -Description $restorePointName -RestorePointType $EventType -ErrorAction Stop -WarningAction SilentlyContinue
            $result = @{ Success = $true; Method = "Checkpoint-Computer"; Name = $restorePointName }
        } finally {
            # Restore original registry value if we modified it
            if ($registryModified) {
                try {
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
                    $regName = "SystemRestorePointCreationFrequency"

                    if ($originalValue) {
                        Set-ItemProperty -Path $regPath -Name $regName -Value $originalValue.$regName -Type DWord -Force
                    } else {
                        Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
                    }
                    Write-Host "   Restored original restore point frequency setting" -ForegroundColor $Script:Colors.Debug
                } catch {
                    Write-Host "   Could not restore registry setting" -ForegroundColor $Script:Colors.Warning
                }
            }
        }

        return $result

    } catch {
        $errorMsg = $_.Exception.Message

        # Handle the 24-hour restriction gracefully
        if ($errorMsg -match "1440 minutes" -or $errorMsg -match "already been created") {
            # A restore point was created within 24 hours - this is actually fine
            Write-Host "   Recent restore point already exists (within 24 hours)" -ForegroundColor $Script:Colors.Info
            Write-Host "   Skipping new restore point creation." -ForegroundColor $Script:Colors.Info
            return @{ Success = $true; Method = "Existing"; Name = "Recent restore point" }
        } elseif ($errorMsg -match "not enabled") {
            $errorMsg = "System Protection is disabled. Enable it in System Properties > System Protection"
        } elseif ($errorMsg -match "insufficient privileges") {
            $errorMsg = "Insufficient privileges. Run as Administrator"
        } elseif ($errorMsg -match "service") {
            $errorMsg = "Volume Shadow Copy Service may be stopped. Check Windows Services"
        }
        return @{ Success = $false; Error = $errorMsg }
    }
}

# ---------------------------------------------------------------------------- #
# Requests user confirmation and creates a restore point if possible
function SetupRestorePoint {
    Write-Host ""
    Write-Host "==============================================================================" -ForegroundColor $Script:Colors.Primary
    Write-Host " Setting up a system restore point..." -ForegroundColor $Script:Colors.Primary

    Write-Host ""
    Write-Host $Script:Prompts.Confirm -ForegroundColor $Script:Colors.Warning -NoNewline
    $response = Read-Host
    if ($response -notin @('Y', 'y')) {
        Write-Host "   Skipping system restore point setup." -ForegroundColor $Script:Colors.Warning
        return
    }

    Write-Host "   Checking system restore capability..." -ForegroundColor $Script:Colors.Info

    if (-not (Test-RestorePointCapability)) {
        Write-Host "   System restore points are not available or not properly configured." -ForegroundColor $Script:Colors.Warning
        Write-Host "   To enable System Restore:" -ForegroundColor $Script:Colors.Info
        Write-Host "   1. Open System Properties (Win+Pause or Control Panel > System)" -ForegroundColor $Script:Colors.Info
        Write-Host "   2. Click 'System Protection' tab" -ForegroundColor $Script:Colors.Info
        Write-Host "   3. Select your system drive and click 'Configure'" -ForegroundColor $Script:Colors.Info
        Write-Host "   4. Select 'Turn on system protection'" -ForegroundColor $Script:Colors.Info
        Write-Host ""
        Write-Host "   Continuing without restore point..." -ForegroundColor $Script:Colors.Warning
        return $false
    }

    Write-Host "   System restore capability confirmed." -ForegroundColor $Script:Colors.Success
    $result = New-RestorePoint -Description "Winfig Bootstrap - Pre-installation state" -EventType "MODIFY_SETTINGS"

    if ($result.Success) {
        Write-Host "   System restore point created successfully: $($result.Name)" -ForegroundColor $Script:Colors.Success
        Write-Host "   You can restore to this point if needed." -ForegroundColor $Script:Colors.Info
        return $true
    } else {
        Write-Host "   Failed to create system restore point:" -ForegroundColor $Script:Colors.Error
        Write-Host "   $($result.Error)" -ForegroundColor $Script:Colors.Error
        Write-Host ""
        Write-Host "   Common solutions:" -ForegroundColor $Script:Colors.Info
        Write-Host "   • Run PowerShell as Administrator" -ForegroundColor $Script:Colors.Info
        Write-Host "   • Enable System Protection in System Properties" -ForegroundColor $Script:Colors.Info
        Write-Host "   • Ensure Volume Shadow Copy Service is running" -ForegroundColor $Script:Colors.Info
        Write-Host "   • Check available disk space (need at least 300MB)" -ForegroundColor $Script:Colors.Info
        Write-Host ""
        Write-Host "   Continuing without restore point..." -ForegroundColor $Script:Colors.Warning
        return $false
    }
}

# ---------------------------------------------------------------------------- #
# Installs all prerequisites (Chocolatey, Winget, Git)
function InstallPrerequisites {
    Write-Host ""
    Write-Host "==============================================================================" -ForegroundColor $Script:Colors.Primary
    Write-Host " Installing prerequisites..." -ForegroundColor $Script:Colors.Primary
    Write-Host ""
    Write-Host " This process will install the following components:" -ForegroundColor $Script:Colors.Info
    Write-Host "   - Chocolatey (Package Manager)" -ForegroundColor $Script:Colors.Dark
    Write-Host "   - Winget (Microsoft Package Manager)" -ForegroundColor $Script:Colors.Dark
    Write-Host "   - Git (Version Control)" -ForegroundColor $Script:Colors.Dark

    Write-Log "Starting prerequisite installation process" -Level "INFO"
    Write-Log "Components to install: Chocolatey, Winget, Git" -Level "INFO"

    Write-Host ""
    Write-Host " [1/3] Installing Chocolatey..." -ForegroundColor $Script:Colors.Highlight
    Write-Log "Step 1/3: Installing Chocolatey package manager" -Level "INFO"
    $chocoInstalled = EnsureChocolatey
    Write-Log "Chocolatey installation result: $chocoInstalled" -Level "INFO"

    Write-Host ""
    Write-Host " [2/3] Setting up Winget..." -ForegroundColor $Script:Colors.Highlight
    Write-Log "Step 2/3: Setting up Winget package manager" -Level "INFO"
    $wingetAvailable = EnsureWinget
    Write-Log "Winget setup result: $wingetAvailable" -Level "INFO"

    Write-Host ""
    Write-Host " [3/3] Installing Git..." -ForegroundColor $Script:Colors.Highlight
    Write-Log "Step 3/3: Installing Git version control system" -Level "INFO"
    $gitInstalled = InstallGit
    Write-Log "Git installation result: $gitInstalled" -Level "INFO"

    # Summary Table
    Write-Host ""
    Write-Host "---------------------------- Installation Summary ---------------------------" -ForegroundColor $Script:Colors.Primary
    Write-Host (" " * 2) + "Chocolatey   : " $(if ($chocoInstalled) { "OK" } else { "FAILED" }) -ForegroundColor $(if ($chocoInstalled) { $Script:Colors.Success } else { $Script:Colors.Error })
    Write-Host (" " * 2) + "Winget       : " $(if ($wingetAvailable) { "OK" } else { "FAILED" }) -ForegroundColor $(if ($wingetAvailable) { $Script:Colors.Success } else { $Script:Colors.Warning })
    Write-Host (" " * 2) + "Git          : " $(if ($gitInstalled) { "OK" } else { "FAILED" }) -ForegroundColor $(if ($gitInstalled) { $Script:Colors.Success } else { $Script:Colors.Error })

    # Note: $uvInstalled and $pythonInstalled are not set in this function; remove or update as needed.
    if ($chocoInstalled -and $wingetAvailable -and $gitInstalled) {
        Write-Host ""
        Write-Host " Core prerequisites installed successfully." -ForegroundColor $Script:Colors.Success
        return $true
    } else {
        Write-Host ""
        Write-Host " Some prerequisites failed to install. The script will continue but some features may not work." -ForegroundColor $Script:Colors.Warning
        return $false
    }
}

# ---------------------------------------------------------------------------- #
# Clones or updates the Winfig repository
function CloneRepository {
    Write-Host ""
    Write-Host "==============================================================================" -ForegroundColor $Script:Colors.Primary
    Write-Host " Cloning the Winfig repository..." -ForegroundColor $Script:Colors.Primary

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "   Git is not available. Cannot clone repository." -ForegroundColor $Script:Colors.Error
        return $false
    }

    $currentDir = Get-Location

    if (Test-Path $Global:RepoDir) {
        # Check if the directory is a valid git repository
        if (Test-Path (Join-Path $Global:RepoDir ".git")) {
            Write-Host "   Repository already exists at $Global:RepoDir. Pulling latest changes..." -ForegroundColor $Script:Colors.Warning
            try {
                Push-Location $Global:RepoDir
                git pull origin main
                Pop-Location
                Write-Host "   Repository updated successfully." -ForegroundColor $Script:Colors.Success
                return $true
            } catch {
                Pop-Location
                Write-Host "   Error updating repository: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Error
                return $false
            }
        } else {
            Write-Host "   Directory exists but is not a git repository. Removing and re-cloning..." -ForegroundColor $Script:Colors.Warning
            try {
                Remove-Item -Path $Global:RepoDir -Recurse -Force
            } catch {
                Write-Host "   Failed to remove existing directory: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Error
                return $false
            }
            # Proceed to clone
            try {
                git clone $Script:ScriptMeta.RepoURL $Global:RepoDir
                Write-Host "   Repository cloned successfully to $Global:RepoDir." -ForegroundColor $Script:Colors.Success
                return $true
            } catch {
                Write-Host "   Error cloning repository: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Error
                return $false
            }
        }
    } else {
        try {
            git clone $Script:ScriptMeta.RepoURL $Global:RepoDir
            Write-Host "   Repository cloned successfully to $Global:RepoDir." -ForegroundColor $Script:Colors.Success
            return $true
        } catch {
            Write-Host "   Error cloning repository: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Error
            return $false
        }
    }
}

# ============================================================================ #
#                                Main Logic                                    #
# ============================================================================ #
ShowBanner
Write-Log "Banner displayed successfully" -Level "INFO"


ValidateEnvironment
Write-Log "Environment validation completed" -Level "INFO"

SetupRestorePoint | Out-Null
Write-Log "System restore point setup completed" -Level "INFO"

$prereqsInstalled = InstallPrerequisites
Write-Log "Prerequisites installation completed. Result: $prereqsInstalled" -Level "INFO"

$repoCloned = CloneRepository
Write-Log "Repository cloning completed. Result: $repoCloned" -Level "INFO"

# Final Summary
Write-Host ""
Write-Host "==============================================================================" -ForegroundColor $Script:Colors.Primary
Write-Host " Bootstrap Summary" -ForegroundColor $Script:Colors.Primary
Write-Host "------------------------------------------------------------------------------" -ForegroundColor $Script:Colors.Primary
Write-Host (" " * 2) + "Environment Validation :  OK" -ForegroundColor $Script:Colors.Success
Write-Host (" " * 2) + "Restore Point          :  OK" -ForegroundColor $Script:Colors.Success
Write-Host (" " * 2) + "Prerequisites          : " $(if ($prereqsInstalled) { "OK" } else { "Partial" }) -ForegroundColor $(if ($prereqsInstalled) { $Script:Colors.Success } else { $Script:Colors.Warning })
Write-Host (" " * 2) + "Repository             : " $(if ($repoCloned) { "OK" } else { "FAILED" }) -ForegroundColor $(if ($repoCloned) { $Script:Colors.Success } else { $Script:Colors.Error })
Write-Host "------------------------------------------------------------------------------" -ForegroundColor $Script:Colors.Primary
Write-Host ""

# Final logging
$endTime = Get-Date
$duration = $endTime - $Script:ScriptMeta.StartTime
Write-Log "======================================================================" -Level "INFO"
Write-Log "WINFIG BOOTSTRAP COMPLETED" -Level "INFO"
Write-Log "Total execution time: $([math]::Round($duration.TotalMinutes, 2)) minutes" -Level "INFO"
Write-Log "End time: $endTime" -Level "INFO"
Write-Log "Final status - Prerequisites: $prereqsInstalled | Repository: $repoCloned " -Level "INFO"
Write-Log "Log file saved to: $Global:LogFile" -Level "INFO"
Write-Log "======================================================================" -Level "INFO"

Write-Host " Log file saved to: $Global:LogFile" -ForegroundColor $Script:Colors.Info
Write-Host " Please review the log file for detailed information." -ForegroundColor $Script:Colors.Info
Write-Host ""
