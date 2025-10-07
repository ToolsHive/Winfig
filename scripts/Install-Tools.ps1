[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$SkipPermissions,
    [string]$LogPath = ""
)

# Set console encoding
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSDefaultParameterValues['*:Encoding'] = 'utf8'
} else {
    $OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}

# ============================================================================ #
#                               GLOBAL VARIABLES                               #
# ============================================================================ #

# Script metadata
$Script:ScriptMeta = @{
    Name         = "Winfig Tools Installer"
    Version      = "1.0.0"
    Author       = "Armoghan-ul-Mohmin"
    Description  = "Advanced Package Management System"
    PowerShell   = $PSVersionTable.PSVersion.ToString()
    StartTime    = Get-Date
}

# Color scheme for output
$Script:Colors = @{
    Primary     = "Cyan"
    Secondary   = "Magenta"
    Success     = "Green"
    Warning     = "Yellow"
    Error       = "Red"
    Info        = "White"
    Debug       = "Gray"
    Accent      = "Blue"
    Highlight   = "DarkYellow"
}

$Global:TempDir = [Environment]::GetEnvironmentVariable("TEMP")

# Configuration settings
$Script:Config = @{
    AssetsDirectory    = Join-Path $PSScriptRoot "Assets"
    WingetJsonFile    = "winget-packages.json"
    ChocoJsonFile     = "choco-packages.json"
    LogDirectory      = [System.IO.Path]::Combine($Global:TempDir, "Winfig-Logs")
    CacheTimeout      = 300  # 5 minutes cache for installed packages
    MaxRetries        = 3
    RetryDelay        = 2    # seconds
}

# Global variables
$Global:InstalledPackagesCache = $null
$Global:CacheTimestamp = $null
$Global:LogFile = $null
$Global:PackageStats = @{
    Total = 0
    Installed = 0
    Skipped = 0
    Failed = 0
    PermissionDenied = 0
}

# ============================================================================ #
#                              UTILITY FUNCTIONS                               #
# ============================================================================ #

function Initialize-Logging {
    try {
        # Create logs directory if it doesn't exist
        if (-not (Test-Path $Script:Config.LogDirectory)) {
            New-Item -ItemType Directory -Path $Script:Config.LogDirectory -Force | Out-Null
        }

        # Generate timestamped log filename
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $Global:LogFile = [System.IO.Path]::Combine($Script:Config.LogDirectory, "InstallTools-$timestamp.log")

        # Initialize log file
        Write-LogEntry -Message "=== Winfig Tools Installer Started ===" -Level "INFO"
        Write-LogEntry -Message "Version: $($Script:ScriptMeta.Version)" -Level "INFO"
        Write-LogEntry -Message "PowerShell Version: $($Script:ScriptMeta.PowerShell)" -Level "INFO"
        Write-LogEntry -Message "Log File: $Global:LogFile" -Level "INFO"

        return $true
    }
    catch {
        Write-Host "Failed to initialize logging: $($_.Exception.Message)" -ForegroundColor $Script:Colors.Error
        return $false
    }
}

function Write-LogEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO"
    )

    try {
        if ($Global:LogFile) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "[$timestamp] [$Level] $Message"
            Add-Content -Path $Global:LogFile -Value $logEntry -Encoding UTF8
        }
    }
    catch {
        # Silent fail for logging to prevent infinite loops
    }
}

function Write-ColorOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Color = "White",

        [Parameter(Mandatory = $false)]
        [string]$Level = "INFO",

        [switch]$NoNewline
    )

    # Simple output without complex formatting
    Write-Host $Message -ForegroundColor $Color
    Write-LogEntry -Message $Message -Level $Level
}

function Write-StatusMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("SUCCESS", "ERROR", "WARNING", "INFO")]
        [string]$Type = "INFO"
    )

    $symbol = switch ($Type) {
        "SUCCESS" { "[+]" }
        "ERROR"   { "[X]" }
        "WARNING" { "[!]" }
        "INFO"    { "[i]" }
    }

    $color = switch ($Type) {
        "SUCCESS" { $Script:Colors.Success }
        "ERROR"   { $Script:Colors.Error }
        "WARNING" { $Script:Colors.Warning }
        "INFO"    { $Script:Colors.Info }
    }

    $statusMessage = "$symbol $Message"
    Write-Host $statusMessage -ForegroundColor $color
    Write-LogEntry -Message $statusMessage -Level $Type
}

function Show-Banner {
    Clear-Host
    Start-Sleep -Milliseconds 100

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "                 WINFIG TOOLS INSTALLER                        " -ForegroundColor Magenta
    Write-Host "                     Version $($Script:ScriptMeta.Version)                         " -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Advanced Package Management System" -ForegroundColor Blue
    Write-Host ""
}

function Test-Prerequisites {
    Write-StatusMessage "Checking system prerequisites..." -Type "INFO"

    # Check admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
    if (-not $isAdmin) {
        Write-StatusMessage "Administrator privileges required. Please run as Administrator." -Type "ERROR"
        return $false
    }
    Write-StatusMessage "Administrator privileges confirmed" -Type "SUCCESS"

    # Check package managers
    $wingetAvailable = Get-Command winget -ErrorAction SilentlyContinue
    $chocoAvailable = Get-Command choco -ErrorAction SilentlyContinue

    if (-not $wingetAvailable -and -not $chocoAvailable) {
        Write-StatusMessage "No package managers found. Please install WinGet or Chocolatey." -Type "ERROR"
        return $false
    }

    if ($wingetAvailable) {
        Write-StatusMessage "WinGet package manager found" -Type "SUCCESS"
        # Test and fix WinGet configuration
        Test-WinGetConfiguration
    }
    if ($chocoAvailable) { Write-StatusMessage "Chocolatey package manager found" -Type "SUCCESS" }

    # Check Assets directory
    if (-not (Test-Path $Script:Config.AssetsDirectory)) {
        Write-StatusMessage "Assets directory not found: $($Script:Config.AssetsDirectory)" -Type "ERROR"
        return $false
    }
    Write-StatusMessage "Assets directory found" -Type "SUCCESS"

    return $true
}

function Test-WinGetConfiguration {
    <#
    .SYNOPSIS
        Tests and fixes WinGet configuration issues
    #>

    try {
        Write-StatusMessage "Verifying WinGet configuration..." -Type "INFO"

        # Test basic WinGet functionality
        $testProcess = Start-Process -FilePath "winget" -ArgumentList @("--version") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "temp_winget_version.txt" -RedirectStandardError "temp_winget_version_err.txt"

        if ($testProcess.ExitCode -ne 0) {
            Write-StatusMessage "WinGet basic test failed, attempting to repair..." -Type "WARNING"

            # Try to update sources
            $updateProcess = Start-Process -FilePath "winget" -ArgumentList @("source", "update", "--force") -NoNewWindow -Wait -PassThru
            if ($updateProcess.ExitCode -eq 0) {
                Write-StatusMessage "WinGet sources updated successfully" -Type "SUCCESS"
            } else {
                Write-StatusMessage "WinGet source update failed" -Type "WARNING"
            }
        } else {
            Write-StatusMessage "WinGet configuration verified" -Type "SUCCESS"
        }

        # Clean up temp files
        Remove-Item "temp_winget_version.txt" -ErrorAction SilentlyContinue
        Remove-Item "temp_winget_version_err.txt" -ErrorAction SilentlyContinue
    }
    catch {
        Write-LogEntry "WinGet configuration test failed: $($_.Exception.Message)" "WARNING"
    }
}

# ============================================================================ #
#                          PACKAGE DETECTION FUNCTIONS                         #
# ============================================================================ #

function Get-InstalledPackages {
    # Check cache validity
    if ($Global:InstalledPackagesCache -and $Global:CacheTimestamp) {
        $cacheAge = (Get-Date) - $Global:CacheTimestamp
        if ($cacheAge.TotalSeconds -lt $Script:Config.CacheTimeout) {
            Write-LogEntry "Using cached installed packages list" "DEBUG"
            return $Global:InstalledPackagesCache
        }
    }

    Write-StatusMessage "Scanning installed packages (this may take a moment)..." -Type "INFO"
    Write-LogEntry "Refreshing installed packages cache" "INFO"

    try {
        # Use WMI to get installed products (more reliable than registry)
        $installedProducts = @()

        # Method 1: WMI Win32_Product (slower but more comprehensive)
        try {
            $wmiProducts = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue |
                          Select-Object Name, Version, IdentifyingNumber
            $installedProducts += $wmiProducts
        }
        catch {
            Write-LogEntry "WMI Win32_Product query failed: $($_.Exception.Message)" "WARNING"
        }

        # Method 2: Registry (faster for additional packages)
        try {
            $registryPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )

            foreach ($path in $registryPaths) {
                if (Test-Path $path.Replace('\*', '')) {
                    $regProducts = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                                  Where-Object { $_.DisplayName } |
                                  Select-Object @{Name='Name';Expression={$_.DisplayName}},
                                               @{Name='Version';Expression={$_.DisplayVersion}},
                                               @{Name='IdentifyingNumber';Expression={$_.PSChildName}}
                    $installedProducts += $regProducts
                }
            }
        }
        catch {
            Write-LogEntry "Registry scan failed: $($_.Exception.Message)" "WARNING"
        }

        # Remove duplicates and cache results
        $uniqueProducts = $installedProducts | Sort-Object Name -Unique
        $Global:InstalledPackagesCache = $uniqueProducts
        $Global:CacheTimestamp = Get-Date

        Write-StatusMessage "Found $($uniqueProducts.Count) installed packages" -Type "SUCCESS"
        Write-LogEntry "Cached $($uniqueProducts.Count) installed packages" "INFO"

        return $uniqueProducts
    }
    catch {
        Write-StatusMessage "Failed to scan installed packages: $($_.Exception.Message)" -Type "ERROR"
        Write-LogEntry "Package scan failed: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Test-PackageInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageName,

        [Parameter(Mandatory = $false)]
        [string]$PackageId = ""
    )

    Write-LogEntry "Checking if package '$PackageName' (ID: '$PackageId') is installed..." "DEBUG"

    # If we have a package ID, try to use the appropriate package manager to check
    if ($PackageId) {
        # Try WinGet first
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            try {
                $wingetResult = Start-Process -FilePath "winget" -ArgumentList @("list", "--id", $PackageId, "--exact") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "temp_winget_check.txt" -RedirectStandardError "temp_winget_error.txt"

                if ($wingetResult.ExitCode -eq 0) {
                    $output = Get-Content "temp_winget_check.txt" -Raw -ErrorAction SilentlyContinue
                    if ($output -and $output -match [regex]::Escape($PackageId)) {
                        Write-LogEntry "Package '$PackageName' found via WinGet" "DEBUG"
                        # Clean up temp files
                        Remove-Item "temp_winget_check.txt" -ErrorAction SilentlyContinue
                        Remove-Item "temp_winget_error.txt" -ErrorAction SilentlyContinue
                        return $true
                    }
                }

                # Clean up temp files
                Remove-Item "temp_winget_check.txt" -ErrorAction SilentlyContinue
                Remove-Item "temp_winget_error.txt" -ErrorAction SilentlyContinue
            }
            catch {
                Write-LogEntry "WinGet check failed for '$PackageName': $($_.Exception.Message)" "DEBUG"
            }
        }

        # Try Chocolatey
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            try {
                $chocoResult = Start-Process -FilePath "choco" -ArgumentList @("list", "--local-only", "--exact", $PackageId) -NoNewWindow -Wait -PassThru -RedirectStandardOutput "temp_choco_check.txt" -RedirectStandardError "temp_choco_error.txt"

                if ($chocoResult.ExitCode -eq 0) {
                    $output = Get-Content "temp_choco_check.txt" -Raw -ErrorAction SilentlyContinue
                    if ($output -and $output -match [regex]::Escape($PackageId) -and $output -notmatch "0 packages installed") {
                        Write-LogEntry "Package '$PackageName' found via Chocolatey" "DEBUG"
                        # Clean up temp files
                        Remove-Item "temp_choco_check.txt" -ErrorAction SilentlyContinue
                        Remove-Item "temp_choco_error.txt" -ErrorAction SilentlyContinue
                        return $true
                    }
                }

                # Clean up temp files
                Remove-Item "temp_choco_check.txt" -ErrorAction SilentlyContinue
                Remove-Item "temp_choco_error.txt" -ErrorAction SilentlyContinue
            }
            catch {
                Write-LogEntry "Chocolatey check failed for '$PackageName': $($_.Exception.Message)" "DEBUG"
            }
        }
    }

    Write-LogEntry "Package '$PackageName' not found via package managers" "DEBUG"
    return $false
}

# ============================================================================ #
#                           JSON PROCESSING FUNCTIONS                          #
# ============================================================================ #

function Read-PackageJsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        if (-not (Test-Path $FilePath)) {
            Write-StatusMessage "Package file not found: $FilePath" -Type "WARNING"
            return @()
        }

        Write-LogEntry "Reading package file: $FilePath" "INFO"

        # Read and parse JSON (PowerShell 5.x and 7.x compatible)
        $jsonContent = Get-Content -Path $FilePath -Raw -Encoding UTF8
        $packages = $jsonContent | ConvertFrom-Json

        # Ensure it's an array
        if ($packages -isnot [Array]) {
            $packages = @($packages)
        }

        Write-StatusMessage "Loaded $($packages.Count) packages from $(Split-Path $FilePath -Leaf)" -Type "SUCCESS"
        Write-LogEntry "Successfully parsed $($packages.Count) packages" "INFO"

        return $packages
    }
    catch {
        Write-StatusMessage "Failed to read package file: $($_.Exception.Message)" -Type "ERROR"
        Write-LogEntry "JSON parse error for $FilePath`: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-AllPackages {
    $allPackages = @{
        WinGet = @()
        Chocolatey = @()
    }

    # Read WinGet packages
    $wingetPath = Join-Path $Script:Config.AssetsDirectory $Script:Config.WingetJsonFile
    $wingetPackages = Read-PackageJsonFile -FilePath $wingetPath
    foreach ($package in $wingetPackages) {
        $package | Add-Member -NotePropertyName "Manager" -NotePropertyValue "WinGet" -Force
        $allPackages.WinGet += $package
    }

    # Read Chocolatey packages
    $chocoPath = Join-Path $Script:Config.AssetsDirectory $Script:Config.ChocoJsonFile
    $chocoPackages = Read-PackageJsonFile -FilePath $chocoPath
    foreach ($package in $chocoPackages) {
        $package | Add-Member -NotePropertyName "Manager" -NotePropertyValue "Chocolatey" -Force
        $allPackages.Chocolatey += $package
    }

    $totalPackages = $allPackages.WinGet.Count + $allPackages.Chocolatey.Count
    $Global:PackageStats.Total = $totalPackages

    Write-StatusMessage "Total packages to process: $totalPackages" -Type "INFO"
    Write-LogEntry "Package summary - WinGet: $($allPackages.WinGet.Count), Chocolatey: $($allPackages.Chocolatey.Count)" "INFO"

    return $allPackages
}

# ============================================================================ #
#                          INSTALLATION FUNCTIONS                             #
# ============================================================================ #

function Request-InstallPermission {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Package
    )

    if ($SkipPermissions) {
        return $true
    }

    # Check if package has permission property
    if ($Package.PSObject.Properties.Name -contains "permission") {
        if ($Package.permission -eq $true -or $Package.permission -eq "true") {
            Write-LogEntry "Package '$($Package.name)' has automatic permission" "DEBUG"
            return $true
        }
        elseif ($Package.permission -eq $false -or $Package.permission -eq "false") {
            # Ask user for permission
            Write-Host ""
            Write-Host "Package: $($Package.name)" -ForegroundColor Yellow
            Write-Host "Description: $($Package.description)" -ForegroundColor White
            Write-Host "Homepage: $($Package.homepage)" -ForegroundColor Cyan
            Write-Host ""

            do {
                Write-Host "Do you want to install this package? (Y/N): " -ForegroundColor Yellow -NoNewline
                $response = Read-Host
                $response = $response.ToUpper()
            } while ($response -notin @('Y', 'N', 'YES', 'NO'))

            $granted = $response -in @('Y', 'YES')
            Write-LogEntry "User permission for '$($Package.name)': $granted" "INFO"

            if (-not $granted) {
                $Global:PackageStats.PermissionDenied++
            }

            return $granted
        }
    }

    # Default behavior - auto-install
    return $true
}

function Install-WinGetPackage {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Package
    )

    $retryCount = 0

    do {
        try {
            Write-LogEntry "Installing WinGet package: $($Package.name) (ID: $($Package.id))" "INFO"

            # First try to update sources if this is the first retry
            if ($retryCount -eq 1) {
                Write-StatusMessage "Updating WinGet sources..." -Type "INFO"
                try {
                    $updateProcess = Start-Process -FilePath "winget" -ArgumentList @("source", "update") -NoNewWindow -Wait -PassThru
                    Write-LogEntry "WinGet source update exit code: $($updateProcess.ExitCode)" "INFO"
                    Start-Sleep -Seconds 2
                }
                catch {
                    Write-LogEntry "WinGet source update failed: $($_.Exception.Message)" "WARNING"
                }
            }

            $arguments = @(
                "install",
                "--id", $Package.id,
                "--exact",
                "--silent",
                "--accept-source-agreements",
                "--accept-package-agreements",
                "--disable-interactivity",
                "--force"
            )

            # Create temp files for output capture
            $tempOut = [System.IO.Path]::GetTempFileName()
            $tempErr = [System.IO.Path]::GetTempFileName()

            $process = Start-Process -FilePath "winget" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr

            # Read output for debugging
            $stdout = Get-Content $tempOut -Raw -ErrorAction SilentlyContinue
            $stderr = Get-Content $tempErr -Raw -ErrorAction SilentlyContinue

            # Clean up temp files
            Remove-Item $tempOut -ErrorAction SilentlyContinue
            Remove-Item $tempErr -ErrorAction SilentlyContinue

            # Log the output for debugging
            if ($stdout) { Write-LogEntry "WinGet stdout: $stdout" "DEBUG" }
            if ($stderr) { Write-LogEntry "WinGet stderr: $stderr" "DEBUG" }

            if ($process.ExitCode -eq 0) {
                Write-StatusMessage "Successfully installed: $($Package.name)" -Type "SUCCESS"
                Write-LogEntry "WinGet installation successful for: $($Package.name)" "SUCCESS"
                return $true
            }
            else {
                # Check for specific error codes
                $errorMsg = switch ($process.ExitCode) {
                    -1978335230 { "WinGet catalog/source error - trying source update" }
                    -1978335221 { "Package not found in configured sources" }
                    -1978335232 { "Installation failed - package may require user interaction" }
                    default { "WinGet returned exit code: $($process.ExitCode)" }
                }

                if ($stderr) { $errorMsg += " - Error: $stderr" }
                throw $errorMsg
            }
        }
        catch {
            $retryCount++
            Write-LogEntry "WinGet installation attempt $retryCount failed for '$($Package.name)': $($_.Exception.Message)" "WARNING"

            if ($retryCount -lt $Script:Config.MaxRetries) {
                Write-StatusMessage "Retrying installation in $($Script:Config.RetryDelay) seconds..." -Type "WARNING"
                Start-Sleep -Seconds $Script:Config.RetryDelay
            }
            else {
                Write-StatusMessage "Failed to install: $($Package.name) - $($_.Exception.Message)" -Type "ERROR"
                Write-LogEntry "WinGet installation failed permanently for: $($Package.name)" "ERROR"
                return $false
            }
        }
    } while ($retryCount -lt $Script:Config.MaxRetries)

    return $false
}

function Install-ChocolateyPackage {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Package
    )

    $retryCount = 0

    do {
        try {
            Write-LogEntry "Installing Chocolatey package: $($Package.name) (ID: $($Package.id))" "INFO"

            $arguments = @(
                "install", $Package.id,
                "-y",
                "--no-progress",
                "--limit-output",
                "--no-color"
            )

            # Create temp files for output capture
            $tempOut = [System.IO.Path]::GetTempFileName()
            $tempErr = [System.IO.Path]::GetTempFileName()

            $process = Start-Process -FilePath "choco" -ArgumentList $arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr

            # Read output for debugging
            $stdout = Get-Content $tempOut -Raw -ErrorAction SilentlyContinue
            $stderr = Get-Content $tempErr -Raw -ErrorAction SilentlyContinue

            # Clean up temp files
            Remove-Item $tempOut -ErrorAction SilentlyContinue
            Remove-Item $tempErr -ErrorAction SilentlyContinue

            if ($process.ExitCode -eq 0) {
                Write-StatusMessage "Successfully installed: $($Package.name)" -Type "SUCCESS"
                Write-LogEntry "Chocolatey installation successful for: $($Package.name)" "SUCCESS"
                return $true
            }
            else {
                $errorMsg = "Chocolatey returned exit code: $($process.ExitCode)"
                if ($stderr) { $errorMsg += " - Error: $stderr" }
                throw $errorMsg
            }
        }
        catch {
            $retryCount++
            Write-LogEntry "Chocolatey installation attempt $retryCount failed for '$($Package.name)': $($_.Exception.Message)" "WARNING"

            if ($retryCount -lt $Script:Config.MaxRetries) {
                Write-StatusMessage "Retrying installation in $($Script:Config.RetryDelay) seconds..." -Type "WARNING"
                Start-Sleep -Seconds $Script:Config.RetryDelay
            }
            else {
                Write-StatusMessage "Failed to install: $($Package.name) - $($_.Exception.Message)" -Type "ERROR"
                Write-LogEntry "Chocolatey installation failed permanently for: $($Package.name)" "ERROR"
                return $false
            }
        }
    } while ($retryCount -lt $Script:Config.MaxRetries)

    return $false
}

function Install-Package {
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Package
    )

    # Validate required properties
    if (-not $Package.name -or -not $Package.id) {
        Write-StatusMessage "Package missing required properties (name/id)" -Type "ERROR"
        Write-LogEntry "Invalid package object: missing name or id" "ERROR"
        return $false
    }

    Write-Host ""
    Write-Host "Processing: $($Package.name) [$($Package.Manager)]" -ForegroundColor White
    Write-LogEntry -Message "Processing: $($Package.name) [$($Package.Manager)]" -Level "INFO"

    # Check if already installed (skip if Force is not specified)
    if (-not $Force -and (Test-PackageInstalled -PackageName $Package.name -PackageId $Package.id)) {
        Write-StatusMessage "Already installed, skipping: $($Package.name)" -Type "WARNING"
        Write-LogEntry "Package already installed: $($Package.name)" "INFO"
        $Global:PackageStats.Skipped++
        return $true
    }

    # Request permission if needed
    if (-not (Request-InstallPermission -Package $Package)) {
        Write-StatusMessage "Installation denied by user: $($Package.name)" -Type "WARNING"
        return $false
    }

    # Install using appropriate manager
    $success = $false

    switch ($Package.Manager) {
        "WinGet" {
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                $success = Install-WinGetPackage -Package $Package
            }
            else {
                Write-StatusMessage "WinGet not available for: $($Package.name)" -Type "ERROR"
                Write-LogEntry "WinGet not available but required for: $($Package.name)" "ERROR"
            }
        }
        "Chocolatey" {
            if (Get-Command choco -ErrorAction SilentlyContinue) {
                $success = Install-ChocolateyPackage -Package $Package
            }
            else {
                Write-StatusMessage "Chocolatey not available for: $($Package.name)" -Type "ERROR"
                Write-LogEntry "Chocolatey not available but required for: $($Package.name)" "ERROR"
            }
        }
        default {
            Write-StatusMessage "Unknown package manager: $($Package.Manager)" -Type "ERROR"
            Write-LogEntry "Unknown package manager '$($Package.Manager)' for package: $($Package.name)" "ERROR"
        }
    }

    if ($success) {
        $Global:PackageStats.Installed++
    }
    else {
        $Global:PackageStats.Failed++
    }

    return $success
}

# ============================================================================ #
#                              MAIN EXECUTION                                  #
# ============================================================================ #

function Show-Summary {
    $duration = (Get-Date) - $Script:ScriptMeta.StartTime
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "                    INSTALLATION SUMMARY                       " -ForegroundColor Magenta
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host " Total Packages:        $($Global:PackageStats.Total) packages processed" -ForegroundColor White
    Write-Host " Successfully Installed: $($Global:PackageStats.Installed) packages" -ForegroundColor Green
    Write-Host " Already Installed:      $($Global:PackageStats.Skipped) packages skipped" -ForegroundColor Yellow
    Write-Host " Permission Denied:      $($Global:PackageStats.PermissionDenied) packages denied" -ForegroundColor Yellow
    Write-Host " Failed Installations:   $($Global:PackageStats.Failed) packages failed" -ForegroundColor Red
    Write-Host " Execution Time:         $($duration.ToString('mm\:ss')) minutes" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-LogEntry "=== Installation Summary ===" "INFO"
    Write-LogEntry "Total: $($Global:PackageStats.Total), Installed: $($Global:PackageStats.Installed), Skipped: $($Global:PackageStats.Skipped), Failed: $($Global:PackageStats.Failed), Denied: $($Global:PackageStats.PermissionDenied)" "INFO"
    Write-LogEntry "Execution time: $($duration.ToString())" "INFO"
    Write-LogEntry "=== Winfig Tools Installer Completed ===" "INFO"

    if ($Global:PackageStats.Failed -gt 0) {
        Write-StatusMessage "Some packages failed to install. Check the log file for details: $Global:LogFile" -Type "WARNING"
    }
    elseif ($Global:PackageStats.Installed -gt 0) {
        Write-StatusMessage "Installation completed successfully!" -Type "SUCCESS"
    }
    else {
        Write-StatusMessage "No new packages were installed." -Type "INFO"
    }
}

function Main {
    try {
        # Initialize
        Show-Banner

        if (-not (Initialize-Logging)) {
            Write-Host "Failed to initialize logging. Continuing without file logging." -ForegroundColor $Script:Colors.Warning
        }

        # Check prerequisites
        if (-not (Test-Prerequisites)) {
            Write-StatusMessage "Prerequisites check failed. Exiting." -Type "ERROR"
            exit 1
        }

        # Load packages
        Write-Host ""
        Write-StatusMessage "Loading package configurations..." -Type "INFO"
        $allPackages = Get-AllPackages

        if (($allPackages.WinGet.Count + $allPackages.Chocolatey.Count) -eq 0) {
            Write-StatusMessage "No packages found to install." -Type "WARNING"
            return
        }

        # Pre-load installed packages cache
        Write-Host ""
        Get-InstalledPackages | Out-Null

        # Process Chocolatey packages
        if ($allPackages.Chocolatey.Count -gt 0) {
            Write-Host ""
            Write-Host "===============================================================" -ForegroundColor Blue
            Write-Host "                 CHOCOLATEY PACKAGES                          " -ForegroundColor Magenta
            Write-Host "===============================================================" -ForegroundColor Blue

            foreach ($package in $allPackages.Chocolatey) {
                Install-Package -Package $package | Out-Null
            }
        }

        # Process WinGet packages
        if ($allPackages.WinGet.Count -gt 0) {
            Write-Host ""
            Write-Host "===============================================================" -ForegroundColor Blue
            Write-Host "                    WINGET PACKAGES                           " -ForegroundColor Magenta
            Write-Host "===============================================================" -ForegroundColor Blue

            foreach ($package in $allPackages.WinGet) {
                Install-Package -Package $package | Out-Null
            }
        }

        # Show summary
        Show-Summary

    }
    catch {
        Write-StatusMessage "Critical error occurred: $($_.Exception.Message)" -Type "ERROR"
        Write-LogEntry "Critical error: $($_.Exception.Message)" "ERROR"
        Write-LogEntry "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        exit 1
    }
}

# ============================================================================ #
#                                 EXECUTION                                    #
# ============================================================================ #

# Run main function
Main

