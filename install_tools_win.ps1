param(
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Write-Section {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-WarnText {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Add-UserPathEntry {
    param([string]$PathToAdd)

    if (-not $PathToAdd) {
        return
    }

    $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($currentUserPath) {
        $parts = $currentUserPath -split ";"
    }

    if ($parts -notcontains $PathToAdd) {
        $newUserPath = (($parts + $PathToAdd) | Where-Object { $_ } | Select-Object -Unique) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    }

    if (($env:Path -split ";") -notcontains $PathToAdd) {
        $env:Path += ";$PathToAdd"
    }
}

function Resolve-GoCommand {
    if (Test-CommandAvailable "go") {
        return "go"
    }

    $programFilesGo = "C:\Program Files\Go\bin\go.exe"
    if (Test-Path $programFilesGo) {
        return $programFilesGo
    }

    return $null
}

function Test-GoAvailable {
    return [bool](Resolve-GoCommand)
}

function Resolve-NmapCommand {
    if (Test-CommandAvailable "nmap") {
        return "nmap"
    }

    $candidates = @(
        "C:\Program Files\Nmap\nmap.exe",
        "C:\Program Files (x86)\Nmap\nmap.exe"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Test-NmapAvailable {
    return [bool](Resolve-NmapCommand)
}

function Add-GoBinPath {
    $goBin = Join-Path $HOME "go\bin"
    if (-not (Test-Path $goBin)) {
        New-Item -ItemType Directory -Force -Path $goBin | Out-Null
    }
    Add-UserPathEntry -PathToAdd $goBin
    return $goBin
}

function Add-NmapPath {
    $nmapCommand = Resolve-NmapCommand
    if (-not $nmapCommand -or $nmapCommand -eq "nmap") {
        return $nmapCommand
    }

    $nmapDir = Split-Path -Parent $nmapCommand
    Add-UserPathEntry -PathToAdd $nmapDir
    return $nmapCommand
}

function Install-WingetPackage {
    param(
        [string]$PackageId,
        [string]$DisplayName,
        [string]$ManualUrl
    )

    if (-not (Test-CommandAvailable "winget")) {
        Write-WarnText "  winget is not available. Install $DisplayName manually: $ManualUrl"
        return $false
    }

    if ($CheckOnly) {
        Write-Info "  Would try winget install for $DisplayName ($PackageId)"
        return $false
    }

    try {
        & winget install --id $PackageId -e --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "  Installed $DisplayName with winget"
            return $true
        }
    } catch {
        Write-WarnText "  winget install failed for ${DisplayName}: $($_.Exception.Message)"
    }

    Write-WarnText "  Could not install $DisplayName automatically. Install manually: $ManualUrl"
    return $false
}

function Install-GoPrerequisite {
    Write-Section "[1/5] Checking Go..."
    $goCommand = Resolve-GoCommand
    if ($goCommand) {
        Write-Ok "  Go found: $goCommand"
        Add-GoBinPath | Out-Null
        return $goCommand
    }

    Write-WarnText "  Go is not installed."
    $null = Install-WingetPackage -PackageId "GoLang.Go" -DisplayName "Go" -ManualUrl "https://go.dev/doc/install"
    $goCommand = Resolve-GoCommand

    if ($goCommand) {
        Write-Ok "  Go is now available: $goCommand"
        Add-GoBinPath | Out-Null
        return $goCommand
    }

    Write-WarnText "  Go is still unavailable. Use the official installer: https://go.dev/doc/install"
    return $null
}

function Install-NmapPrerequisite {
    Write-Section "[2/5] Checking Nmap..."
    $nmapCommand = Add-NmapPath
    if ($nmapCommand) {
        Write-Ok "  Nmap is already installed: $nmapCommand"
        return $true
    }

    Write-WarnText "  Nmap is not installed."
    $installed = Install-WingetPackage -PackageId "Insecure.Nmap" -DisplayName "Nmap" -ManualUrl "https://nmap.org/download.html"
    $nmapCommand = Add-NmapPath
    if ($nmapCommand) {
        Write-Ok "  Nmap is now available: $nmapCommand"
        return $true
    }

    if (-not $installed) {
        Write-WarnText "  If winget does not work, install Nmap from https://nmap.org/download.html"
    }

    return (Test-NmapAvailable)
}

function Install-GoTool {
    param(
        [string]$GoCommand,
        [string]$CommandName,
        [string]$InstallTarget
    )

    if (Test-CommandAvailable $CommandName) {
        Write-Ok "  $CommandName already installed."
        return
    }

    if (-not $GoCommand) {
        Write-WarnText "  Skipping $CommandName because Go is not available."
        return
    }

    if ($CheckOnly) {
        Write-Info "  Would run: $GoCommand install $InstallTarget"
        return
    }

    & $GoCommand install $InstallTarget
    if ($LASTEXITCODE -ne 0) {
        Write-WarnText "  Failed to install $CommandName with go install."
        return
    }

    Add-GoBinPath | Out-Null

    if (Test-CommandAvailable $CommandName) {
        Write-Ok "  Installed $CommandName"
    } else {
        Write-WarnText "  $CommandName was installed, but you may need to open a new PowerShell window."
    }
}

function Install-ReconGoTools {
    param([string]$GoCommand)

    Write-Section "[3/5] Checking recon CLI tools..."
    Install-GoTool -GoCommand $GoCommand -CommandName "subfinder" -InstallTarget "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    Install-GoTool -GoCommand $GoCommand -CommandName "httpx" -InstallTarget "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    Install-GoTool -GoCommand $GoCommand -CommandName "ffuf" -InstallTarget "github.com/ffuf/ffuf/v2@latest"
    Install-GoTool -GoCommand $GoCommand -CommandName "gau" -InstallTarget "github.com/lc/gau/v2/cmd/gau@latest"
}

function Install-SecListsWordlist {
    Write-Section "[4/5] Checking local wordlist..."

    $wordlistDir = Join-Path $PSScriptRoot "wordlists"
    $wordlistPath = Join-Path $wordlistDir "common.txt"
    if (Test-Path $wordlistPath) {
        Write-Ok "  Wordlist already exists: $wordlistPath"
        $env:RECON_WORDLIST = $wordlistPath
        return $wordlistPath
    }

    if ($CheckOnly) {
        Write-Info "  Would download Discovery/Web-Content/common.txt directly from the SecLists repository"
        return $null
    }

    New-Item -ItemType Directory -Force -Path $wordlistDir | Out-Null

    $headers = @{ "User-Agent" = "RECON-OS-Installer" }
    $urls = @(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/main/Discovery/Web-Content/common.txt"
    )

    try {
        foreach ($url in $urls) {
            try {
                Invoke-WebRequest -Uri $url -OutFile $wordlistPath -Headers $headers
                if ((Test-Path $wordlistPath) -and ((Get-Item $wordlistPath).Length -gt 0)) {
                    $env:RECON_WORDLIST = $wordlistPath
                    Write-Ok "  Downloaded wordlist: $wordlistPath"
                    return $wordlistPath
                }
            } catch {
                Write-WarnText "  Download attempt failed: $url"
            }
        }

        throw "Could not download common.txt from the official SecLists repository."
    } catch {
        Write-WarnText "  Failed to download SecLists automatically: $($_.Exception.Message)"
        Write-WarnText "  Manual source: https://github.com/danielmiessler/SecLists/releases"
        return $null
    }
}

function Show-Summary {
    Write-Section "[5/5] Summary"
    if (Test-GoAvailable) {
        Write-Ok "  go: ready"
    } else {
        Write-WarnText "  go: missing"
    }

    foreach ($tool in @("subfinder", "httpx", "ffuf", "gau")) {
        if (Test-CommandAvailable $tool) {
            Write-Ok "  ${tool}: ready"
        } else {
            Write-WarnText "  ${tool}: missing"
        }
    }

    if (Test-NmapAvailable) {
        Write-Ok "  nmap: ready"
    } else {
        Write-WarnText "  nmap: missing"
    }

    $localWordlist = Join-Path $PSScriptRoot "wordlists\common.txt"
    if (Test-Path $localWordlist) {
        Write-Ok "  wordlist: $localWordlist"
    } else {
        Write-WarnText "  wordlist: missing"
    }

    Write-Host ""
    Write-Info "Next step:"
    Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File .\setup_recon_win.ps1" -ForegroundColor White
}

Write-Host ""
Write-Host "  RECON//OS" -ForegroundColor Green
Write-Host "  Windows Tool Installer" -ForegroundColor Green
Write-Host ""

$goCommand = Install-GoPrerequisite
Install-NmapPrerequisite | Out-Null
Install-ReconGoTools -GoCommand $goCommand
Install-SecListsWordlist | Out-Null
Show-Summary
