param(
    [switch]$SkipInstall,
    [switch]$NoLaunch
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

function Write-WarnText {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-ErrorText {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

function Get-PythonCommand {
    $venvPython = Join-Path $PSScriptRoot "recon\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }

    if (Get-Command py -ErrorAction SilentlyContinue) {
        return "py"
    }

    if (Get-Command python -ErrorAction SilentlyContinue) {
        return "python"
    }

    throw "Python was not found. Install Python or create the recon virtual environment first."
}

function Invoke-Python {
    param(
        [string]$PythonCommand,
        [string[]]$Arguments
    )

    & $PythonCommand @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed: $PythonCommand $($Arguments -join ' ')"
    }
}

function Test-Tool {
    param(
        [string]$Name,
        [string]$InstallHint
    )

    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        Write-Host "  [OK] $Name - found" -ForegroundColor Green
    }
    else {
        Write-Host "  [MISSING] $Name - Python fallback will be used" -ForegroundColor Yellow
        Write-Host "      Install: $InstallHint" -ForegroundColor DarkYellow
    }
}

function Test-ProjectDiscoveryHttpx {
    param([string]$InstallHint)

    $candidates = @()
    $resolved = Get-Command httpx -ErrorAction SilentlyContinue
    if ($resolved) {
        $candidates += $resolved.Source
    }

    $goHttpx = Join-Path $HOME "go\bin\httpx.exe"
    if (Test-Path $goHttpx) {
        $candidates += $goHttpx
    }

    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        try {
            $helpOutput = (& $candidate -h 2>&1 | Out-String)
        }
        catch {
            continue
        }

        if ($helpOutput -match "-status-code" -and ($helpOutput -match "-silent" -or $helpOutput -match "projectdiscovery")) {
            Write-Host "  [OK] httpx - found at $candidate" -ForegroundColor Green
            return
        }
    }

    if ($resolved) {
        Write-Host "  [MISMATCH] httpx - found, but it is not ProjectDiscovery httpx" -ForegroundColor Yellow
        Write-Host "      Install: $InstallHint" -ForegroundColor DarkYellow
        return
    }

    Write-Host "  [MISSING] httpx - Python fallback will be used" -ForegroundColor Yellow
    Write-Host "      Install: $InstallHint" -ForegroundColor DarkYellow
}

function Resolve-Wordlist {
    $candidates = @(
        (Join-Path $PSScriptRoot "wordlists\common.txt"),
        (Join-Path $PSScriptRoot "common.txt"),
        (Join-Path $HOME "SecLists\Discovery\Web-Content\common.txt"),
        (Join-Path $HOME "tools\SecLists\Discovery\Web-Content\common.txt")
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    return $null
}

Write-Host ""
Write-Host "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗" -ForegroundColor Green
Write-Host "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║" -ForegroundColor Green
Write-Host "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║" -ForegroundColor Green
Write-Host "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║" -ForegroundColor Green
Write-Host "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║" -ForegroundColor Green
Write-Host "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝" -ForegroundColor Green
Write-Host "  Bug Bounty Recon Automation - Windows Setup Script" -ForegroundColor Gray
Write-Host ""

$pythonCommand = Get-PythonCommand
Write-Info "Using Python: $pythonCommand"

Write-Host ""
Write-Section "[1/4] Installing Python dependencies..."
if ($SkipInstall) {
    Write-WarnText "  Skipping dependency installation because -SkipInstall was provided."
}
else {
    Invoke-Python -PythonCommand $pythonCommand -Arguments @("-m", "pip", "install", "fastapi", "uvicorn")
    Write-Host "  [OK] FastAPI and Uvicorn installed" -ForegroundColor Green
}

Write-Host ""
Write-Section "[2/4] Checking optional recon tools..."
Test-Tool -Name "subfinder" -InstallHint "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
Test-ProjectDiscoveryHttpx -InstallHint "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
Test-Tool -Name "nmap" -InstallHint "Install Nmap for Windows from nmap.org or via winget/choco"
Test-Tool -Name "ffuf" -InstallHint "go install github.com/ffuf/ffuf/v2@latest"
Test-Tool -Name "gau" -InstallHint "go install github.com/lc/gau/v2/cmd/gau@latest"

Write-Host ""
Write-Section "[3/4] Checking wordlists..."
$wordlist = Resolve-Wordlist
if ($wordlist) {
    $env:RECON_WORDLIST = $wordlist
    Write-Host "  [OK] Wordlist found: $wordlist" -ForegroundColor Green
}
else {
    Write-WarnText "  [MISSING] No local wordlist found."
    Write-WarnText "  Place a file at .\wordlists\common.txt or .\common.txt for directory fuzzing."
}

Write-Host ""
Write-Section "[4/4] Starting RECON//OS API..."
Write-Host ""
Write-Host "  API:       http://localhost:8000" -ForegroundColor Green
Write-Host "  Docs:      http://localhost:8000/docs" -ForegroundColor Green
Write-Host "  Dashboard: http://localhost:8000" -ForegroundColor Green
Write-Host ""
Write-WarnText "  TIP: Only scan targets you own or have written permission to test."
Write-Host ""

if ($NoLaunch) {
    Write-WarnText "Launch skipped because -NoLaunch was provided."
    exit 0
}

Invoke-Python -PythonCommand $pythonCommand -Arguments @("-m", "uvicorn", "recon_api:app", "--host", "0.0.0.0", "--port", "8000")
