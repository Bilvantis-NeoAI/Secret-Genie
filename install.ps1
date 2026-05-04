# SecretGenie bootstrap installer for Windows (PowerShell 5+).
#
# Usage (from an end user's PowerShell prompt):
#   iex (iwr -UseBasicParsing 'https://your-host/install.ps1').Content
#   # or, safer (review before running):
#   iwr -UseBasicParsing 'https://your-host/install.ps1' -OutFile install-secretgenie.ps1
#   notepad install-secretgenie.ps1
#   powershell -ExecutionPolicy Bypass -File install-secretgenie.ps1
#
# What it does:
#   1. Checks prerequisites (Python 3.9+, pip, git, git identity, PATH).
#   2. Clones or updates the SecretGenie source tree under %USERPROFILE%\.secretgenie\src.
#   3. Installs the package with `pip install --user -e .`.
#   4. Runs `secretgenie install --auto` to wire up the git pre-push hook.
#
# Environment overrides:
#   $env:GENIE_REPO_URL      URL to clone from.
#   $env:GENIE_INSTALL_DIR   Where to put the source.
#   $env:GENIE_LOCAL_SOURCE  Skip clone and install from this directory instead.

$ErrorActionPreference = 'Stop'

# ---- Configuration -------------------------------------------------------
$RepoUrl    = if ($env:GENIE_REPO_URL)    { $env:GENIE_REPO_URL }    else { 'https://github.com/Bilvantis-NeoAI/Secret-Genie.git' }
$InstallDir = if ($env:GENIE_INSTALL_DIR) { $env:GENIE_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.secretgenie\src' }
$MinPyMajor = 3
$MinPyMinor = 9

# ---- Output helpers ------------------------------------------------------
function Write-Info($msg)  { Write-Host "→ $msg" -ForegroundColor Blue }
function Write-Ok($msg)    { Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "! $msg" -ForegroundColor Yellow }
function Fail($msg)        { Write-Host "✗ $msg" -ForegroundColor Red; exit 1 }

function Banner {
    Write-Host ""
    Write-Host "✦ SecretGenie installer" -ForegroundColor Cyan
    Write-Host "Local, browser-first git hook manager for catching secrets before push." -ForegroundColor DarkGray
    Write-Host ""
}

# ---- Python detection (prefer `py -3`, fall back to `python`) ------------
function Resolve-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $test = & py -3 -c "import sys; print(sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0) { return 'py -3' }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $test = & python -c "import sys; print(sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0) { return 'python' }
    }
    if (Get-Command python3 -ErrorAction SilentlyContinue) { return 'python3' }
    return $null
}

function Invoke-Python {
    param([Parameter(Mandatory)][string[]]$Args)
    $parts = $script:PythonCmd.Split(' ')
    $exe   = $parts[0]
    $pre   = if ($parts.Length -gt 1) { $parts[1..($parts.Length - 1)] } else { @() }
    & $exe @pre @Args
}

# ---- Prereq checks -------------------------------------------------------

function Check-OS {
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        Fail "This script is for Windows. On macOS/Linux use install.sh."
    }
    if ([Environment]::OSVersion.Platform -notin 'Win32NT','Win32Windows','Win32S','WinCE') {
        Fail "This script is for Windows. On macOS/Linux use install.sh."
    }
    Write-Ok "Operating system: Windows"
}

function Check-Python {
    $script:PythonCmd = Resolve-PythonCommand
    if (-not $script:PythonCmd) {
        Fail @"
Python 3 is not installed or not on PATH.
   Download Python 3.9+ from https://www.python.org/downloads/
   During install, tick 'Add python.exe to PATH'.
"@
    }
    $vStr = Invoke-Python -Args @('-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    $vStr = $vStr.Trim()
    $major, $minor = $vStr.Split('.')
    if ([int]$major -lt $MinPyMajor -or ([int]$major -eq $MinPyMajor -and [int]$minor -lt $MinPyMinor)) {
        Fail "Python $vStr is too old — need Python $MinPyMajor.$MinPyMinor or newer."
    }
    Write-Ok "Python $vStr ($script:PythonCmd)"
}

function Check-Pip {
    $null = Invoke-Python -Args @('-m','pip','--version')
    if ($LASTEXITCODE -ne 0) {
        Fail @"
pip is not available for your Python install.
   Try: $script:PythonCmd -m ensurepip --user
"@
    }
    Write-Ok "pip available"
}

function Check-Git {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Fail @"
git is not installed.
   Download: https://git-scm.com/download/win
"@
    }
    Write-Ok "git $((git --version) -replace '^git version ','')"
}

function Check-GitIdentity {
    $name  = (git config --global user.name  2>$null)
    $email = (git config --global user.email 2>$null)
    if (-not $name -or -not $email) {
        Fail @"
Git identity is not configured. Please run:
    git config --global user.name "Your Name"
    git config --global user.email "you@example.com"
Then re-run this installer.
"@
    }
    Write-Ok "git identity: $name <$email>"
}

function Detect-UserBin {
    $userBase = (Invoke-Python -Args @('-m','site','--user-base')).Trim()
    $script:UserBin = Join-Path $userBase 'Scripts'   # Windows uses Scripts, not bin
    $segments = $env:PATH -split ';'
    if ($segments -contains $script:UserBin) {
        $script:PathAlreadyOn = $true
        Write-Ok "User Scripts on PATH ($($script:UserBin))"
    } else {
        $script:PathAlreadyOn = $false
    }
}

function Update-UserPath {
    # This is a per-user PATH update via the registry — no admin rights needed.
    # The change persists across sessions but only reaches new processes.
    if ($script:PathAlreadyOn) { return }
    if ($env:GENIE_SKIP_PATH_UPDATE -eq '1') {
        Write-Warn "Skipping PATH update (GENIE_SKIP_PATH_UPDATE=1 set)."
        Write-Host "   Add $($script:UserBin) to your user PATH manually when you're ready." -ForegroundColor DarkGray
        $script:PathFixMessage = 'manual'
        return
    }

    $currentUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $currentUserPath) { $currentUserPath = '' }

    $userSegments = $currentUserPath -split ';' | Where-Object { $_ }
    if ($userSegments -notcontains $script:UserBin) {
        $newUserPath = if ($currentUserPath) { "$($script:UserBin);$currentUserPath" } else { $script:UserBin }
        [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
        Write-Ok "Added $($script:UserBin) to your user PATH (persists across sessions)"
    } else {
        Write-Ok "User PATH already contains $($script:UserBin)"
    }

    # Make it effective for the rest of this install script too
    $env:PATH = "$($script:UserBin);$env:PATH"
    $script:PathFixMessage = 'applied'
}

# ---- Install steps -------------------------------------------------------

function Fetch-Source {
    if ($env:GENIE_LOCAL_SOURCE) {
        $script:InstallDir = $env:GENIE_LOCAL_SOURCE
        Write-Info "Using local source at $script:InstallDir (GENIE_LOCAL_SOURCE set)"
        if (-not (Test-Path (Join-Path $script:InstallDir 'pyproject.toml'))) {
            Fail "GENIE_LOCAL_SOURCE=$script:InstallDir does not contain pyproject.toml"
        }
        return
    }

    $parent = Split-Path $InstallDir -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }

    if (Test-Path (Join-Path $InstallDir '.git')) {
        Write-Info "Updating existing source at $InstallDir..."
        git -C $InstallDir pull --ff-only --quiet
        if ($LASTEXITCODE -ne 0) { Fail "git pull failed. Fix conflicts manually, or remove $InstallDir and re-run." }
        Write-Ok "Source updated"
    } elseif (Test-Path $InstallDir) {
        Fail "$InstallDir exists but is not a git repo. Remove it and re-run."
    } else {
        Write-Info "Cloning $RepoUrl into $InstallDir..."
        git clone --quiet --depth 1 $RepoUrl $InstallDir
        if ($LASTEXITCODE -ne 0) { Fail "git clone failed. Check network and that $RepoUrl is correct." }
        Write-Ok "Source cloned"
    }
    $script:InstallDir = $InstallDir
}

function Install-Package {
    Write-Info "Installing SecretGenie (pip install --user -e)..."
    Invoke-Python -Args @('-m','pip','install','--user','--quiet','--upgrade','pip>=24.0') 2>$null
    Invoke-Python -Args @('-m','pip','install','--user','--quiet','--editable',$script:InstallDir)
    if ($LASTEXITCODE -ne 0) {
        Fail @"
pip install failed. Run without --quiet to see the full error:
    $script:PythonCmd -m pip install --user --editable $script:InstallDir
"@
    }
    Write-Ok "SecretGenie installed"
}

function Run-FirstTimeSetup {
    $genieBin = Join-Path $script:UserBin 'secretgenie.exe'
    if (-not (Test-Path $genieBin)) {
        # Some installs put the launcher with no extension
        $genieBin = Join-Path $script:UserBin 'secretgenie'
    }
    if (-not (Test-Path $genieBin)) {
        Fail "secretgenie command was not created in $($script:UserBin). Install may be incomplete."
    }
    Write-Info "Running first-time setup (git hook registration)..."
    & $genieBin install --auto
    if ($LASTEXITCODE -ne 0) {
        Fail @"
First-time setup failed. Try running manually:
    $genieBin install
"@
    }
}

function Final-Message {
    Write-Host ""
    Write-Host "All set!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:"
    switch ($script:PathFixMessage) {
        'applied' {
            Write-Host "  - Open a new PowerShell window to pick up the updated PATH"
        }
        'manual' {
            Write-Host "  - Add $($script:UserBin) to PATH (see instructions above)" -ForegroundColor Yellow
        }
    }
    Write-Host "  - Run 'secretgenie' to open the dashboard in your browser"
    Write-Host "  - Your next 'git push' will be scanned automatically"
    Write-Host "  - If secrets are found, a browser tab opens for you to approve or abort"
    Write-Host ""
    Write-Host "Source:    $script:InstallDir" -ForegroundColor DarkGray
    Write-Host "Update:    cd $script:InstallDir ; git pull ; $script:PythonCmd -m pip install --user -e ." -ForegroundColor DarkGray
    Write-Host "Uninstall: secretgenie uninstall --auto ; Remove-Item -Recurse -Force $script:InstallDir" -ForegroundColor DarkGray
    Write-Host ""
}

# ---- main ----------------------------------------------------------------

Banner
Write-Info "Checking prerequisites..."
Check-OS
Check-Python
Check-Pip
Check-Git
Check-GitIdentity
Detect-UserBin
Write-Host ""
Fetch-Source
Install-Package
Update-UserPath
Run-FirstTimeSetup
Final-Message
