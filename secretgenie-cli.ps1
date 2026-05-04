# Thin PowerShell wrapper that forwards all arguments to the SecretGenie CLI binary.

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$candidates = @(
    (Join-Path $scriptDir "secretgenie.exe"),
    (Join-Path $scriptDir "secretgenie-hsbc.exe")
)

$bin = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $bin) {
    Write-Error "secretgenie.exe not found alongside this wrapper."
    exit 1
}

& $bin @args
exit $LASTEXITCODE
