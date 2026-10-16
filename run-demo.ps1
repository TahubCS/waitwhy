# run-demo.ps1
# Builds slowapp and waitwhy, then shows waitwhy finding the lock bug in slowapp,
# first in the buggy version and then in the fixed version.
#
# Run this from an ADMINISTRATOR PowerShell window, in the folder with the .cpp files:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\run-demo.ps1

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# 1. Kernel tracing needs Administrator rights.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Please run this from an Administrator PowerShell window (right-click PowerShell > Run as administrator)." -ForegroundColor Red
    exit 1
}

# 2. Find the Visual Studio C++ compiler and switch to 64-bit (x64) mode.
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        Write-Host "Visual Studio was not found. Install 'Build Tools for Visual Studio' with the" -ForegroundColor Red
        Write-Host "'Desktop development with C++' workload, then run this script again." -ForegroundColor Red
        exit 1
    }
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vsPath) {
        Write-Host "Visual Studio is installed but the C++ tools are missing. Add the 'Desktop development with C++' workload." -ForegroundColor Red
        exit 1
    }
    Import-Module (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
    Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
}
if ($env:VSCMD_ARG_TGT_ARCH -and $env:VSCMD_ARG_TGT_ARCH -ne 'x64') {
    Write-Host "This shell builds $($env:VSCMD_ARG_TGT_ARCH) programs, but waitwhy must be 64-bit." -ForegroundColor Red
    Write-Host "Open a plain Administrator PowerShell instead and run this script again (it sets up x64 itself)." -ForegroundColor Red
    exit 1
}

# 3. Build both programs. /Zi makes the .pdb files that hold the function names.
Write-Host "Building slowapp.exe and waitwhy.exe..." -ForegroundColor Cyan
cl /nologo /W4 /WX /EHsc /Od /Zi /std:c++17 slowapp.cpp /Fe:slowapp.exe | Out-Host
if ($LASTEXITCODE -ne 0) { throw "slowapp.cpp did not compile" }
cl /nologo /W4 /WX /EHsc /O2 /Zi /std:c++17 waitwhy.cpp /Fe:waitwhy.exe | Out-Host
if ($LASTEXITCODE -ne 0) { throw "waitwhy.cpp did not compile" }

# Microsoft's redistributable dbghelp.dll and symsrv.dll, when the Windows SDK has them, let
# "waitwhy --symbols ms" download Windows' own symbols (W27). Windows' copy in System32 cannot.
$debuggers = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64'
foreach ($dll in 'dbghelp.dll', 'symsrv.dll') {
    $source = Join-Path $debuggers $dll
    if (Test-Path $source) { Copy-Item $source -Destination $PSScriptRoot -Force }
}

# 4. Run slowapp in its own window, then point waitwhy at it.
function Invoke-Case {
    param([string]$Title, [string[]]$SlowappArgs)

    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Yellow
    $app = Start-Process -FilePath (Join-Path $PSScriptRoot 'slowapp.exe') `
        -ArgumentList (@('--seconds', '20') + $SlowappArgs) -PassThru
    Write-Host "slowapp started (PID $($app.Id)) in a new window. Letting it warm up..."
    Start-Sleep -Seconds 3
    & (Join-Path $PSScriptRoot 'waitwhy.exe') --pid $app.Id --seconds 8
    if (-not $app.HasExited) { Stop-Process -Id $app.Id -ErrorAction SilentlyContinue }
}

Invoke-Case -Title 'BUGGY slowapp: disk write happens while holding the lock' -SlowappArgs @()
Read-Host "`nPress Enter to run the FIXED version"
Invoke-Case -Title 'FIXED slowapp: disk write moved outside the lock' -SlowappArgs @('--fixed')
