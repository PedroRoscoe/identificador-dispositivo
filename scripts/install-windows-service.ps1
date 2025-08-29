# Windows Service Installation Script for Device Info API
# This script will be used in future versions to install the application as a Windows service
# Requires administrative privileges to run

param(
    [string]$ServiceName = "DeviceInfoAPI",
    [string]$DisplayName = "Device Info API Service",
    [string]$Description = "Provides device information via local API endpoints",
    [string]$ExecutablePath = "C:\DeviceInfoAPI\DeviceInfoAPI.exe"
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires administrative privileges. Please run as Administrator."
    exit 1
}

Write-Host "Device Info API Windows Service Installer" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""

# TODO: Implement Windows service installation
# This will include:
# 1. Creating the Windows service
# 2. Setting startup type to Automatic
# 3. Configuring service account and permissions
# 4. Setting up logging and monitoring

Write-Host "Windows service installation will be implemented in a future version." -ForegroundColor Yellow
Write-Host "For now, you can run the application manually or use the batch files provided." -ForegroundColor Yellow
Write-Host ""

Write-Host "To run the application manually:" -ForegroundColor Cyan
Write-Host "1. Open Command Prompt or PowerShell" -ForegroundColor White
Write-Host "2. Navigate to the application directory" -ForegroundColor White
Write-Host "3. Run: dotnet run" -ForegroundColor White
Write-Host ""

Write-Host "Or use the provided batch files:" -ForegroundColor Cyan
Write-Host "- build-and-run.bat (for development)" -ForegroundColor White
Write-Host "- publish.bat (for production deployment)" -ForegroundColor White
Write-Host ""

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
