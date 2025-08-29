@echo off
echo Building Test Client...
dotnet build

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build successful! Running test client...
echo Make sure the Device Info API is running on http://localhost:5000
echo.

dotnet run
