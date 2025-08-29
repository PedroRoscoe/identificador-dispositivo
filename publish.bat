@echo off
echo Publishing Device Info API as self-contained executable...

dotnet publish DeviceInfoAPI\DeviceInfoAPI.csproj -c Release -r win-x64 --self-contained true -o ./publish

if %ERRORLEVEL% NEQ 0 (
    echo Publish failed!
    pause
    exit /b 1
)

echo.
echo Publish successful! Files are in the ./publish directory
echo.
echo To run the published application:
echo cd publish
echo DeviceInfoAPI.exe
echo.
pause
