@echo off
echo Building Device Info API...
dotnet build

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build successful! Starting the application...
echo.
echo The API will be available at: http://localhost:5000
echo Swagger UI will be available at: http://localhost:5000/swagger
echo.
echo Press Ctrl+C to stop the application
echo.

dotnet run --project DeviceInfoAPI
