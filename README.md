# Device Info API

A .NET 8 Web API application that gathers Windows device information and exposes it via local endpoints.

## Features

- **Device Information Gathering**: Collects device name, ID, IP address, and MAC address
- **Local API Endpoints**: Exposes device information via REST API
- **Windows Service Ready**: Can be configured to run as a Windows service for auto-startup
- **Admin-Only Access**: Designed to be restricted to administrative users (implementation pending)

## API Endpoints

- `GET /` - Health check and API status
- `GET /api/device-info` - Get current device information (synchronous)
- `GET /api/device-info/async` - Get current device information (asynchronous)
- `GET /api/health` - Health check endpoint
- `GET /swagger` - API documentation (development only)

## Test Client

A test client application is included to demonstrate how to consume the API:

- **Location**: `test-client/` directory
- **Purpose**: Test and validate API endpoints
- **Usage**: Run `run-test-client.bat` or `dotnet run` from the test-client directory

## Device Information Collected

- **Device Name**: Computer system name from WMI
- **Device ID**: Unique identifier (UUID from BIOS or generated hash)
- **IP Address**: Primary IPv4 address (non-loopback)
- **MAC Address**: Physical address of the primary network interface
- **Last Updated**: Timestamp of when the information was gathered

## Prerequisites

- .NET 8.0 SDK or Runtime
- Windows operating system
- Administrative privileges (for some device information)

## Building the Application

### Development Build
```bash
dotnet build
```

### Production Build (Self-contained)
```bash
dotnet publish -c Release -r win-x64 --self-contained true
```

## Running the Application

### Development Mode
```bash
dotnet run
```

### Production Mode
```bash
dotnet run --environment Production
```

The API will be available at `http://localhost:5000`

## Windows Service Setup (Future Implementation)

The application is designed to be easily converted to a Windows service for auto-startup. This will be implemented in a future version with:

- Windows Service wrapper
- Auto-startup configuration
- Administrative access restrictions
- Service management commands

## Configuration

The application can be configured via `appsettings.json`:

- **Port**: Configure the listening port in the Kestrel section
- **Logging**: Adjust log levels as needed
- **CORS**: Modify allowed origins for local access

## Dependencies

- **Microsoft.AspNetCore.OpenApi**: OpenAPI/Swagger support
- **Swashbuckle.AspNetCore**: Swagger UI for API documentation
- **System.Management**: Windows Management Instrumentation (WMI) access
- **System.Net.NetworkInformation**: Network interface information

## Security Considerations

- The API is designed to run locally only
- CORS is configured to allow local access
- Administrative privileges may be required for some device information
- Future versions will implement proper authentication and authorization

## Troubleshooting

### Common Issues

1. **Access Denied**: Ensure the application runs with appropriate privileges
2. **Port Already in Use**: Change the port in `appsettings.json`
3. **WMI Access**: Verify Windows Management Instrumentation service is running

### Logs

Check the console output for detailed information about the application startup and any errors.

## Development

### Project Structure

```
DeviceInfoAPI/
├── DeviceInfoAPI/              # Main API project
│   ├── Models/
│   │   └── DeviceInfo.cs      # Device information model
│   ├── Services/
│   │   ├── IDeviceInfoService.cs  # Service interface
│   │   └── DeviceInfoService.cs   # Service implementation
│   ├── Program.cs              # Application entry point
│   ├── appsettings.json       # Configuration
│   └── DeviceInfoAPI.csproj   # Main project file
├── test-client/                # Test client application
│   ├── TestClient.cs          # Test client implementation
│   ├── TestClient.csproj      # Test client project file
│   └── run-test-client.bat    # Test client runner
├── scripts/                    # Utility scripts
│   └── install-windows-service.ps1  # Future Windows service installer
├── DeviceInfoAPI.sln          # Solution file
├── build-and-run.bat          # Build and run script
├── publish.bat                 # Publish script
└── README.md                  # This file
```

### Adding New Features

1. Create models in the `Models/` directory
2. Define interfaces in the `Services/` directory
3. Implement services following the existing pattern
4. Add endpoints in `Program.cs`
5. Update configuration as needed

## License

This project is provided as-is for educational and development purposes.
