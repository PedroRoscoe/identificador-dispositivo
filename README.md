# Device Info API

A .NET 8/9 Web API application that gathers comprehensive device and network information from Windows systems, with intelligent VPN detection and IP geolocation capabilities.

## 🎯 What This Application Does

This application automatically detects and reports detailed information about your Windows device and network configuration, including:

- **Device Information**: Computer name and unique device ID
- **Network Interfaces**: All active network adapters with IP addresses, MAC addresses, and connection status
- **VPN Detection**: Intelligent detection of VPN connections using network topology analysis
- **External IP Management**: Smart storage and retrieval of external IP addresses, even when connected to VPN
- **IP Geolocation**: Rich location and ISP information using IP-API integration

## 🏗️ Architecture Overview

The application follows Clean Architecture principles with a feature-first organization:

```
lib/
├── core/                          # Shared/common code
├── features/                      # All app features
│   └── device-info/              # Main device info feature
│       ├── data/                  # Data layer (storage, external APIs)
│       ├── domain/                # Business logic and entities
│       └── presentation/          # API endpoints and controllers
└── main.dart                      # Entry point
```

### Key Components

1. **DeviceInfoService**: Core business logic for gathering device and network information
2. **IpStorageService**: Manages persistent storage of external IP addresses
3. **IpApiService**: Integrates with IP-API for geolocation data
4. **Network Analysis**: Advanced algorithms for VPN detection and network classification

## 🔍 How It Works

### 1. Device Information Gathering

The application uses Windows Management Instrumentation (WMI) to collect:
- Computer system name from `Win32_ComputerSystem`
- Device UUID from `Win32_ComputerSystemProduct`

### 2. Network Interface Analysis

For each active network interface (`OperationalStatus.Up`), the application:

1. **Collects Basic Info**: Name, description, type, status, MAC address
2. **IP Address Analysis**: Extracts IPv4/IPv6 addresses, subnet masks, gateways, DNS servers
3. **IP Classification**: Categorizes addresses as Internal, External, VPN, Loopback, or Link-Local
4. **VPN Detection**: Uses sophisticated heuristics to identify VPN connections

### 3. VPN Detection Algorithm

The application uses multiple strategies to detect VPN connections:

- **Subnet Analysis**: Compares local IP and gateway addresses to determine if they're in the same network
- **Private Range Comparison**: Identifies when local and gateway are in different private IP ranges
- **Network Topology**: Analyzes routing patterns to distinguish local networks from VPN tunnels

### 4. External IP Management

The application implements a smart IP storage strategy:

1. **When NOT on VPN**: 
   - Queries external IP services (ipify.org, icanhazip.com, etc.)
   - Stores the current external IP in local storage
   - Returns the IP with "(Current - Stored for VPN use)" suffix

2. **When ON VPN**:
   - Retrieves the last known external IP from storage
   - Returns the IP with "(Stored - Last Updated: X minutes ago)" suffix
   - Ensures you always know your "real" internet IP, even through VPN

### 5. IP Geolocation Integration

For external IP addresses, the application:
- Queries `http://ip-api.com/json/{ipAddress}` for location data
- Returns comprehensive information including country, city, ISP, coordinates, timezone
- Skips private IP addresses automatically

## 💾 Data Storage

### External IP Storage Location

External IP addresses are stored in a JSON file located at:
```
%APPDATA%\DeviceInfoAPI\external_ip.json
```

**File Structure:**
```json
{
  "ExternalIpAddress": "45.184.70.195",
  "LastUpdated": "2025-08-29T02:36:52.8757469Z"
}
```

**Why This Location?**
- `%APPDATA%` is the standard Windows location for application data
- Survives system restarts and updates
- Accessible without admin privileges
- Automatically cleaned up if the application is uninstalled

### Storage Security

- Data is stored locally on your machine
- No external services receive your IP address (except IP-API for geolocation)
- File permissions follow Windows user account security

## 🚀 Installation and Setup

### Prerequisites

- Windows 10/11
- .NET 8.0 or 9.0 Runtime
- Internet connection for IP geolocation features

### Method 1: Manual Installation

1. **Download and Extract**
   ```bash
   # Clone or download the project
   git clone <repository-url>
   cd acr-identificador-dispositivo
   ```

2. **Build the Application**
   ```bash
   dotnet build
   ```

3. **Publish for Distribution**
   ```bash
   dotnet publish DeviceInfoAPI/DeviceInfoAPI.csproj -c Release -r win-x64 --self-contained
   ```

4. **Run the Application**
   ```bash
   dotnet run --project DeviceInfoAPI
   ```

### Method 2: Windows Service Installation (Recommended for Production)

1. **Build and Publish**
   ```bash
   dotnet publish DeviceInfoAPI/DeviceInfoAPI.csproj -c Release -r win-x64 --self-contained
   ```

2. **Install as Windows Service**
   ```powershell
   # Run PowerShell as Administrator
   .\scripts\install-windows-service.ps1
   ```

3. **Configure Auto-Start**
   ```powershell
   # The service will automatically start with Windows
   Get-Service -Name "DeviceInfoAPI" | Set-Service -StartupType Automatic
   ```

### Method 3: Task Scheduler (Alternative to Windows Service)

1. **Create Startup Script**
   Create a batch file `start-device-info-api.bat`:
   ```batch
   @echo off
   cd /d "C:\path\to\your\published\app"
   "DeviceInfoAPI.exe"
   ```

2. **Configure Task Scheduler**
   - Open Task Scheduler (taskschd.msc)
   - Create Basic Task
   - Name: "Device Info API Startup"
   - Trigger: At system startup
   - Action: Start a program
   - Program: `C:\path\to\start-device-info-api.bat`
   - Run with highest privileges: Yes

## 🔧 Configuration

### Port Configuration

The application runs on `http://localhost:5000` by default. To change this:

1. **Edit `appsettings.json`:**
   ```json
   {
     "Kestrel": {
       "Endpoints": {
         "Http": {
           "Url": "http://localhost:YOUR_PORT"
         }
       }
     }
   }
   ```

2. **Environment Variable:**
   ```bash
   set ASPNETCORE_URLS=http://localhost:YOUR_PORT
   ```

### CORS Configuration

The application allows local access by default. To modify CORS settings, edit `Program.cs`:

```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocal", policy =>
    {
        // Modify these origins as needed
        policy.WithOrigins("http://localhost:*", "https://localhost:*")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});
```

## 📡 API Endpoints

### 1. Device Information
```
GET /api/device-info
```
Returns comprehensive device and network information.

**Response Example:**
```json
{
  "deviceName": "PEDRO",
  "deviceId": "EA9FA101-2D64-F11A-A42A-047C16850A67",
  "externalIpAddress": "45.184.70.195 (Stored - Last Updated: 45 minutes ago)",
  "ipLocationInfo": {
    "country": "Brazil",
    "countryCode": "BR",
    "region": "DF",
    "city": "Brasília",
    "lat": -15.7783,
    "lon": -47.9319,
    "timezone": "America/Sao_Paulo",
    "isp": "CANAA TELECOMUNICAÇÕES LTDA - ME"
  },
  "networkInterfaces": [...],
  "lastUpdated": "2025-08-29T03:07:03.7029717Z"
}
```

### 2. Health Check
```
GET /api/health
```
Returns application health status.

### 3. IP-API Test (Debug)
```
GET /api/test-ip-api/{ip}
```
Tests IP-API integration for a specific IP address.

## 🧪 Testing

### Test Client

A console test client is included to verify API functionality:

```bash
cd test-client
dotnet run
```

### Manual Testing

1. **Start the Application**
   ```bash
   dotnet run --project DeviceInfoAPI
   ```

2. **Test API Endpoints**
   ```bash
   # Using PowerShell
   Invoke-WebRequest -Uri "http://localhost:5000/api/device-info" -UseBasicParsing
   
   # Using curl (if available)
   curl http://localhost:5000/api/device-info
   
   # Using browser
   http://localhost:5000/api/device-info
   ```

3. **Check Console Output**
   The application provides detailed logging for debugging VPN detection and IP-API calls.

## 🔒 Security Considerations

### Network Access
- The application only listens on localhost by default
- No external network access is required (except for IP geolocation)
- CORS is configured for local access only

### Data Privacy
- Device information is collected locally
- External IP addresses are only sent to IP-API for geolocation
- No data is stored on external servers

### Admin Requirements
- Some WMI queries may require elevated privileges
- Windows service installation requires administrator access
- The application can run with standard user privileges for basic functionality

## 🐛 Troubleshooting

### Common Issues

1. **Application Won't Start**
   - Check if port 5000 is already in use
   - Verify .NET runtime is installed
   - Check Windows Event Viewer for errors

2. **VPN Detection Issues**
   - Ensure network interfaces are properly configured
   - Check console output for VPN detection logs
   - Verify network adapter properties

3. **IP-API Not Working**
   - Check internet connectivity
   - Verify firewall settings
   - Check console output for API call logs

4. **External IP Not Stored**
   - Check `%APPDATA%\DeviceInfoAPI\` folder exists
   - Verify file permissions
   - Check console output for storage logs

### Debug Mode

Enable detailed logging by running in development mode:

```bash
set ASPNETCORE_ENVIRONMENT=Development
dotnet run --project DeviceInfoAPI
```

### Log Files

The application logs to:
- Console output (when running interactively)
- Windows Event Log (when running as service)
- Application data folder for IP storage

## 🔄 Maintenance and Updates

### Updating the Application

1. **Stop the Service**
   ```powershell
   Stop-Service -Name "DeviceInfoAPI"
   ```

2. **Replace Files**
   - Copy new application files
   - Preserve `external_ip.json` if you want to keep stored IPs

3. **Restart the Service**
   ```powershell
   Start-Service -Name "DeviceInfoAPI"
   ```

### Backup Considerations

- **External IP Data**: Backup `%APPDATA%\DeviceInfoAPI\external_ip.json`
- **Configuration**: Backup `appsettings.json` if modified
- **Service Configuration**: Document any custom service settings

## 📚 For Java Developers

### Key .NET Concepts

1. **Dependency Injection**: Similar to Spring's IoC container
   ```csharp
   // Registration (like @Service in Spring)
   builder.Services.AddSingleton<IDeviceInfoService, DeviceInfoService>();
   
   // Injection (like @Autowired in Spring)
   public DeviceInfoService(IDeviceInfoService deviceInfoService)
   ```

2. **Async/Await**: Similar to Java's CompletableFuture
   ```csharp
   // C# async/await
   public async Task<IpApiResponse?> GetIpInfoAsync(string ipAddress)
   {
       var response = await _httpClient.GetStringAsync(url);
       return JsonSerializer.Deserialize<IpApiResponse>(response);
   }
   
   // Java equivalent
   public CompletableFuture<IpApiResponse> getIpInfoAsync(String ipAddress) {
       return httpClient.getAsync(url)
           .thenApply(response -> jsonMapper.readValue(response, IpApiResponse.class));
   }
   ```

3. **LINQ**: Similar to Java Streams
   ```csharp
   // C# LINQ
   var activeInterfaces = interfaces.Where(nic => nic.OperationalStatus == OperationalStatus.Up);
   
   // Java Streams
   var activeInterfaces = interfaces.stream()
       .filter(nic -> nic.getOperationalStatus() == OperationalStatus.UP)
       .collect(Collectors.toList());
   ```

4. **Properties**: Similar to Java getters/setters
   ```csharp
   // C# properties
   public string DeviceName { get; set; } = string.Empty;
   
   // Java equivalent
   private String deviceName = "";
   public String getDeviceName() { return deviceName; }
   public void setDeviceName(String deviceName) { this.deviceName = deviceName; }
   ```

### Project Structure Comparison

| .NET | Java | Purpose |
|------|------|---------|
| `Program.cs` | `Main.java` | Application entry point |
| `Services/` | `Services/` | Business logic layer |
| `Models/` | `Entities/` | Data transfer objects |
| `Interfaces/` | `Interfaces/` | Contract definitions |
| `appsettings.json` | `application.properties` | Configuration |
| `*.csproj` | `pom.xml` | Project dependencies |

## 🤝 Contributing

### Development Setup

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd acr-identificador-dispositivo
   ```

2. **Install Dependencies**
   ```bash
   dotnet restore
   ```

3. **Run Tests**
   ```bash
   dotnet test
   ```

4. **Build and Run**
   ```bash
   dotnet build
   dotnet run --project DeviceInfoAPI
   ```

### Code Style

- Follow C# coding conventions
- Use meaningful variable and method names
- Add XML documentation for public APIs
- Include unit tests for business logic

## 📄 License

[Add your license information here]

## 🆘 Support

For issues and questions:
- Check the troubleshooting section
- Review console output and logs
- Check Windows Event Viewer
- Create an issue in the repository

---

**Note**: This application is designed for Windows environments and uses Windows-specific APIs for device information gathering. Cross-platform support would require significant modifications to use platform-agnostic alternatives.
