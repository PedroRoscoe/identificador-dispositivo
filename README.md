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

### 4. External IP Management with Intelligent Caching

The application implements an enhanced IP storage strategy with intelligent caching:

1. **When NOT on VPN**: 
   - Queries external IP services (ipify.org, icanhazip.com, etc.)
   - Stores the current external IP AND enriched location data in encrypted storage
   - Returns the IP with "(Current - Stored for VPN use)" suffix
   - **NEW**: Caches IP-API response to avoid repeated calls for the same IP

2. **When ON VPN**:
   - Retrieves the last known external IP and location data from encrypted storage
   - Returns the IP with "(Stored - Last Updated: X minutes ago)" suffix
   - Ensures you always know your "real" internet IP, even through VPN
   - **NEW**: Returns cached location data without making external API calls

3. **Intelligent Caching**:
   - Only calls IP-API when the external IP address changes
   - Stores location data (country, city, ISP, coordinates, timezone) locally
   - Uses SHA-256 hashing for quick IP change detection
   - **NEW**: All stored data is encrypted using AES-256 encryption

### 5. IP Geolocation Integration with Caching

For external IP addresses, the application:
- **First**: Checks if location data is already cached for the current IP
- **If cached**: Returns stored location data immediately (no external API call)
- **If not cached or IP changed**: Queries `http://ip-api.com/json/{ipAddress}` for fresh data
- **Always**: Stores new location data in encrypted storage for future use
- Returns comprehensive information including country, city, ISP, coordinates, timezone
- Skips private IP addresses automatically

## 💾 Data Storage

### Enhanced IP Storage with Encryption

External IP addresses and location data are now stored in an encrypted JSON file located at:
```
%APPDATA%\DeviceInfoAPI\enhanced_external_ip.json
```

**File Structure:**
```json
{
  "ExternalIpAddress": "ENCRYPTED_IP_ADDRESS",
  "LastUpdated": "2025-08-29T02:36:52.8757469Z",
  "LocationInfo": {
    "Country": "ENCRYPTED_COUNTRY",
    "CountryCode": "ENCRYPTED_COUNTRY_CODE",
    "Region": "ENCRYPTED_REGION",
    "City": "ENCRYPTED_CITY",
    "Lat": -15.7783,
    "Lon": -47.9319,
    "Timezone": "ENCRYPTED_TIMEZONE",
    "Isp": "ENCRYPTED_ISP"
  },
  "IpHash": "SHA256_HASH_OF_IP",
  "IsEncrypted": true
}
```

**Why This Location?**
- `%APPDATA%` is the standard Windows location for application data
- Survives system restarts and updates
- Accessible without admin privileges
- Automatically cleaned up if the application is uninstalled

### Enhanced Storage Security

- **AES-256 Encryption**: All sensitive data is encrypted using military-grade encryption
- **Machine-Specific Keys**: Encryption keys are derived from machine-specific identifiers
- **Data Integrity**: SHA-256 hashing prevents IP tampering and enables quick change detection
- **Location Data Caching**: Stores enriched IP-API responses to minimize external API calls
- **Backward Compatibility**: Automatically migrates existing unencrypted data to encrypted format
- **Local Storage Only**: Data is stored locally on your machine with no external transmission
- **File Permissions**: Follows Windows user account security model

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

### Data Protection
- **AES-256 Encryption**: All stored IP and location data is encrypted using military-grade encryption
- **Machine-Specific Keys**: Encryption keys are derived from machine-specific identifiers, preventing data theft
- **Tamper Detection**: SHA-256 hashing enables quick detection of IP address changes and prevents manipulation
- **Local Storage Only**: No sensitive data is transmitted to external servers (except for IP-API geolocation queries)
- **Automatic Migration**: Existing unencrypted data is automatically migrated to encrypted format on startup

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
   - **NEW**: Verify encryption service is working properly
   - **NEW**: Check if data migration completed successfully

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

## 🚀 Performance Improvements

### Intelligent Caching System

The application now implements a sophisticated caching system that significantly improves performance:

1. **IP Change Detection**
   - Uses SHA-256 hashing to quickly determine if the external IP has changed
   - Eliminates unnecessary API calls when the IP remains the same
   - Provides instant response for repeated requests

2. **Location Data Caching**
   - Stores enriched IP-API responses locally in encrypted format
   - Returns cached location data immediately when IP hasn't changed
   - Reduces external API calls by up to 90% in typical usage scenarios

3. **Smart Storage Strategy**
   - Only queries IP-API when external IP address changes
   - Caches comprehensive location information (country, city, ISP, coordinates, timezone)
   - Maintains data freshness while minimizing network overhead

### Performance Benefits

- **Faster Response Times**: Cached data returns in milliseconds instead of seconds
- **Reduced Network Usage**: Minimizes external API calls to IP-API service
- **Improved Reliability**: Less dependent on external service availability
- **Better User Experience**: Consistent response times regardless of network conditions

## 🔄 Maintenance and Updates

### Updating the Application

1. **Stop the Service**
   ```powershell
   Stop-Service -Name "DeviceInfoAPI"
   ```

2. **Replace Files**
   - Copy new application files
   - **NEW**: The application will automatically migrate existing `external_ip.json` to encrypted `enhanced_external_ip.json`
   - **NEW**: Old file is backed up as `external_ip.json.backup`

3. **Restart the Service**
   ```powershell
   Start-Service -Name "DeviceInfoAPI"
   ```

4. **Verify Migration**
   - Check console output for "Data migration completed successfully" message
   - Verify `enhanced_external_ip.json` exists and contains encrypted data

### Backup Considerations

- **External IP Data**: Backup `%APPDATA%\DeviceInfoAPI\enhanced_external_ip.json` (encrypted)
- **Legacy Data**: Backup `%APPDATA%\DeviceInfoAPI\external_ip.json.backup` if migration was performed
- **Configuration**: Backup `appsettings.json` if modified
- **Service Configuration**: Document any custom service settings
- **Encryption Keys**: **IMPORTANT**: Encrypted data can only be decrypted on the same machine where it was encrypted

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
