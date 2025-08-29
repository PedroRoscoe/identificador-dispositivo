// ============================================================================
// DeviceInfoService.cs - Core business logic for gathering device and network information
// ============================================================================
// This service is responsible for:
// 1. Collecting device information using Windows Management Instrumentation (WMI)
// 2. Analyzing network interfaces and their properties
// 3. Detecting VPN connections using sophisticated network topology analysis
// 4. Managing external IP address storage and retrieval
// 5. Integrating with IP-API for geolocation data
//
// For Java developers: This is similar to a Service class in Spring Boot
// that handles business logic and coordinates between different components.
// ============================================================================

using DeviceInfoAPI.Models;
using System.Management;  // Windows Management Instrumentation (WMI) - Windows-specific API
using System.Net;         // Network utilities like IPAddress, Dns, HttpClient
using SystemNetNetworkInterface = System.Net.NetworkInformation.NetworkInterface;  // Alias to avoid naming conflicts
using System.Net.NetworkInformation;  // Network interface information
using System.Net.Sockets; // Socket operations
using System.Text.Json;   // JSON serialization/deserialization
using System.Text.RegularExpressions; // Regular expression support
using System.Diagnostics; // Process and diagnostic information

namespace DeviceInfoAPI.Services;

/// <summary>
/// Main service for gathering comprehensive device and network information.
/// 
/// This service implements the core business logic for:
/// - Device identification using Windows WMI
/// - Network interface analysis and classification
/// - VPN detection using network topology analysis
/// - External IP address management with persistent storage
/// - IP geolocation integration
/// 
/// For Java developers: This class is similar to a @Service annotated class in Spring Boot.
/// It uses dependency injection to receive its dependencies (like @Autowired in Spring).
/// </summary>
public class DeviceInfoService : IDeviceInfoService
{
    // ============================================================================
    // DEPENDENCY INJECTION - Similar to @Autowired in Spring Boot
    // ============================================================================
    
    /// <summary>
    /// HTTP client for making external API calls to IP geolocation services.
    /// Configured with timeout and used for querying external IP services.
    /// </summary>
    private readonly HttpClient _httpClient;
    
    /// <summary>
    /// Service for persisting and retrieving external IP addresses with enhanced features.
    /// This allows us to remember the "real" internet IP even when connected to VPN,
    /// and cache location data to avoid unnecessary API calls.
    /// </summary>
    private readonly IEnhancedIpStorageService _enhancedIpStorageService;
    
    /// <summary>
    /// Service for querying IP-API to get geolocation and ISP information.
    /// Provides country, city, coordinates, timezone, and ISP details.
    /// </summary>
    private readonly IIpApiService _ipApiService;

    /// <summary>
    /// Service for encrypting and decrypting sensitive data.
    /// Used to secure stored IP and location information.
    /// </summary>
    private readonly IEncryptionService _encryptionService;

    /// <summary>
    /// Constructor for DeviceInfoService.
    /// 
    /// In .NET, this constructor is automatically called by the dependency injection container
    /// when creating an instance of this service. This is similar to how Spring Boot
    /// automatically creates and injects dependencies in Java.
    /// 
    /// For Java developers: This is equivalent to:
    /// @Autowired
    /// public DeviceInfoService(IEnhancedIpStorageService enhancedIpStorageService, IIpApiService ipApiService)
    /// </summary>
    /// <param name="enhancedIpStorageService">Service for managing enhanced external IP storage</param>
    /// <param name="ipApiService">Service for IP geolocation queries</param>
    /// <param name="encryptionService">Service for encrypting and decrypting sensitive data</param>
    public DeviceInfoService(IEnhancedIpStorageService enhancedIpStorageService, IIpApiService ipApiService, IEncryptionService encryptionService)
    {
        // ============================================================================
        // HTTP CLIENT INITIALIZATION
        // ============================================================================
        // Create a new HttpClient instance with a 10-second timeout.
        // This is used for querying external IP services like ipify.org, icanhazip.com, etc.
        // 
        // Note: In production applications, you might want to use HttpClientFactory
        // or a singleton HttpClient to avoid socket exhaustion issues.
        // ============================================================================
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)  // 10 second timeout for external API calls
        };
        
        // ============================================================================
        // DEPENDENCY INJECTION - Store injected services
        // ============================================================================
        // These services were injected by the DI container and are now stored
        // as private readonly fields for use throughout this class.
        // ============================================================================
        _enhancedIpStorageService = enhancedIpStorageService;  // Service for enhanced IP storage with caching
        _ipApiService = ipApiService;                          // Service for IP geolocation queries
        _encryptionService = encryptionService;                // Service for encrypting and decrypting data
    }

    /// <summary>
    /// Asynchronous version of GetDeviceInfo that wraps the synchronous method in a Task.
    /// 
    /// For Java developers: This is similar to wrapping a synchronous method in
    /// CompletableFuture.supplyAsync() in Java.
    /// </summary>
    /// <returns>A Task containing the DeviceInfo object</returns>
    public async Task<DeviceInfo> GetDeviceInfoAsync()
    {
        // ============================================================================
        // ASYNC WRAPPER - Converting synchronous to asynchronous
        // ============================================================================
        // Task.Run() runs the synchronous GetDeviceInfo() method on a background thread.
        // This prevents blocking the main thread while gathering device information.
        // 
        // In Java, this would be equivalent to:
        // return CompletableFuture.supplyAsync(() -> getDeviceInfo());
        // ============================================================================
        return await Task.Run(() => GetDeviceInfo());
    }

    /// <summary>
    /// Main method for gathering comprehensive device and network information.
    /// 
    /// This method orchestrates the entire process of collecting device information:
    /// 1. Gets the external IP address (with VPN-aware logic)
    /// 2. Retrieves IP geolocation information
    /// 3. Collects device name and ID using Windows WMI
    /// 4. Analyzes all network interfaces
    /// 5. Returns a complete DeviceInfo object
    /// 
    /// For Java developers: This is the main business logic method, similar to
    /// a service method in Spring Boot that coordinates multiple operations.
    /// </summary>
    /// <returns>A complete DeviceInfo object with all device and network information</returns>
    public DeviceInfo GetDeviceInfo()
    {
        Console.WriteLine("GetDeviceInfo: Starting...");
        
        // ============================================================================
        // STEP 1: GET EXTERNAL IP ADDRESS
        // ============================================================================
        // This method handles VPN detection and returns either:
        // - Current external IP (when not on VPN) with "(Current - Stored for VPN use)" suffix
        // - Stored external IP (when on VPN) with "(Stored - Last Updated: X minutes ago)" suffix
        // ============================================================================
        var externalIp = GetExternalIpAddress();
        Console.WriteLine($"GetDeviceInfo: Got external IP: '{externalIp}'");
        
        Console.WriteLine("GetDeviceInfo: About to get IP location info...");
        
        // ============================================================================
        // DEBUGGING: DIRECT IP-API TEST
        // ============================================================================
        // This is a temporary debugging section to test if the IP-API service is working.
        // It directly queries the IP-API service with a hardcoded IP to verify functionality.
        // This should be removed in production code.
        // ============================================================================
        Console.WriteLine("GetDeviceInfo: Testing IP-API service directly...");
        var testIp = "45.184.70.195";
        var testResult = _ipApiService.GetIpInfoAsync(testIp).Result;  // .Result blocks until async operation completes
        Console.WriteLine($"GetDeviceInfo: Direct IP-API test result: {testResult != null}");
        if (testResult != null)
        {
            Console.WriteLine($"GetDeviceInfo: Direct test - Country: {testResult.Country}, City: {testResult.City}");
        }
        
        // ============================================================================
        // STEP 2: GET IP GEOLOCATION INFORMATION
        // ============================================================================
        // Query IP-API to get location, ISP, and other information for the external IP.
        // Note: We use .Result here because this method is synchronous, but GetIpLocationInfo
        // is asynchronous. In production, consider making this method async.
        // ============================================================================
        var ipLocationInfo = GetIpLocationInfo(externalIp).Result; // Use .Result here since we can't make this method async
        Console.WriteLine($"GetDeviceInfo: Got IP location info: {ipLocationInfo != null}");
        
        if (ipLocationInfo != null)
        {
            Console.WriteLine($"GetDeviceInfo: IP location details - Country: {ipLocationInfo.Country}, City: {ipLocationInfo.City}");
        }
        
        // ============================================================================
        // STEP 3: BUILD COMPLETE DEVICE INFO OBJECT
        // ============================================================================
        // Create a DeviceInfo object containing all gathered information.
        // This follows the Builder pattern, setting properties one by one.
        // 
        // For Java developers: This is similar to using a Builder class or
        // setting properties on a POJO (Plain Old Java Object).
        // ============================================================================
        var result = new DeviceInfo
        {
            DeviceName = GetDeviceName(),                    // Get computer name from WMI
            DeviceId = GetDeviceId(),                        // Get unique device identifier
            NetworkInterfaces = GetNetworkInterfaces(),      // Get all network interface details
            ExternalIpAddress = externalIp,                  // External IP with VPN context
            IpLocationInfo = ipLocationInfo,                 // Geolocation and ISP information
            LastUpdated = DateTime.UtcNow                    // Current timestamp in UTC
        };
        
        Console.WriteLine($"GetDeviceInfo: Created DeviceInfo with IpLocationInfo: {result.IpLocationInfo != null}");
        return result;
    }

    /// <summary>
    /// Retrieves the computer system name using Windows Management Instrumentation (WMI).
    /// 
    /// This method queries the Windows WMI database to get the computer name from the
    /// Win32_ComputerSystem class. WMI is a Windows-specific API that provides access
    /// to system information and configuration.
    /// 
    /// For Java developers: This is similar to using JNA (Java Native Access) or
    /// JNI (Java Native Interface) to call Windows system APIs. In .NET, we have
    /// direct access to these APIs through the System.Management namespace.
    /// 
    /// Fallback strategy:
    /// 1. Try to get name from WMI (most accurate)
    /// 2. Fall back to Environment.MachineName if WMI fails
    /// </summary>
    /// <returns>The computer system name, or fallback to environment variable</returns>
    private string GetDeviceName()
    {
        try
        {
            // ============================================================================
            // WMI QUERY - Windows Management Instrumentation
            // ============================================================================
            // WMI is a Windows infrastructure for management data and operations.
            // It allows us to query system information like computer names, hardware
            // details, and configuration settings.
            // 
            // The query "SELECT Name FROM Win32_ComputerSystem" retrieves the computer
            // name from the Win32_ComputerSystem WMI class, which represents the
            // computer system and its properties.
            // ============================================================================
            using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_ComputerSystem");
            
            // ============================================================================
            // ITERATE THROUGH WMI RESULTS
            // ============================================================================
            // WMI queries can return multiple objects, but typically there's only one
            // computer system. We iterate through the results and take the first one.
            // 
            // For Java developers: This is similar to iterating through a ResultSet
            // from a database query.
            // ============================================================================
            foreach (ManagementObject obj in searcher.Get())
            {
                // ============================================================================
                // EXTRACT NAME PROPERTY WITH NULL COALESCING
                // ============================================================================
                // obj["Name"] gets the "Name" property from the WMI object.
                // ?.ToString() safely converts to string if the property exists.
                // ?? Environment.MachineName provides a fallback if the property is null.
                // 
                // This is equivalent to Java's Optional.orElse() pattern:
                // Optional.ofNullable(obj.get("Name")).map(Object::toString).orElse(Environment.getProperty("COMPUTERNAME"))
                // ============================================================================
                return obj["Name"]?.ToString() ?? Environment.MachineName;
            }
        }
        catch (Exception)
        {
            // ============================================================================
            // EXCEPTION HANDLING - Graceful degradation
            // ============================================================================
            // If WMI fails for any reason (permissions, service not running, etc.),
            // we silently catch the exception and fall back to the environment variable.
            // 
            // In production, you might want to log this exception for debugging.
            // ============================================================================
            // Fallback to environment variable
        }
        
        // ============================================================================
        // FALLBACK - Environment variable
        // ============================================================================
        // Environment.MachineName is a .NET property that gets the computer name
        // from the COMPUTERNAME environment variable. This is a reliable fallback
        // that doesn't require special permissions or WMI access.
        // ============================================================================
        return Environment.MachineName;
    }

    /// <summary>
    /// Retrieves a unique device identifier using Windows Management Instrumentation (WMI).
    /// 
    /// This method attempts to get the BIOS/UEFI UUID from the Win32_ComputerSystemProduct
    /// WMI class, which provides a hardware-based unique identifier that persists across
    /// operating system installations and hardware changes.
    /// 
    /// For Java developers: This is similar to getting hardware identifiers like
    /// MAC addresses or processor IDs in Java, but WMI provides more reliable
    /// hardware information on Windows systems.
    /// 
    /// Fallback strategy:
    /// 1. Try to get UUID from WMI (hardware-based, most reliable)
    /// 2. Generate a hash from machine name if WMI fails
    /// </summary>
    /// <returns>A unique device identifier string</returns>
    private string GetDeviceId()
    {
        try
        {
            // ============================================================================
            // WMI QUERY - Hardware UUID from BIOS/UEFI
            // ============================================================================
            // Win32_ComputerSystemProduct represents the computer system product
            // and contains hardware information like UUID, SKU, and vendor details.
            // 
            // The UUID is typically stored in the BIOS/UEFI firmware and provides
            // a unique identifier for the physical hardware.
            // ============================================================================
            using var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
            
            // ============================================================================
            // ITERATE THROUGH WMI RESULTS
            // ============================================================================
            // Similar to GetDeviceName(), we iterate through the results to find
            // the UUID property. There's typically only one computer system product.
            // ============================================================================
            foreach (ManagementObject obj in searcher.Get())
            {
                var uuid = obj["UUID"]?.ToString();
                
                // ============================================================================
                // VALIDATE UUID - Check if it's not null or empty
                // ============================================================================
                // We only return the UUID if it's a valid, non-empty string.
                // This prevents returning null or empty values that could cause issues.
                // ============================================================================
                if (!string.IsNullOrEmpty(uuid))
                {
                    return uuid;
                }
            }
        }
        catch (Exception)
        {
            // ============================================================================
            // EXCEPTION HANDLING - Graceful degradation
            // ============================================================================
            // If WMI fails, we fall back to generating a hash from the machine name.
            // This ensures we always return a unique identifier, even if hardware
            // information is unavailable.
            // ============================================================================
            // Fallback to machine name hash
        }

        // ============================================================================
        // FALLBACK - Generate hash from machine name
        // ============================================================================
        // If WMI fails or returns no UUID, we generate a unique identifier by:
        // 1. Converting the machine name to UTF-8 bytes
        // 2. Converting to Base64 string
        // 3. Replacing URL-unsafe characters
        // 4. Truncating to a reasonable length
        // 
        // This provides a consistent, unique identifier based on the computer name.
        // 
        // For Java developers: This is similar to:
        // String hash = Base64.getEncoder().encodeToString(machineName.getBytes("UTF-8"))
        //     .replace("/", "_").replace("+", "-").replace("=", "")
        //     .substring(0, Math.min(16, machineName.length()));
        // ============================================================================
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Environment.MachineName))
            .Replace("/", "_")      // Replace URL-unsafe forward slash
            .Replace("+", "-")      // Replace URL-unsafe plus sign
            .Replace("=", "")       // Remove padding equals signs
            .Substring(0, Math.Min(16, Environment.MachineName.Length));  // Limit length to 16 characters
    }

    /// <summary>
    /// Collects information about all active network interfaces on the system.
    /// 
    /// This method analyzes each network interface to determine:
    /// - Interface status and operational state
    /// - IP addresses (both IPv4 and IPv6)
    /// - MAC addresses and interface types
    /// - Network configuration (gateways, DNS servers, subnet masks)
    /// - VPN detection and classification
    /// 
    /// For Java developers: This is similar to using Java's NetworkInterface class
    /// to enumerate network interfaces, but with additional Windows-specific
    /// capabilities through .NET's System.Net.NetworkInformation namespace.
    /// 
    /// The method filters interfaces to only include those that are:
    /// 1. Operationally up (connected and active)
    /// 2. Have valid IP addresses assigned
    /// 3. Are not loopback or link-local only
    /// </summary>
    /// <returns>A list of NetworkInterface objects representing active network adapters</returns>
    private List<Models.NetworkInterface> GetNetworkInterfaces()
    {
        // ============================================================================
        // INITIALIZE RESULT LIST
        // ============================================================================
        // Create an empty list to store network interface information.
        // We'll populate this list as we discover active interfaces.
        // ============================================================================
        var networkInterfaces = new List<Models.NetworkInterface>();
        
        try
        {
            // ============================================================================
            // GET ALL NETWORK INTERFACES
            // ============================================================================
            // SystemNetNetworkInterface.GetAllNetworkInterfaces() returns all network
            // interfaces on the system, including physical adapters, virtual adapters,
            // VPN interfaces, and loopback interfaces.
            // 
            // For Java developers: This is similar to NetworkInterface.getNetworkInterfaces()
            // in Java, but returns a more detailed collection of interface information.
            // ============================================================================
            var interfaces = SystemNetNetworkInterface.GetAllNetworkInterfaces();
            
            // ============================================================================
            // ITERATE THROUGH EACH INTERFACE
            // ============================================================================
            // Process each network interface to extract relevant information.
            // We'll filter out inactive interfaces and those without valid IP addresses.
            // ============================================================================
            foreach (var nic in interfaces)
            {
                // ============================================================================
                // FILTER: ONLY ACTIVE INTERFACES
                // ============================================================================
                // OperationalStatus.Up means the interface is connected and operational.
                // We skip interfaces that are down, disconnected, or in error states.
                // 
                // For Java developers: This is similar to checking if an interface
                // is up and running in Java's NetworkInterface class.
                // ============================================================================
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                // ============================================================================
                // GET NETWORK ADDRESSES FOR THIS INTERFACE
                // ============================================================================
                // This method extracts all IP addresses, subnet masks, gateways,
                // DNS servers, and performs IP classification for the interface.
                // ============================================================================
                var addresses = GetNetworkAddresses(nic);
                
                // ============================================================================
                // FILTER: ONLY INTERFACES WITH VALID IP ADDRESSES
                // ============================================================================
                // We only include interfaces that have at least one valid IP address.
                // This filters out interfaces that might be up but don't have
                // network configuration (like some VPN interfaces).
                // 
                // For Java developers: This is similar to checking if an interface
                // has any InetAddress objects assigned to it.
                // ============================================================================
                if (addresses.Any(addr => IsValidIpAddress(addr.IpAddress)))
                {
                    // ============================================================================
                    // CREATE NETWORK INTERFACE OBJECT
                    // ============================================================================
                    // Build a NetworkInterface object (our custom model) with all the
                    // information we've gathered about this network adapter.
                    // 
                    // For Java developers: This is similar to creating a DTO (Data Transfer Object)
                    // or entity object to represent the network interface data.
                    // ============================================================================
                    var networkInterface = new Models.NetworkInterface
                    {
                        Name = nic.Name,                                    // Interface name (e.g., "Ethernet 3")
                        Description = nic.Description,                      // Human-readable description
                        Type = nic.NetworkInterfaceType.ToString(),         // Interface type (Ethernet, WiFi, etc.)
                        Status = nic.OperationalStatus.ToString(),          // Current status (Up, Down, etc.)
                        MacAddress = FormatMacAddress(nic.GetPhysicalAddress()), // MAC address in readable format
                        IsActive = true,                                    // Mark as active since we filtered for Up status
                        Addresses = addresses.Where(addr => IsValidIpAddress(addr.IpAddress)).ToList() // Filter valid addresses
                    };

                    // ============================================================================
                    // ADD TO RESULT LIST
                    // ============================================================================
                    // Add this interface to our collection of active network interfaces.
                    // ============================================================================
                    networkInterfaces.Add(networkInterface);
                }
            }
        }
        catch (Exception)
        {
            // ============================================================================
            // EXCEPTION HANDLING - Fallback to localhost interface
            // ============================================================================
            // If anything goes wrong while gathering network interface information
            // (permissions, system errors, etc.), we create a fallback interface
            // with localhost information to ensure the API always returns something useful.
            // 
            // For Java developers: This is similar to providing a default response
            // when an operation fails, ensuring the API doesn't crash completely.
            // ============================================================================
            networkInterfaces.Add(new Models.NetworkInterface
            {
                Name = "Localhost",
                Description = "Fallback localhost interface",
                Type = "Loopback",
                Status = "Up",
                MacAddress = "00:00:00:00:00:00",
                IsActive = true,
                Addresses = new List<NetworkAddress>
                {
                    new NetworkAddress
                    {
                        IpAddress = "127.0.0.1",                    // Standard localhost IP
                        AddressFamily = "IPv4",                      // IPv4 address family
                        SubnetMask = "255.0.0.0",                   // Standard localhost subnet mask
                        Gateway = "",                                // No gateway for localhost
                        DnsServers = "",                             // No DNS servers for localhost
                        IpType = IpAddressType.Loopback,             // Mark as loopback address
                        IpTypeDescription = "Loopback address"       // Human-readable description
                    }
                }
            });
        }

        return networkInterfaces;
    }

    private List<NetworkAddress> GetNetworkAddresses(SystemNetNetworkInterface nic)
    {
        var addresses = new List<NetworkAddress>();
        
        try
        {
            var properties = nic.GetIPProperties();
            
            // Get IPv4 addresses
            foreach (var ipv4Address in properties.UnicastAddresses)
            {
                if (ipv4Address.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    var address = new NetworkAddress
                    {
                        IpAddress = ipv4Address.Address.ToString(),
                        AddressFamily = "IPv4",
                        SubnetMask = ipv4Address.IPv4Mask?.ToString() ?? "",
                        Gateway = GetGateway(properties.GatewayAddresses),
                        DnsServers = GetDnsServers(properties.DnsAddresses),
                        IpType = ClassifyIpAddress(ipv4Address.Address),
                        IpTypeDescription = GetIpTypeDescription(ClassifyIpAddress(ipv4Address.Address)),
                        IsVpnGateway = IsVpnGateway(ipv4Address.Address, properties.GatewayAddresses)
                    };
                    
                    addresses.Add(address);
                }
            }

            // Get IPv6 addresses
            foreach (var ipv6Address in properties.UnicastAddresses)
            {
                if (ipv6Address.Address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    var address = new NetworkAddress
                    {
                        IpAddress = ipv6Address.Address.ToString(),
                        AddressFamily = "IPv6",
                        SubnetMask = ipv6Address.PrefixLength.ToString(),
                        Gateway = GetGateway(properties.GatewayAddresses),
                        DnsServers = GetDnsServers(properties.DnsAddresses),
                        IpType = ClassifyIpAddress(ipv6Address.Address),
                        IpTypeDescription = GetIpTypeDescription(ClassifyIpAddress(ipv6Address.Address)),
                        IsVpnGateway = IsVpnGateway(ipv6Address.Address, properties.GatewayAddresses)
                    };
                    
                    addresses.Add(address);
                }
            }
        }
        catch (Exception)
        {
            // Handle any errors gracefully
        }

        return addresses;
    }

    /// <summary>
    /// Intelligently determines the external IP address with VPN-aware logic.
    /// 
    /// This is one of the most important methods in the application. It implements
    /// a smart strategy for external IP management that works both when connected
    /// to a VPN and when using a direct internet connection.
    /// 
    /// Strategy Overview:
    /// 1. **VPN Detection**: First determine if we're currently connected to a VPN
    /// 2. **VPN Active**: Return the last known external IP from persistent storage
    /// 3. **No VPN**: Query external services for current IP and store it for future use
    /// 4. **Fallback**: If current IP detection fails, try to return stored IP
    /// 
    /// For Java developers: This method demonstrates several .NET patterns:
    /// - Exception handling with try-catch blocks
    /// - Async/await pattern (though we use .Result for synchronous compatibility)
    /// - String interpolation with $"" syntax
    /// - Null coalescing operators (??)
    /// 
    /// The method ensures that users always know their "real" internet IP address,
    /// even when connected to a VPN that would normally hide it.
    /// </summary>
    /// <returns>
    /// External IP address with context information:
    /// - "IP (Current - Stored for VPN use)" when not on VPN
    /// - "IP (Stored - Last Updated: X minutes ago)" when on VPN
    /// - "No stored external IP available (VPN Active)" if no stored IP exists
    /// - "Unable to determine external IP" if all methods fail
    /// </returns>
    private string GetExternalIpAddress()
    {
        try
        {
            // ============================================================================
            // STEP 1: VPN DETECTION
            // ============================================================================
            // First, we need to determine if we're currently connected to a VPN.
            // This is crucial because VPNs hide your real external IP address.
            // 
            // The IsOnVpn() method uses sophisticated network topology analysis
            // to detect VPN connections by analyzing gateway addresses, subnet masks,
            // and network routing patterns.
            // ============================================================================
            var isOnVpn = IsOnVpn();
            
            if (isOnVpn)
            {
                // ============================================================================
                // SCENARIO: CONNECTED TO VPN
                // ============================================================================
                // When connected to a VPN, external IP services will return the VPN's IP,
                // not your real internet IP address. To solve this, we use a clever approach:
                // 
                // 1. We store the external IP when NOT connected to VPN
                // 2. When VPN is active, we retrieve and return the stored IP
                // 3. This ensures users always know their "real" internet IP
                // 
                // For Java developers: This is similar to using a cache or persistent
                // storage to remember previous values when current detection is unreliable.
                // ============================================================================
                
                // ============================================================================
                // RETRIEVE STORED EXTERNAL IP
                // ============================================================================
                // Get the last known external IP address from enhanced persistent storage.
                // This IP was stored when we were NOT connected to a VPN.
                // 
                // Note: We use .Result here because this method is synchronous.
                // In production, consider making this method async for better performance.
                // ============================================================================
                var storedData = _enhancedIpStorageService.GetLastKnownExternalIpDataAsync().Result;
                var storedIp = storedData?.ExternalIpAddress;
                var lastUpdate = storedData?.LastUpdated;
                
                if (!string.IsNullOrEmpty(storedIp))
                {
                    // ============================================================================
                    // SUCCESS: RETURN STORED IP WITH TIMESTAMP
                    // ============================================================================
                    // We have a stored IP, so return it with information about when it was stored.
                    // The GetTimeAgo() method converts the timestamp to a human-readable format
                    // like "15 minutes ago" or "2 hours ago".
                    // 
                    // For Java developers: This is similar to formatting timestamps using
                    // Java's Duration or Period classes, or libraries like Joda Time.
                    // ============================================================================
                    var timeAgo = lastUpdate.HasValue ? GetTimeAgo(lastUpdate.Value) : "Unknown";
                    return $"{storedIp} (Stored - Last Updated: {timeAgo})";
                }
                else
                {
                    // ============================================================================
                    // NO STORED IP AVAILABLE
                    // ============================================================================
                    // This can happen if:
                    // 1. The application is running for the first time
                    // 2. The stored IP was deleted or corrupted
                    // 3. The storage service failed
                    // 
                    // We return a clear message indicating the situation.
                    // ============================================================================
                    return "No stored external IP available (VPN Active)";
                }
            }
            else
            {
                // ============================================================================
                // SCENARIO: NOT CONNECTED TO VPN
                // ============================================================================
                // When not connected to a VPN, we can directly query external IP services
                // to get our current external IP address. This is the "real" internet IP
                // that we want to store for future use when VPN is active.
                // ============================================================================
                
                // ============================================================================
                // GET CURRENT EXTERNAL IP
                // ============================================================================
                // Query external IP services like ipify.org, icanhazip.com, etc.
                // to determine our current external IP address.
                // ============================================================================
                var currentIp = GetCurrentExternalIp();
                
                if (!string.IsNullOrEmpty(currentIp) && currentIp != "Unable to determine")
                {
                    // ============================================================================
                    // SUCCESS: STORE AND RETURN CURRENT IP
                    // ============================================================================
                    // We successfully got the current external IP. Now we:
                    // 1. Store it in enhanced persistent storage for future VPN use
                    // 2. Return it with a suffix indicating it's current
                    // 
                    // Note: We use .Wait() here because SaveExternalIpDataAsync is async
                    // but this method is synchronous. In production, consider making
                    // this method async for better performance.
                    // ============================================================================
                    _enhancedIpStorageService.SaveExternalIpDataAsync(currentIp, null).Wait();
                    return currentIp + " (Current - Stored for VPN use)";
                }
                else
                {
                    // ============================================================================
                    // CURRENT IP DETECTION FAILED - TRY STORED IP AS FALLBACK
                    // ============================================================================
                    // External IP services failed, but we might have a stored IP
                    // from a previous successful detection. Try to return that instead.
                    // ============================================================================
                    var storedData = _enhancedIpStorageService.GetLastKnownExternalIpDataAsync().Result;
                    var storedIp = storedData?.ExternalIpAddress;
                    if (!string.IsNullOrEmpty(storedIp))
                    {
                        var lastUpdate = storedData?.LastUpdated;
                        var timeAgo = lastUpdate.HasValue ? GetTimeAgo(lastUpdate.Value) : "Unknown";
                        return $"{storedIp} (Stored - Last Updated: {timeAgo})";
                    }
                    
                    // ============================================================================
                    // COMPLETE FAILURE
                    // ============================================================================
                    // Both current IP detection and stored IP retrieval failed.
                    // Return a clear error message.
                    // ============================================================================
                    return "Unable to determine external IP";
                }
            }
        }
        catch
        {
            // ============================================================================
            // EXCEPTION HANDLING - GRACEFUL DEGRADATION
            // ============================================================================
            // If anything goes wrong in the main logic, we try to fall back to
            // the stored IP as a last resort. This ensures the application
            // doesn't crash completely and can still provide some useful information.
            // 
            // For Java developers: This is similar to providing fallback behavior
            // in catch blocks to ensure graceful degradation of service.
            // ============================================================================
            
            // ============================================================================
            // FALLBACK: TRY STORED IP
            // ============================================================================
            // Attempt to retrieve the stored IP as a fallback option.
            // We wrap this in another try-catch to handle any storage service errors.
            // ============================================================================
            try
            {
                var storedData = _enhancedIpStorageService.GetLastKnownExternalIpDataAsync().Result;
                var storedIp = storedData?.ExternalIpAddress;
                if (!string.IsNullOrEmpty(storedIp))
                {
                    var lastUpdate = storedData?.LastUpdated;
                    var timeAgo = lastUpdate.HasValue ? GetTimeAgo(lastUpdate.Value) : "Unknown";
                    return $"{storedIp} (Stored - Last Updated: {timeAgo})";
                }
            }
            catch
            {
                // ============================================================================
                // IGNORE STORAGE ERRORS
                // ============================================================================
                // If even the fallback fails, we silently ignore the error
                // and return the generic failure message. This prevents
                // error cascading and ensures the API remains stable.
                // ============================================================================
                // Ignore errors
            }
            
            // ============================================================================
            // FINAL FALLBACK
            // ============================================================================
            // All methods have failed. Return a generic error message
            // that indicates the situation without exposing internal errors.
            // ============================================================================
            return "Unable to determine external IP";
        }
    }

    private string GetCurrentExternalIp()
    {
        try
        {
            // Try to get external IP through external services
            var services = new[]
            {
                "https://api.ipify.org",
                "https://icanhazip.com",
                "https://ifconfig.me/ip",
                "https://checkip.amazonaws.com"
            };

            foreach (var service in services)
            {
                try
                {
                    var response = _httpClient.GetStringAsync(service).Result;
                    var ip = response.Trim();
                    
                    // Validate the response looks like an IP address
                    if (IPAddress.TryParse(ip, out _))
                    {
                        return ip;
                    }
                }
                catch
                {
                    // Continue to next service
                    continue;
                }
            }
        }
        catch
        {
            // Handle errors gracefully
        }

        return "Unable to determine";
    }

    private string GetTimeAgo(DateTime lastUpdate)
    {
        var timeSpan = DateTime.UtcNow - lastUpdate;
        
        if (timeSpan.TotalDays >= 1)
        {
            var days = (int)timeSpan.TotalDays;
            return $"{days} day{(days == 1 ? "" : "s")} ago";
        }
        else if (timeSpan.TotalHours >= 1)
        {
            var hours = (int)timeSpan.TotalHours;
            return $"{hours} hour{(hours == 1 ? "" : "s")} ago";
        }
        else if (timeSpan.TotalMinutes >= 1)
        {
            var minutes = (int)timeSpan.TotalMinutes;
            return $"{minutes} minute{(minutes == 1 ? "" : "s")} ago";
        }
        else
        {
            return "Just now";
        }
    }

    private async Task<IpLocationInfo?> GetIpLocationInfo(string externalIpAddress)
    {
        try
        {
            Console.WriteLine($"GetIpLocationInfo: Starting with input: '{externalIpAddress}'");
            
            // Extract the actual IP address from the formatted string
            var ipAddress = ExtractIpAddress(externalIpAddress);
            Console.WriteLine($"GetIpLocationInfo: Extracted IP: '{ipAddress}'");
            
            if (string.IsNullOrEmpty(ipAddress))
            {
                Console.WriteLine("GetIpLocationInfo: IP address is null or empty, returning null");
                return null;
            }

            // ============================================================================
            // INTELLIGENT CACHING: CHECK IF WE ALREADY HAVE LOCATION DATA FOR THIS IP
            // ============================================================================
            // First, check if we have stored location data for the current IP address.
            // If the IP hasn't changed, we can return the cached location data instead
            // of making a new API call to IP-API.
            // ============================================================================
            var storedData = await _enhancedIpStorageService.GetLastKnownExternalIpDataAsync();
            if (storedData != null && storedData.LocationInfo != null)
            {
                // Check if the stored IP is the same as the current IP
                if (await _enhancedIpStorageService.IsStoredIpCurrentAsync(ipAddress))
                {
                    Console.WriteLine($"GetIpLocationInfo: Using cached location data for IP: {ipAddress}");
                    
                    // Get decrypted location info from the encrypted storage
                    var decryptedLocationInfo = storedData.GetDecryptedLocationInfo(_encryptionService);
                    if (decryptedLocationInfo != null)
                    {
                        Console.WriteLine($"GetIpLocationInfo: Cached data - Country: {decryptedLocationInfo.Country}, City: {decryptedLocationInfo.City}");
                        
                        // Return cached location data with updated timestamp
                        var cachedResult = new IpLocationInfo
                        {
                            Country = decryptedLocationInfo.Country,
                            CountryCode = decryptedLocationInfo.CountryCode,
                            Region = decryptedLocationInfo.Region,
                            RegionName = decryptedLocationInfo.RegionName,
                            City = decryptedLocationInfo.City,
                            Zip = decryptedLocationInfo.Zip,
                            Lat = decryptedLocationInfo.Lat,
                            Lon = decryptedLocationInfo.Lon,
                            Timezone = decryptedLocationInfo.Timezone,
                            Isp = decryptedLocationInfo.Isp,
                            Organization = decryptedLocationInfo.Organization,
                            AsNumber = decryptedLocationInfo.AsNumber,
                            Query = decryptedLocationInfo.Query,
                            LastUpdated = DateTime.UtcNow
                        };
                        
                        return cachedResult;
                    }
                    else
                    {
                        Console.WriteLine("GetIpLocationInfo: Failed to decrypt cached location data, will query IP-API");
                    }
                }
                else
                {
                    Console.WriteLine($"GetIpLocationInfo: IP has changed from {storedData.ExternalIpAddress} to {ipAddress}, will query IP-API");
                }
            }
            else
            {
                Console.WriteLine("GetIpLocationInfo: No cached location data available, will query IP-API");
            }

            Console.WriteLine($"GetIpLocationInfo: About to query IP-API for IP: {ipAddress}");
            
            // Query IP-API for location information
            var ipApiResponse = await _ipApiService.GetIpInfoAsync(ipAddress);
            Console.WriteLine($"GetIpLocationInfo: IP-API response received: {ipApiResponse != null}");
            
            if (ipApiResponse == null)
            {
                Console.WriteLine("GetIpLocationInfo: IP-API response is null, returning null");
                return null;
            }

            Console.WriteLine($"GetIpLocationInfo: IP-API response details - Status: {ipApiResponse.Status}, Country: {ipApiResponse.Country}, City: {ipApiResponse.City}");

            var result = new IpLocationInfo
            {
                Country = ipApiResponse.Country ?? string.Empty,
                CountryCode = ipApiResponse.CountryCode ?? string.Empty,
                Region = ipApiResponse.Region ?? string.Empty,
                RegionName = ipApiResponse.RegionName ?? string.Empty,
                City = ipApiResponse.City ?? string.Empty,
                Zip = ipApiResponse.Zip ?? string.Empty,
                Lat = ipApiResponse.Lat ?? 0.0,
                Lon = ipApiResponse.Lon ?? 0.0,
                Timezone = ipApiResponse.Timezone ?? string.Empty,
                Isp = ipApiResponse.Isp ?? string.Empty,
                Organization = ipApiResponse.Org ?? string.Empty,
                AsNumber = ipApiResponse.As ?? string.Empty,
                Query = ipApiResponse.Query ?? string.Empty,
                LastUpdated = DateTime.UtcNow
            };

            Console.WriteLine($"GetIpLocationInfo: Created IpLocationInfo object: Country={result.Country}, City={result.City}");
            
            // ============================================================================
            // CACHE THE NEW LOCATION DATA
            // ============================================================================
            // Store the new location data along with the IP address for future use.
            // This will prevent unnecessary API calls when the same IP is requested again.
            // ============================================================================
            await _enhancedIpStorageService.SaveExternalIpDataAsync(ipAddress, result);
            Console.WriteLine($"GetIpLocationInfo: Cached new location data for IP: {ipAddress}");
            
            return result;
        }
        catch (Exception ex)
        {
            // Handle errors gracefully
            Console.WriteLine($"GetIpLocationInfo: Exception occurred: {ex.Message}");
            Console.WriteLine($"GetIpLocationInfo: Stack trace: {ex.StackTrace}");
            return null;
        }
    }

    private string ExtractIpAddress(string externalIpAddress)
    {
        try
        {
            Console.WriteLine($"ExtractIpAddress: Input: '{externalIpAddress}'");
            
            // Handle different formats:
            // "123.45.67.89 (Current - Stored for VPN use)"
            // "123.45.67.89 (Stored - Last Updated: X minutes ago)"
            // "123.45.67.89"
            
            var parts = externalIpAddress.Split(' ');
            Console.WriteLine($"ExtractIpAddress: Split into {parts.Length} parts");
            
            if (parts.Length > 0)
            {
                Console.WriteLine($"ExtractIpAddress: First part: '{parts[0]}'");
                
                if (System.Net.IPAddress.TryParse(parts[0], out _))
                {
                    Console.WriteLine($"ExtractIpAddress: Successfully parsed IP: '{parts[0]}'");
                    return parts[0];
                }
                else
                {
                    Console.WriteLine($"ExtractIpAddress: Failed to parse IP from '{parts[0]}'");
                }
            }
            else
            {
                Console.WriteLine("ExtractIpAddress: No parts found after split");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ExtractIpAddress: Error: {ex.Message}");
            Console.WriteLine($"ExtractIpAddress: Stack trace: {ex.StackTrace}");
        }
        
        Console.WriteLine("ExtractIpAddress: Returning empty string");
        return string.Empty;
    }

    private bool IsOnVpn()
    {
        try
        {
            var interfaces = SystemNetNetworkInterface.GetAllNetworkInterfaces();
            
            foreach (var nic in interfaces)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    var properties = nic.GetIPProperties();
                    
                    foreach (var address in properties.UnicastAddresses)
                    {
                        if (address.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            // Check if this interface is connected to a VPN gateway
                            if (IsVpnGateway(address.Address, properties.GatewayAddresses))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Handle errors gracefully
        }
        
        return false;
    }









    private SystemNetNetworkInterface? GetLocalNetworkInterface()
    {
        try
        {
            var interfaces = SystemNetNetworkInterface.GetAllNetworkInterfaces();
            
            foreach (var nic in interfaces)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    var properties = nic.GetIPProperties();
                    
                    foreach (var address in properties.UnicastAddresses)
                    {
                        if (address.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            var bytes = address.Address.GetAddressBytes();
                            
                            // Look for local network interface (not VPN)
                            // Check if it's a private IP in the 192.168.x.x range
                            if (bytes[0] == 192 && bytes[1] == 168)
                            {
                                // Verify this is NOT a VPN interface
                                if (!IsVpnGateway(address.Address, properties.GatewayAddresses))
                                {
                                    return nic;
                                }
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Handle errors gracefully
        }
        
        return null;
    }





    private string GetExternalIpFromGateway(string gatewayIp)
    {
        try
        {
            // Try to get external IP information from the ISP gateway
            // Some ISPs expose this information
            var gatewayEndpoints = new[]
            {
                $"http://{gatewayIp}/",
                $"http://{gatewayIp}:8080/",
            };

            foreach (var endpoint in gatewayEndpoints)
            {
                try
                {
                    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
                    var response = client.GetStringAsync(endpoint).Result;
                    
                    // Look for IP patterns in the response
                    var ipPattern = @"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b";
                    var matches = Regex.Matches(response, ipPattern);
                    
                    foreach (Match match in matches)
                    {
                        var ip = match.Value;
                        if (IPAddress.TryParse(ip, out var ipAddress))
                        {
                            var bytes = ipAddress.GetAddressBytes();
                            if (!IsPrivateIpAddress(bytes))
                            {
                                return ip;
                            }
                        }
                    }
                }
                catch
                {
                    continue;
                }
            }
        }
        catch
        {
            // Handle errors gracefully
        }
        
        return "Unable to determine";
    }

    private string GetDefaultGateway()
    {
        try
        {
            var interfaces = SystemNetNetworkInterface.GetAllNetworkInterfaces();
            
            foreach (var nic in interfaces)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    var properties = nic.GetIPProperties();
                    
                    foreach (var gateway in properties.GatewayAddresses)
                    {
                        if (gateway.Address != null && gateway.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return gateway.Address.ToString();
                        }
                    }
                }
            }
        }
        catch
        {
            // Handle errors gracefully
        }
        
        return string.Empty;
    }

    private bool IsLocalNetworkIp(byte[] ipBytes, string routerIp)
    {
        try
        {
            if (IPAddress.TryParse(routerIp, out var routerAddress))
            {
                var routerBytes = routerAddress.GetAddressBytes();
                
                // Check if IP is in the same subnet as router
                // For 192.168.x.x networks, check first 3 octets
                if (ipBytes[0] == 192 && ipBytes[1] == 168 && 
                    routerBytes[0] == 192 && routerBytes[1] == 168)
                {
                    return ipBytes[2] == routerBytes[2];
                }
                
                // For 10.x.x.x networks, check first octet
                if (ipBytes[0] == 10 && routerBytes[0] == 10)
                {
                    return true;
                }
                
                // For 172.16-31.x.x networks, check first two octets
                if (ipBytes[0] == 172 && ipBytes[1] >= 16 && ipBytes[1] <= 31 &&
                    routerBytes[0] == 172 && routerBytes[1] >= 16 && routerBytes[1] <= 31)
                {
                    return ipBytes[1] == routerBytes[1];
                }
            }
        }
        catch
        {
            // Handle errors gracefully
        }
        
        return false;
    }

    private bool IsValidIpAddress(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return false;

        // Skip loopback and link-local addresses
        if (ipAddress == "127.0.0.1" || ipAddress == "::1" || ipAddress.StartsWith("169.254."))
            return false;

        return IPAddress.TryParse(ipAddress, out _);
    }

    private string FormatMacAddress(PhysicalAddress macAddress)
    {
        if (macAddress == null || macAddress.GetAddressBytes().Length == 0)
            return "00:00:00:00:00:00";

        return BitConverter.ToString(macAddress.GetAddressBytes()).Replace("-", ":");
    }

    private string GetGateway(GatewayIPAddressInformationCollection gatewayAddresses)
    {
        var gateways = gatewayAddresses.Select(g => g.Address.ToString());
        return string.Join(", ", gateways);
    }

    private string GetDnsServers(IPAddressCollection dnsAddresses)
    {
        var dnsServers = dnsAddresses.Select(d => d.ToString());
        return string.Join(", ", dnsServers);
    }

    private bool IsVpnGateway(IPAddress localAddress, GatewayIPAddressInformationCollection gateways)
    {
        try
        {
            foreach (var gateway in gateways)
            {
                var gatewayIp = gateway.Address;
                
                // Skip if no gateway
                if (gatewayIp == null) continue;
                
                // Both addresses must be IPv4 for proper analysis
                if (localAddress.AddressFamily == AddressFamily.InterNetwork && 
                    gatewayIp.AddressFamily == AddressFamily.InterNetwork)
                {
                    var localBytes = localAddress.GetAddressBytes();
                    var gatewayBytes = gatewayIp.GetAddressBytes();
                    
                    // Case 1: Both are in private ranges - need deeper analysis
                    if (IsPrivateIpAddress(localBytes) && IsPrivateIpAddress(gatewayBytes))
                    {
                        // Check if they're in the SAME private subnet (likely local network)
                        if (AreInSameSubnet(localAddress, gatewayIp))
                        {
                            return false; // Same subnet = local network, not VPN
                        }
                        
                        // Check if they're in DIFFERENT private ranges (likely VPN)
                        if (AreInDifferentPrivateRanges(localBytes, gatewayBytes))
                        {
                            return true; // Different private ranges = likely VPN
                        }
                        
                        // If same private range but different subnets, could be corporate network
                        // This is ambiguous, so we'll be conservative and say it's NOT a VPN
                        return false;
                    }
                    
                    // Case 2: Local is private, gateway is public (likely VPN)
                    if (IsPrivateIpAddress(localBytes) && !IsPrivateIpAddress(gatewayBytes))
                    {
                        return true;
                    }
                    
                    // Case 3: Both are public (unusual, but not necessarily VPN)
                    if (!IsPrivateIpAddress(localBytes) && !IsPrivateIpAddress(gatewayBytes))
                    {
                        // Could be corporate network with public IPs
                        return false;
                    }
                }
                
                // For IPv6, use simpler logic
                if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    // Link-local addresses are typically local
                    if (localAddress.IsIPv6LinkLocal)
                        return false;
                    
                    // If gateway is in a different IPv6 range, might be VPN
                    // But this is less reliable than IPv4 analysis
                    return false;
                }
            }
        }
        catch
        {
            // Handle errors gracefully - assume local network if we can't determine
        }

        // Default: assume local network (conservative approach)
        return false;
    }

    private bool AreInSameSubnet(IPAddress localAddress, IPAddress gatewayAddress)
    {
        try
        {
            // Get the network interface to find subnet mask
            var interfaces = SystemNetNetworkInterface.GetAllNetworkInterfaces();
            
            foreach (var nic in interfaces)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    var properties = nic.GetIPProperties();
                    
                    foreach (var address in properties.UnicastAddresses)
                    {
                        if (address.Address.Equals(localAddress))
                        {
                            var subnetMask = address.IPv4Mask;
                            if (subnetMask != null)
                            {
                                // Calculate network addresses
                                var localNetwork = GetNetworkAddress(localAddress, subnetMask);
                                var gatewayNetwork = GetNetworkAddress(gatewayAddress, subnetMask);
                                
                                return localNetwork.Equals(gatewayNetwork);
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Fallback: simple heuristic based on first two octets
            var localBytes = localAddress.GetAddressBytes();
            var gatewayBytes = gatewayAddress.GetAddressBytes();
            
            // For 192.168.x.x networks, check first 3 octets
            if (localBytes[0] == 192 && localBytes[1] == 168)
            {
                return localBytes[2] == gatewayBytes[2];
            }
            
            // For 10.x.x.x networks, check first octet only
            if (localBytes[0] == 10)
            {
                return true; // 10.0.0.0/8 is one large network
            }
            
            // For 172.16-31.x.x networks, check first two octets
            if (localBytes[0] == 172 && localBytes[1] >= 16 && localBytes[1] <= 31)
            {
                return localBytes[1] == gatewayBytes[1];
            }
        }
        
        return false;
    }

    private bool AreInDifferentPrivateRanges(byte[] localBytes, byte[] gatewayBytes)
    {
        // Check if local and gateway are in completely different private IP ranges
        
        // Local is 192.168.x.x, gateway is 10.x.x.x
        if (localBytes[0] == 192 && localBytes[1] == 168 && gatewayBytes[0] == 10)
            return true;
        
        // Local is 192.168.x.x, gateway is 172.16-31.x.x
        if (localBytes[0] == 192 && localBytes[1] == 168 && 
            gatewayBytes[0] == 172 && gatewayBytes[1] >= 16 && gatewayBytes[1] <= 31)
            return true;
        
        // Local is 10.x.x.x, gateway is 192.168.x.x
        if (localBytes[0] == 10 && gatewayBytes[0] == 192 && gatewayBytes[1] == 168)
            return true;
        
        // Local is 10.x.x.x, gateway is 172.16-31.x.x
        if (localBytes[0] == 10 && 
            gatewayBytes[0] == 172 && gatewayBytes[1] >= 16 && gatewayBytes[1] <= 31)
            return true;
        
        // Local is 172.16-31.x.x, gateway is 192.168.x.x
        if (localBytes[0] == 172 && localBytes[1] >= 16 && localBytes[1] <= 31 && 
            gatewayBytes[0] == 192 && gatewayBytes[1] == 168)
            return true;
        
        // Local is 172.16-31.x.x, gateway is 10.x.x.x
        if (localBytes[0] == 172 && localBytes[1] >= 16 && localBytes[1] <= 31 && 
            gatewayBytes[0] == 10)
            return true;
        
        return false;
    }

    private IPAddress GetNetworkAddress(IPAddress ipAddress, IPAddress subnetMask)
    {
        var ipBytes = ipAddress.GetAddressBytes();
        var maskBytes = subnetMask.GetAddressBytes();
        var networkBytes = new byte[4];
        
        for (int i = 0; i < 4; i++)
        {
            networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);
        }
        
        return new IPAddress(networkBytes);
    }

    private IpAddressType ClassifyIpAddress(IPAddress ipAddress)
    {
        if (IPAddress.IsLoopback(ipAddress))
            return IpAddressType.Loopback;

        if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ipAddress.IsIPv6LinkLocal)
                return IpAddressType.LinkLocal;
        }

        if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ipAddress.GetAddressBytes();
            
            // Check for private IP ranges
            if (IsPrivateIpAddress(bytes))
                return IpAddressType.Internal;
            
            // Check for VPN ranges (common VPN subnets)
            if (IsVpnIpAddress(bytes))
                return IpAddressType.VPN;
            
            // If not private or VPN, it's likely external
            return IpAddressType.External;
        }

        return IpAddressType.Unknown;
    }

    private bool IsPrivateIpAddress(byte[] bytes)
    {
        if (bytes.Length != 4) return false;

        // 10.0.0.0/8
        if (bytes[0] == 10) return true;
        
        // 172.16.0.0/12
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        
        // 192.168.0.0/16
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        
        // 127.0.0.0/8 (loopback)
        if (bytes[0] == 127) return true;
        
        // 169.254.0.0/16 (link-local)
        if (bytes[0] == 169 && bytes[1] == 254) return true;

        return false;
    }

    private bool IsVpnIpAddress(byte[] bytes)
    {
        if (bytes.Length != 4) return false;

        // Common VPN subnets
        // 192.168.1.0/24 (common home/office)
        if (bytes[0] == 192 && bytes[1] == 168 && bytes[2] == 1) return true;
        
        // 10.8.0.0/24 (OpenVPN default)
        if (bytes[0] == 10 && bytes[1] == 8) return true;
        
        // 10.10.0.0/24 (common VPN range)
        if (bytes[0] == 10 && bytes[1] == 10) return true;
        
        // 172.20.0.0/16 (common corporate VPN)
        if (bytes[0] == 172 && bytes[1] >= 20 && bytes[1] <= 30) return true;

        return false;
    }

    private string GetIpTypeDescription(IpAddressType ipType)
    {
        return ipType switch
        {
            IpAddressType.Internal => "Private/Internal network address",
            IpAddressType.External => "Public/Internet address",
            IpAddressType.VPN => "VPN tunnel address",
            IpAddressType.Loopback => "Loopback/localhost address",
            IpAddressType.LinkLocal => "Link-local address",
            IpAddressType.Unknown => "Unknown address type",
            _ => "Unspecified address type"
        };
    }
}
