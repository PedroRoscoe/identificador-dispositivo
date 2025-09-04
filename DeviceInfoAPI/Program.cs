// ============================================================================
// Program.cs - Application entry point and configuration
// ============================================================================
// This file is the main entry point for the .NET application. It configures:
// - Dependency injection container
// - Services and their lifetimes
// - Middleware pipeline (CORS, Swagger, etc.)
// - API endpoints and routing
// - Application startup and shutdown
//
// For Java developers: This is similar to the main() method in a Java application
// combined with Spring Boot's @SpringBootApplication class and configuration.
// The builder pattern is used to configure the application step by step.
// ============================================================================

using DeviceInfoAPI.Services;  // Import our custom services
using DeviceInfoAPI.Controllers;  // Import our controllers

var builder = WebApplication.CreateBuilder(args);

// ============================================================================
// DEPENDENCY INJECTION CONFIGURATION
// ============================================================================
// Register services in the DI container. This tells the application how to
// create and manage instances of our services.
//
// For Java developers: This is similar to using @Service, @Component, or @Bean
// annotations in Spring Boot to register services in the application context.
//
// Service lifetimes:
// - Singleton: One instance for the entire application lifetime
// - Scoped: One instance per HTTP request
// - Transient: New instance every time it's requested
// ============================================================================

// Add services to the container
builder.Services.AddSingleton<IEncryptionService, EncryptionService>();           // Encryption service for data security
builder.Services.AddSingleton<IEnhancedIpStorageService, EnhancedIpStorageService>(); // Enhanced IP storage with caching
builder.Services.AddSingleton<IIpApiService, IpApiService>();                     // IP geolocation API service
builder.Services.AddSingleton<IDeviceInfoService, DeviceInfoService>();           // Main device info service
builder.Services.AddSingleton<IRiskAnalysisService, RiskAnalysisService>();      // Risk analysis service
builder.Services.AddSingleton<IMaliciousApplicationsService, MaliciousApplicationsService>(); // Malicious applications detection service
builder.Services.AddSingleton<IMaliciousApplicationsStorageService, MaliciousApplicationsStorageService>(); // Encrypted storage service for malicious applications
builder.Services.AddSingleton<MaliciousApplicationsMigrationService>(); // Migration service for malicious applications

// ============================================================================
// CORS (CROSS-ORIGIN RESOURCE SHARING) CONFIGURATION
// ============================================================================
// CORS is a security feature that controls which domains can access your API.
// Since this is a local development tool, we allow access from localhost
// with any port number.
//
// For Java developers: This is similar to @CrossOrigin annotation in Spring Boot
// or configuring CORS in WebMvcConfigurer.
//
// In production, you would restrict this to specific domains for security.
// ============================================================================

// Configure CORS to allow local access
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocal", policy =>
    {
        policy.WithOrigins("http://localhost:*", "https://localhost:*")  // Allow any localhost port
              .AllowAnyHeader()                                          // Allow any HTTP headers
              .AllowAnyMethod();                                         // Allow any HTTP methods (GET, POST, etc.)
    });
});

// ============================================================================
// SWAGGER/OPENAPI CONFIGURATION
// ============================================================================
// Swagger provides interactive API documentation and testing interface.
// This is automatically generated from your API endpoints and can be
// accessed at /swagger when running in development mode.
//
// For Java developers: This is similar to springdoc-openapi in Spring Boot,
// which automatically generates OpenAPI documentation from your controllers.
// ============================================================================

// Add Swagger/OpenAPI support
builder.Services.AddEndpointsApiExplorer();  // Enable endpoint discovery for Swagger
builder.Services.AddSwaggerGen();            // Generate Swagger documentation

// Add controllers for the risk analysis API
builder.Services.AddControllers();

var app = builder.Build();

// ============================================================================
// MIDDLEWARE PIPELINE CONFIGURATION
// ============================================================================
// Middleware components are executed in the order they're added to the pipeline.
// Each middleware can process the request, modify it, or short-circuit the pipeline.
//
// For Java developers: This is similar to configuring filters, interceptors,
// or middleware in Spring Boot applications.
// ============================================================================

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    // ============================================================================
    // DEVELOPMENT-ONLY MIDDLEWARE
    // ============================================================================
    // These middleware components are only enabled in development mode
    // for security and performance reasons.
    // ============================================================================
    app.UseSwagger();        // Enable Swagger JSON endpoint (/swagger/v1/swagger.json)
    app.UseSwaggerUI();      // Enable Swagger UI interface (/swagger)
}

// ============================================================================
    // CORS MIDDLEWARE
    // ============================================================================
    // Enable CORS for all requests. This must be called before routing
    // to ensure CORS headers are properly set.
    // ============================================================================
app.UseCors("AllowLocal");

// Add routing and controllers
app.UseRouting();
app.MapControllers();

// ============================================================================
// API ENDPOINTS DEFINITION
// ============================================================================
// Define the HTTP endpoints that your API exposes. Each endpoint maps
// an HTTP method and path to a handler function that processes the request.
//
// For Java developers: This is similar to @RestController and @RequestMapping
// annotations in Spring Boot, but using a more functional approach.
//
// Endpoint structure:
// - HTTP method (GET, POST, PUT, DELETE)
// - URL path (/api/device-info)
// - Handler function (lambda that processes the request)
// - Metadata (name, OpenAPI documentation)
// ============================================================================

// Define endpoints

// ============================================================================
// ROOT ENDPOINT - Health check and API status
// ============================================================================
// Simple endpoint that returns a message indicating the API is running.
// Useful for health checks and basic connectivity testing.
// ============================================================================
app.MapGet("/", () => "Device Info API is running!");

// ============================================================================
// DEVICE INFO ENDPOINT - Main API functionality
// ============================================================================
// This is the primary endpoint that returns comprehensive device and
// network information. It uses dependency injection to get the
// DeviceInfoService instance.
//
// For Java developers: The parameter injection is similar to @Autowired
// in Spring Boot controllers.
// ============================================================================
app.MapGet("/api/device-info", (IDeviceInfoService deviceInfoService) =>
{
    // ============================================================================
    // REQUEST PROCESSING
    // ============================================================================
    // Call the service to gather device information and return it as
    // a JSON response with HTTP 200 (OK) status.
    // 
    // For Java developers: This is similar to calling a service method
    // and returning ResponseEntity.ok(deviceInfo) in Spring Boot.
    // ============================================================================
    var deviceInfo = deviceInfoService.GetDeviceInfo();
    return Results.Ok(deviceInfo);
})
.WithName("GetDeviceInfo")        // Name for OpenAPI documentation
.WithOpenApi();                   // Include in OpenAPI/Swagger documentation

// ============================================================================
// ASYNC DEVICE INFO ENDPOINT - Alternative async implementation
// ============================================================================
// This endpoint provides the same functionality as /api/device-info but
// uses the asynchronous version of the service method. This can be useful
// for performance testing and demonstrating async capabilities.
//
// For Java developers: This is similar to having both synchronous and
// asynchronous versions of the same endpoint in Spring Boot.
// ============================================================================
app.MapGet("/api/device-info/async", async (IDeviceInfoService deviceInfoService) =>
{
    // ============================================================================
    // ASYNC REQUEST PROCESSING
    // ============================================================================
    // Use the async version of the service method and await the result.
    // The async keyword allows the method to handle multiple concurrent requests.
    // ============================================================================
    var deviceInfo = await deviceInfoService.GetDeviceInfoAsync();
    return Results.Ok(deviceInfo);
})
.WithName("GetDeviceInfoAsync")   // Name for OpenAPI documentation
.WithOpenApi();                   // Include in OpenAPI/Swagger documentation

// ============================================================================
// HEALTH CHECK ENDPOINT - Application health monitoring
// ============================================================================
// Simple health check endpoint that returns the application status and
// current timestamp. Useful for monitoring systems and load balancers
// to verify the application is running and responsive.
//
// For Java developers: This is similar to a health check endpoint in
// Spring Boot Actuator or custom health check controllers.
// ============================================================================
app.MapGet("/api/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
.WithName("HealthCheck")          // Name for OpenAPI documentation
.WithOpenApi();                   // Include in OpenAPI/Swagger documentation

// ============================================================================
// IP-API TEST ENDPOINT - Debugging and testing tool
// ============================================================================
// This endpoint allows developers to test the IP-API integration directly
// by providing an IP address as a path parameter. It's useful for:
// - Debugging IP-API responses
// - Testing private IP detection logic
// - Verifying the service integration works correctly
//
// For Java developers: This is similar to a test endpoint in Spring Boot
// that allows direct testing of external service integrations.
// ============================================================================
app.MapGet("/api/test-ip-api/{ip}", async (string ip, IIpApiService ipApiService) =>
{
    try
    {
        Console.WriteLine($"Test endpoint: Testing IP-API for IP: {ip}");
        
        // ============================================================================
        // STEP 1: PRIVATE IP VALIDATION TEST
        // ============================================================================
        // Test our private IP detection logic directly to verify it works
        // correctly. This helps debug any issues with the validation.
        // ============================================================================
        var isPrivate = IsPrivateIpAddress(ip);
        Console.WriteLine($"Test endpoint: IsPrivateIpAddress({ip}) = {isPrivate}");
        
        // ============================================================================
        // STEP 2: IP-API SERVICE TEST
        // ============================================================================
        // Call the actual IP-API service to test the integration.
        // This verifies that the service can communicate with the external API.
        // ============================================================================
        var result = await ipApiService.GetIpInfoAsync(ip);
        Console.WriteLine($"Test endpoint: IP-API result: {result != null}");
        
        // ============================================================================
        // STEP 3: RETURN TEST RESULTS
        // ============================================================================
        // Return a comprehensive result object that shows:
        // - The IP address being tested
        // - Whether it was detected as private
        // - The IP-API service result
        // - Key fields from the response (country, city, status)
        // ============================================================================
        return Results.Ok(new { 
            TestIp = ip,           // The IP address being tested
            IsPrivate = isPrivate, // Result of private IP detection
            Result = result != null, // Whether IP-API returned data
            Country = result?.Country, // Country from IP-API response
            City = result?.City,       // City from IP-API response
            Status = result?.Status    // Status from IP-API response
        });
    }
    catch (Exception ex)
    {
        // ============================================================================
        // EXCEPTION HANDLING - Return error details for debugging
        // ============================================================================
        // If any exception occurs during testing, return the error details
        // to help developers understand what went wrong.
        // ============================================================================
        Console.WriteLine($"Test endpoint: Exception: {ex.Message}");
        return Results.Ok(new { 
            TestIp = ip,           // The IP address being tested
            Error = ex.Message,    // Error message for debugging
            StackTrace = ex.StackTrace // Stack trace for detailed debugging
        });
    }
    
    // ============================================================================
    // LOCAL HELPER METHOD - Private IP detection logic
    // ============================================================================
    // This method duplicates the logic from IpApiService for testing purposes.
    // It allows us to test the private IP detection independently of the service.
    //
    // Note: In production, consider extracting this to a shared utility class
    // to avoid code duplication.
    // ============================================================================
    bool IsPrivateIpAddress(string ipAddress)
    {
        // ============================================================================
        // IP ADDRESS VALIDATION
        // ============================================================================
        // Parse the IP address string and return false if it's invalid.
        // This prevents errors when processing malformed IP addresses.
        // ============================================================================
        if (!System.Net.IPAddress.TryParse(ipAddress, out var ip))
            return false;

        // ============================================================================
        // GET IP ADDRESS BYTES
        // ============================================================================
        // Convert the IP address to its byte array representation for analysis.
        // IPv4 addresses are 4 bytes, IPv6 addresses are 16 bytes.
        // ============================================================================
        var bytes = ip.GetAddressBytes();
        
        // ============================================================================
        // RFC 1918 PRIVATE IP RANGE CHECKS
        // ============================================================================
        // Check each private IP range according to RFC 1918 standards.
        // These ranges are reserved for private networks and cannot be
        // used on the public internet.
        // ============================================================================
        
        // 10.0.0.0/8 (Class A private network)
        if (bytes[0] == 10) return true;
        
        // 172.16.0.0/12 (Class B private network)
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        
        // 192.168.0.0/16 (Class C private network)
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        
        // ============================================================================
        // SPECIAL PURPOSE IP RANGES
        // ============================================================================
        // Additional ranges that are not routable on the public internet.
        // ============================================================================
        
        // 127.0.0.0/8 (Loopback addresses - localhost)
        if (bytes[0] == 127) return true;
        
        // 169.254.0.0/16 (Link-local addresses - auto-assigned when DHCP fails)
        if (bytes[0] == 169 && bytes[1] == 254) return true;

        // ============================================================================
        // PUBLIC IP ADDRESS
        // ============================================================================
        // If the IP address doesn't match any private ranges above,
        // it's considered a public IP address that can be queried.
        // ============================================================================
        return false;
    }
})
.WithName("TestIpApi")             // Name for OpenAPI documentation
.WithOpenApi();                    // Include in OpenAPI/Swagger documentation

// ============================================================================
// DEVICE IDENTIFIERS TEST ENDPOINT - Debugging and testing tool
// ============================================================================
// This endpoint allows developers to see all available Windows device identifiers
// from multiple sources (WMI, Registry, Network, Environment) to help identify
// which identifier matches what Windows displays to users.
//
// For Java developers: This is similar to a diagnostic endpoint in Spring Boot
// that exposes system information for troubleshooting purposes.
// ============================================================================
app.MapGet("/api/test-identifiers", () =>
{
    try
    {
        Console.WriteLine("Test identifiers endpoint: Querying all Windows device identifiers...");
        
        var identifiers = new Dictionary<string, object>();
        
        // ============================================================================
        // SOURCE 1: WMI (Windows Management Instrumentation) Identifiers
        // ============================================================================
        try
        {
            // Query 1: Computer System Product (BIOS UUID)
            try
            {
                using var searcher1 = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystemProduct");
                foreach (System.Management.ManagementObject obj in searcher1.Get())
                {
                    var uuid = obj["UUID"]?.ToString();
                    var name = obj["Name"]?.ToString();
                    var vendor = obj["Vendor"]?.ToString();
                    var identifyingNumber = obj["IdentifyingNumber"]?.ToString();
                    var sku = obj["SKU"]?.ToString();

                    if (!string.IsNullOrEmpty(uuid))
                    {
                        identifiers["BIOS_UUID"] = uuid;
                        Console.WriteLine($"Test identifiers: Found BIOS UUID: {uuid}");
                    }
                    if (!string.IsNullOrEmpty(name))
                        identifiers["System_Product_Name"] = name;
                    if (!string.IsNullOrEmpty(vendor))
                        identifiers["Vendor"] = vendor;
                    if (!string.IsNullOrEmpty(identifyingNumber))
                        identifiers["Identifying_Number"] = identifyingNumber;
                    if (!string.IsNullOrEmpty(sku))
                        identifiers["SKU"] = sku;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test identifiers: WMI Query 1 Error: {ex.Message}");
            }

            // Query 2: Computer System
            try
            {
                using var searcher2 = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (System.Management.ManagementObject obj in searcher2.Get())
                {
                    var name = obj["Name"]?.ToString();
                    var guid = obj["GUID"]?.ToString();
                    var domain = obj["Domain"]?.ToString();
                    var manufacturer = obj["Manufacturer"]?.ToString();
                    var model = obj["Model"]?.ToString();

                    if (!string.IsNullOrEmpty(name))
                        identifiers["Computer_Name"] = name;
                    if (!string.IsNullOrEmpty(guid))
                        identifiers["Computer_GUID"] = guid;
                    if (!string.IsNullOrEmpty(domain))
                        identifiers["Computer_Domain"] = domain;
                    if (!string.IsNullOrEmpty(manufacturer))
                        identifiers["Computer_Manufacturer"] = manufacturer;
                    if (!string.IsNullOrEmpty(model))
                        identifiers["Computer_Model"] = model;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test identifiers: WMI Query 2 Error: {ex.Message}");
            }

            // Query 3: BaseBoard (Motherboard)
            try
            {
                using var searcher3 = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");
                foreach (System.Management.ManagementObject obj in searcher3.Get())
                {
                    var manufacturer = obj["Manufacturer"]?.ToString();
                    var product = obj["Product"]?.ToString();
                    var serialNumber = obj["SerialNumber"]?.ToString();
                    var version = obj["Version"]?.ToString();

                    if (!string.IsNullOrEmpty(manufacturer))
                        identifiers["Motherboard_Manufacturer"] = manufacturer;
                    if (!string.IsNullOrEmpty(product))
                        identifiers["Motherboard_Product"] = product;
                    if (!string.IsNullOrEmpty(serialNumber))
                        identifiers["Motherboard_SerialNumber"] = serialNumber;
                    if (!string.IsNullOrEmpty(version))
                        identifiers["Motherboard_Version"] = version;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test identifiers: WMI Query 3 Error: {ex.Message}");
            }

            // Query 4: Processor
            try
            {
                using var searcher4 = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_Processor");
                foreach (System.Management.ManagementObject obj in searcher4.Get())
                {
                    var name = obj["Name"]?.ToString();
                    var manufacturer = obj["Manufacturer"]?.ToString();
                    var deviceId = obj["DeviceID"]?.ToString();
                    var processorId = obj["ProcessorId"]?.ToString();

                    if (!string.IsNullOrEmpty(name))
                        identifiers["Processor_Name"] = name;
                    if (!string.IsNullOrEmpty(manufacturer))
                        identifiers["Processor_Manufacturer"] = manufacturer;
                    if (!string.IsNullOrEmpty(deviceId))
                        identifiers["Processor_DeviceID"] = deviceId;
                    if (!string.IsNullOrEmpty(processorId))
                        identifiers["Processor_ID"] = processorId;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test identifiers: WMI Query 4 Error: {ex.Message}");
            }

            // Query 5: Operating System
            try
            {
                using var searcher5 = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem");
                foreach (System.Management.ManagementObject obj in searcher5.Get())
                {
                    var name = obj["Name"]?.ToString();
                    var version = obj["Version"]?.ToString();
                    var buildNumber = obj["BuildNumber"]?.ToString();
                    var serialNumber = obj["SerialNumber"]?.ToString();
                    var csdVersion = obj["CSDVersion"]?.ToString();
                    var osArchitecture = obj["OSArchitecture"]?.ToString();

                    if (!string.IsNullOrEmpty(name))
                        identifiers["OS_Name"] = name;
                    if (!string.IsNullOrEmpty(version))
                        identifiers["OS_Version"] = version;
                    if (!string.IsNullOrEmpty(buildNumber))
                        identifiers["OS_Build_Number"] = buildNumber;
                    if (!string.IsNullOrEmpty(serialNumber))
                        identifiers["OS_Serial_Number"] = serialNumber;
                    if (!string.IsNullOrEmpty(csdVersion))
                        identifiers["OS_CSD_Version"] = csdVersion;
                    if (!string.IsNullOrEmpty(osArchitecture))
                        identifiers["OS_Architecture"] = osArchitecture;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test identifiers: WMI Query 5 Error: {ex.Message}");
            }

            // Query 6: Computer System Product (Additional fields)
            try
            {
                using var searcher6 = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystemProduct");
                foreach (System.Management.ManagementObject obj in searcher6.Get())
                {
                    var version = obj["Version"]?.ToString();
                    var description = obj["Description"]?.ToString();
                    var caption = obj["Caption"]?.ToString();

                    if (!string.IsNullOrEmpty(version))
                        identifiers["Product_Version"] = version;
                    if (!string.IsNullOrEmpty(description))
                        identifiers["Product_Description"] = description;
                    if (!string.IsNullOrEmpty(caption))
                        identifiers["Product_Caption"] = caption;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test identifiers: WMI Query 6 Error: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            identifiers["WMI_Error"] = ex.Message;
            Console.WriteLine($"Test identifiers: WMI Error: {ex.Message}");
        }

        // ============================================================================
        // SOURCE 2: Registry Identifiers
        // ============================================================================
        try
        {
            // Windows NT CurrentVersion
            using var key1 = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key1 != null)
            {
                var productId = key1.GetValue("ProductId")?.ToString();
                var installationId = key1.GetValue("InstallationId")?.ToString();
                var machineGuid = key1.GetValue("MachineGuid")?.ToString();
                var productName = key1.GetValue("ProductName")?.ToString();
                var buildLab = key1.GetValue("BuildLab")?.ToString();
                var buildLabEx = key1.GetValue("BuildLabEx")?.ToString();
                var currentBuild = key1.GetValue("CurrentBuild")?.ToString();
                var currentBuildNumber = key1.GetValue("CurrentBuildNumber")?.ToString();

                if (!string.IsNullOrEmpty(productId))
                    identifiers["Product_ID"] = productId;
                if (!string.IsNullOrEmpty(installationId))
                    identifiers["Installation_ID"] = installationId;
                if (!string.IsNullOrEmpty(machineGuid))
                    identifiers["Machine_GUID"] = machineGuid;
                if (!string.IsNullOrEmpty(productName))
                    identifiers["Product_Name"] = productName;
                if (!string.IsNullOrEmpty(buildLab))
                    identifiers["Build_Lab"] = buildLab;
                if (!string.IsNullOrEmpty(buildLabEx))
                    identifiers["Build_LabEx"] = buildLabEx;
                if (!string.IsNullOrEmpty(currentBuild))
                    identifiers["Current_Build"] = currentBuild;
                if (!string.IsNullOrEmpty(currentBuildNumber))
                    identifiers["Current_Build_Number"] = currentBuildNumber;
            }

            // Windows CurrentVersion
            using var key2 = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion");
            if (key2 != null)
            {
                var devicePath = key2.GetValue("DevicePath")?.ToString();
                var programFilesDir = key2.GetValue("ProgramFilesDir")?.ToString();
                var commonFilesDir = key2.GetValue("CommonFilesDir")?.ToString();

                if (!string.IsNullOrEmpty(devicePath))
                    identifiers["Device_Path"] = devicePath;
                if (!string.IsNullOrEmpty(programFilesDir))
                    identifiers["Program_Files_Dir"] = programFilesDir;
                if (!string.IsNullOrEmpty(commonFilesDir))
                    identifiers["Common_Files_Dir"] = commonFilesDir;
            }

            // Windows Setup
            using var key3 = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Setup");
            if (key3 != null)
            {
                var installDate = key3.GetValue("InstallDate")?.ToString();
                var installType = key3.GetValue("InstallType")?.ToString();
                var productId2 = key3.GetValue("ProductId")?.ToString();

                if (!string.IsNullOrEmpty(installDate))
                    identifiers["Install_Date"] = installDate;
                if (!string.IsNullOrEmpty(installType))
                    identifiers["Install_Type"] = installType;
                if (!string.IsNullOrEmpty(productId2))
                    identifiers["Setup_Product_ID"] = productId2;
            }

            // Windows Activation
            using var key4 = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform");
            if (key4 != null)
            {
                var backupProductKeyDefault = key4.GetValue("BackupProductKeyDefault")?.ToString();
                var lastActivationSku = key4.GetValue("LastActivationSku")?.ToString();

                if (!string.IsNullOrEmpty(backupProductKeyDefault))
                    identifiers["Backup_Product_Key"] = backupProductKeyDefault;
                if (!string.IsNullOrEmpty(lastActivationSku))
                    identifiers["Last_Activation_SKU"] = lastActivationSku;
            }
        }
        catch (Exception ex)
        {
            identifiers["Registry_Error"] = ex.Message;
            Console.WriteLine($"Test identifiers: Registry Error: {ex.Message}");
        }

        // ============================================================================
        // SOURCE 3: Environment Identifiers
        // ============================================================================
        try
        {
            identifiers["Machine_Name"] = Environment.MachineName;
            identifiers["User_Name"] = Environment.UserName;
            identifiers["User_Domain"] = Environment.UserDomainName;
            identifiers["OS_Version"] = Environment.OSVersion.ToString();
            identifiers["Processor_Count"] = Environment.ProcessorCount;
        }
        catch (Exception ex)
        {
            identifiers["Environment_Error"] = ex.Message;
            Console.WriteLine($"Test identifiers: Environment Error: {ex.Message}");
        }

        // ============================================================================
        // SOURCE 4: Network Interface Identifiers
        // ============================================================================
        try
        {
            var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            var macAddresses = new List<string>();

            foreach (var nic in interfaces)
            {
                if (nic.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
                {
                    var mac = nic.GetPhysicalAddress();
                    if (mac != null && mac.GetAddressBytes().Length > 0)
                    {
                        var macString = BitConverter.ToString(mac.GetAddressBytes()).Replace("-", ":");
                        macAddresses.Add(macString);
                    }
                }
            }

            if (macAddresses.Any())
            {
                identifiers["MAC_Addresses"] = macAddresses;
                identifiers["Total_Active_MAC_Addresses"] = macAddresses.Count;
            }
        }
        catch (Exception ex)
        {
            identifiers["Network_Error"] = ex.Message;
            Console.WriteLine($"Test identifiers: Network Error: {ex.Message}");
        }

        Console.WriteLine($"Test identifiers: Found {identifiers.Count} identifier types");
        return Results.Ok(identifiers);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Test identifiers: Exception: {ex.Message}");
        return Results.Ok(new { 
            Error = ex.Message,
            StackTrace = ex.StackTrace
        });
    }
})
.WithName("TestIdentifiers")       // Name for OpenAPI documentation
.WithOpenApi();                    // Include in OpenAPI/Swagger documentation

// ============================================================================
// APPLICATION STARTUP AND LOGGING
// ============================================================================
// Display startup information and begin listening for HTTP requests.
// This section provides useful information for developers and operators
// about the application's configuration and startup status.
//
// For Java developers: This is similar to logging application startup
// information in Spring Boot's main method or ApplicationRunner.
// ============================================================================

// Start the application
Console.WriteLine("Starting Device Info API...");
Console.WriteLine($"Environment: {app.Environment.EnvironmentName}");  // Development, Production, etc.
Console.WriteLine($"URLs: {string.Join(", ", app.Urls)}");            // Listening URLs (e.g., http://localhost:5000)

// ============================================================================
// DATA MIGRATION
// ============================================================================
// Migrate existing unencrypted data to encrypted format for enhanced security.
// This ensures backward compatibility while improving data protection.
// ============================================================================
try
{
    var enhancedStorageService = app.Services.GetRequiredService<IEnhancedIpStorageService>();
    await enhancedStorageService.MigrateToEncryptedStorageAsync();
    Console.WriteLine("Enhanced storage data migration completed successfully.");
}
catch (Exception ex)
{
    Console.WriteLine($"Enhanced storage data migration failed: {ex.Message}");
    Console.WriteLine("Application will continue with existing data.");
}

// Migrate malicious applications from JSON to encrypted format
try
{
    var maliciousAppsMigrationService = app.Services.GetRequiredService<MaliciousApplicationsMigrationService>();
    await maliciousAppsMigrationService.MigrateFromJsonAsync();
    Console.WriteLine("Malicious applications data migration completed successfully.");
}
catch (Exception ex)
{
    Console.WriteLine($"Malicious applications data migration failed: {ex.Message}");
    Console.WriteLine("Application will continue with existing data.");
}

// ============================================================================
// APPLICATION EXECUTION
// ============================================================================
// Start the web application and begin listening for HTTP requests.
// This call blocks until the application is shut down.
//
// For Java developers: This is similar to SpringApplication.run() in Spring Boot,
// which starts the embedded web server and begins accepting requests.
// ============================================================================
app.Run();
