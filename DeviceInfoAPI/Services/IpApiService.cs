// ============================================================================
// IpApiService.cs - Service for querying IP geolocation and ISP information
// ============================================================================
// This service integrates with the IP-API (http://ip-api.com) to retrieve
// comprehensive information about IP addresses, including:
// - Geographic location (country, region, city, coordinates)
// - ISP and organization details
// - Timezone information
// - AS (Autonomous System) number
//
// For Java developers: This is similar to a service class that makes HTTP
// calls to external APIs and deserializes JSON responses. It's equivalent
// to using RestTemplate or WebClient in Spring Boot.
// ============================================================================

using System.Text.Json;  // JSON serialization/deserialization

namespace DeviceInfoAPI.Services;

/// <summary>
/// Service for querying IP geolocation and ISP information from IP-API.
/// 
/// This service makes HTTP requests to http://ip-api.com/json/{ipAddress} to
/// retrieve detailed information about IP addresses. It handles:
/// - HTTP communication with external API
/// - JSON response deserialization
/// - Private IP address filtering
/// - Error handling and logging
/// 
/// For Java developers: This class is similar to a service that uses RestTemplate
/// or WebClient to make HTTP calls to external APIs. The HttpClient is equivalent
/// to Java's HttpURLConnection or Apache HttpClient.
/// </summary>
public class IpApiService : IIpApiService
{
    // ============================================================================
    // DEPENDENCIES AND CONFIGURATION
    // ============================================================================
    
    /// <summary>
    /// HTTP client for making requests to the IP-API service.
    /// Configured with timeout and used for all external API calls.
    /// 
    /// For Java developers: This is similar to RestTemplate or WebClient in Spring Boot.
    /// </summary>
    private readonly HttpClient _httpClient;
    
    /// <summary>
    /// Base URL for the IP-API service.
    /// The full URL is constructed as: {baseUrl}/{ipAddress}
    /// Example: http://ip-api.com/json/8.8.8.8
    /// </summary>
    private readonly string _baseUrl = "http://ip-api.com/json";

    /// <summary>
    /// Constructor for IpApiService.
    /// 
    /// Initializes the HTTP client with a 10-second timeout to prevent
    /// the application from hanging if the IP-API service is slow or unresponsive.
    /// 
    /// For Java developers: This is similar to configuring RestTemplate with
    /// timeout settings in Spring Boot.
    /// </summary>
    public IpApiService()
    {
        // ============================================================================
        // HTTP CLIENT CONFIGURATION
        // ============================================================================
        // Create a new HttpClient instance with timeout configuration.
        // The timeout ensures that API calls don't hang indefinitely if the
        // external service is slow or unresponsive.
        // 
        // Note: In production applications, consider using HttpClientFactory
        // or a singleton HttpClient to avoid socket exhaustion issues.
        // 
        // For Java developers: This is similar to setting connection and
        // read timeouts on HttpURLConnection or RestTemplate.
        // ============================================================================
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)  // 10 second timeout for all API calls
        };
    }

    /// <summary>
    /// Asynchronously retrieves IP geolocation and ISP information from IP-API.
    /// 
    /// This method performs the following steps:
    /// 1. Validates that the IP address is not private (skips private IPs)
    /// 2. Constructs the API URL for the IP-API service
    /// 3. Makes an HTTP GET request to retrieve the IP information
    /// 4. Deserializes the JSON response into an IpApiResponse object
    /// 5. Validates the response status and returns the data if successful
    /// 
    /// For Java developers: This method demonstrates several .NET patterns:
    /// - async/await for asynchronous HTTP operations
    /// - JSON deserialization with error handling
    /// - Nullable reference types (?)
    /// - String interpolation with $"" syntax
    /// 
    /// The equivalent Java code would use CompletableFuture and Jackson ObjectMapper.
    /// </summary>
    /// <param name="ipAddress">The IP address to query (IPv4 or IPv6)</param>
    /// <returns>
    /// IpApiResponse object with location and ISP information if successful,
    /// null if the IP is private, the API call fails, or the response is invalid
    /// </returns>
    public async Task<IpApiResponse?> GetIpInfoAsync(string ipAddress)
    {
        try
        {
            Console.WriteLine($"IP-API: GetIpInfoAsync called with IP: {ipAddress}");
            
            // ============================================================================
            // STEP 1: PRIVATE IP VALIDATION
            // ============================================================================
            // Skip private IP addresses because IP-API cannot provide meaningful
            // geolocation information for them. Private IPs include:
            // - 10.x.x.x (10.0.0.0/8)
            // - 172.16.x.x to 172.31.x.x (172.16.0.0/12)
            // - 192.168.x.x (192.168.0.0/16)
            // - 127.x.x.x (127.0.0.0/8 - loopback)
            // - 169.254.x.x (169.254.0.0/16 - link-local)
            // 
            // For Java developers: This is similar to validating input parameters
            // before making external API calls to avoid unnecessary network requests.
            // ============================================================================
            if (IsPrivateIpAddress(ipAddress))
            {
                Console.WriteLine($"IP-API: Skipping private IP address: {ipAddress}");
                return null;
            }

            Console.WriteLine($"IP-API: IP {ipAddress} is not private, proceeding with API call");

            // ============================================================================
            // STEP 2: CONSTRUCT API URL
            // ============================================================================
            // Build the full URL for the IP-API service by combining the base URL
            // with the specific IP address we want to query.
            // 
            // For Java developers: This is similar to using StringBuilder or
            // String.format() to construct URLs for API calls.
            // ============================================================================
            var url = $"{_baseUrl}/{ipAddress}";
            Console.WriteLine($"IP-API: Querying URL: {url}");
            
            // ============================================================================
            // STEP 3: MAKE HTTP REQUEST
            // ============================================================================
            // Use HttpClient to make an asynchronous GET request to the IP-API service.
            // The await keyword ensures we wait for the response before continuing.
            // 
            // For Java developers: This is similar to using RestTemplate.getForObject()
            // or WebClient.get().retrieve().bodyToMono() in Spring Boot.
            // ============================================================================
            var response = await _httpClient.GetStringAsync(url);
            Console.WriteLine($"IP-API: Full response received: {response}");
            
            // ============================================================================
            // STEP 4: JSON DESERIALIZATION
            // ============================================================================
            // Convert the JSON response string into a strongly-typed C# object.
            // We use PropertyNameCaseInsensitive = true to handle any case mismatches
            // between the JSON property names and our C# property names.
            // 
            // For Java developers: This is similar to using Jackson ObjectMapper
            // or Gson to deserialize JSON responses into Java objects.
            // ============================================================================
            IpApiResponse? ipInfo = null;
            try
            {
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true  // Handle case mismatches in JSON
                };
                ipInfo = JsonSerializer.Deserialize<IpApiResponse>(response, options);
                Console.WriteLine($"IP-API: Deserialized object - Status: '{ipInfo?.Status}', Country: '{ipInfo?.Country}', City: '{ipInfo?.City}'");
            }
            catch (JsonException ex)
            {
                // ============================================================================
                // JSON DESERIALIZATION ERROR HANDLING
                // ============================================================================
                // If the JSON response cannot be parsed (malformed JSON, unexpected format),
                // we log the error details and continue with null ipInfo.
                // 
                // For Java developers: This is similar to catching JsonParseException
                // or JsonMappingException when using Jackson ObjectMapper.
                // ============================================================================
                Console.WriteLine($"IP-API: JSON deserialization error: {ex.Message}");
                Console.WriteLine($"IP-API: JSON path: {ex.Path}, Line: {ex.LineNumber}");
            }
            
            // ============================================================================
            // STEP 5: RESPONSE VALIDATION
            // ============================================================================
            // Check if the API call was successful by examining the "status" field
            // in the response. IP-API returns "success" for valid queries and
            // error messages for failed queries.
            // 
            // For Java developers: This is similar to checking response status codes
            // or custom response fields to determine if an API call succeeded.
            // ============================================================================
            if (ipInfo?.Status == "success")
            {
                Console.WriteLine($"IP-API: Success - Country: {ipInfo.Country}, City: {ipInfo.City}");
                return ipInfo;
            }
            else
            {
                Console.WriteLine($"IP-API: Failed - Status: '{ipInfo?.Status}'");
            }
        }
        catch (Exception ex)
        {
            // ============================================================================
            // GENERAL EXCEPTION HANDLING
            // ============================================================================
            // Catch any other exceptions that might occur during the API call,
            // such as network errors, timeout exceptions, or unexpected errors.
            // We log the error details for debugging purposes.
            // 
            // For Java developers: This is similar to catching general Exception
            // in Java and logging the error details.
            // ============================================================================
            Console.WriteLine($"IP-API: Error occurred: {ex.Message}");
            Console.WriteLine($"IP-API: Stack trace: {ex.StackTrace}");
        }
        
        // ============================================================================
        // FAILURE CASE - RETURN NULL
        // ============================================================================
        // If we reach this point, something went wrong with the API call.
        // Return null to indicate failure, which the calling code can handle
        // appropriately (e.g., by using cached data or providing a fallback).
        // 
        // For Java developers: This is similar to returning null or Optional.empty()
        // when an operation fails, allowing the caller to handle the failure case.
        // ============================================================================
        Console.WriteLine($"IP-API: Returning null for IP: {ipAddress}");
        return null;
    }

    /// <summary>
    /// Determines if an IP address is in a private range that should not be queried.
    /// 
    /// This method implements RFC 1918 private IP address detection and additional
    /// special-purpose ranges. Private IP addresses cannot provide meaningful
    /// geolocation information and should be skipped when making external API calls.
    /// 
    /// Private IP ranges according to RFC 1918:
    /// - 10.0.0.0/8 (10.0.0.0 to 10.255.255.255)
    /// - 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
    /// - 192.168.0.0/16 (192.168.0.0 to 192.168.255.255)
    /// 
    /// Additional special-purpose ranges:
    /// - 127.0.0.0/8 (127.0.0.0 to 127.255.255.255) - Loopback addresses
    /// - 169.254.0.0/16 (169.254.0.0 to 169.254.255.255) - Link-local addresses
    /// 
    /// For Java developers: This method demonstrates:
    /// - IP address parsing and validation
    /// - Byte array manipulation for IP address analysis
    /// - RFC compliance for network address classification
    /// 
    /// The equivalent Java code would use InetAddress.getByName() and
    /// getAddress() to get the byte array representation.
    /// </summary>
    /// <param name="ipAddress">The IP address string to check (IPv4 or IPv6)</param>
    /// <returns>true if the IP is private, false if it's public</returns>
    private bool IsPrivateIpAddress(string ipAddress)
    {
        // ============================================================================
        // STEP 1: IP ADDRESS VALIDATION
        // ============================================================================
        // First, validate that the input string is a valid IP address.
        // IPAddress.TryParse() returns false if the string cannot be parsed
        // as a valid IP address, and sets the 'ip' variable to null.
        // 
        // For Java developers: This is similar to using InetAddress.getByName()
        // and catching UnknownHostException if the address is invalid.
        // ============================================================================
        if (!System.Net.IPAddress.TryParse(ipAddress, out var ip))
            return false;

        // ============================================================================
        // STEP 2: GET IP ADDRESS BYTES
        // ============================================================================
        // Convert the IP address to its byte array representation.
        // IPv4 addresses are 4 bytes, IPv6 addresses are 16 bytes.
        // We'll use the byte array to check specific octet values.
        // 
        // For Java developers: This is equivalent to calling getAddress()
        // on an InetAddress object to get the byte array.
        // ============================================================================
        var bytes = ip.GetAddressBytes();
        
        // ============================================================================
        // STEP 3: CHECK PRIVATE IP RANGES
        // ============================================================================
        // Check each private IP range according to RFC 1918 and additional
        // special-purpose ranges. We check the most common ranges first
        // for performance optimization.
        // ============================================================================
        
        // ============================================================================
        // RFC 1918: 10.0.0.0/8 (Class A private network)
        // ============================================================================
        // This range covers 10.0.0.0 to 10.255.255.255
        // Only need to check the first octet (bytes[0]) since it's a /8 network
        // 
        // For Java developers: This is similar to checking if the first byte
        // of the IP address byte array equals 10.
        // ============================================================================
        if (bytes[0] == 10) return true;
        
        // ============================================================================
        // RFC 1918: 172.16.0.0/12 (Class B private network)
        // ============================================================================
        // This range covers 172.16.0.0 to 172.31.255.255
        // Need to check both first and second octets since it's a /12 network
        // 
        // For Java developers: This is similar to checking if the first byte
        // equals 172 AND the second byte is between 16 and 31 (inclusive).
        // ============================================================================
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        
        // ============================================================================
        // RFC 1918: 192.168.0.0/16 (Class C private network)
        // ============================================================================
        // This range covers 192.168.0.0 to 192.168.255.255
        // Need to check both first and second octets since it's a /16 network
        // 
        // For Java developers: This is similar to checking if the first byte
        // equals 192 AND the second byte equals 168.
        // ============================================================================
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        
        // ============================================================================
        // SPECIAL PURPOSE: 127.0.0.0/8 (Loopback addresses)
        // ============================================================================
        // This range covers 127.0.0.0 to 127.255.255.255
        // The most common loopback address is 127.0.0.1 (localhost)
        // Loopback addresses are used for internal communication and
        // cannot provide meaningful geolocation information.
        // ============================================================================
        if (bytes[0] == 127) return true;
        
        // ============================================================================
        // SPECIAL PURPOSE: 169.254.0.0/16 (Link-local addresses)
        // ============================================================================
        // This range covers 169.254.0.0 to 169.254.255.255
        // Link-local addresses are automatically assigned when DHCP fails
        // and are used for local network communication only.
        // ============================================================================
        if (bytes[0] == 169 && bytes[1] == 254) return true;

        // ============================================================================
        // PUBLIC IP ADDRESS
        // ============================================================================
        // If the IP address doesn't match any of the private ranges above,
        // it's considered a public IP address that can be queried for
        // geolocation information.
        // ============================================================================
        return false;
    }
}
