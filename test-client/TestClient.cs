using System.Text.Json;

namespace TestClient;

public class DeviceInfo
{
    public string DeviceName { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public DateTime LastUpdated { get; set; }
}

public class Program
{
    private static readonly HttpClient client = new HttpClient();
    private static readonly string baseUrl = "http://localhost:5000";

    public static async Task Main(string[] args)
    {
        Console.WriteLine("Device Info API Test Client");
        Console.WriteLine("============================");
        Console.WriteLine();

        try
        {
            // Test health endpoint
            await TestHealthEndpoint();

            // Test device info endpoint
            await TestDeviceInfoEndpoint();

            // Test async device info endpoint
            await TestAsyncDeviceInfoEndpoint();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            Console.WriteLine("Make sure the Device Info API is running on http://localhost:5000");
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    private static async Task TestHealthEndpoint()
    {
        Console.WriteLine("Testing Health Endpoint...");
        try
        {
            var response = await client.GetAsync($"{baseUrl}/api/health");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"✓ Health check successful: {content}");
            }
            else
            {
                Console.WriteLine($"✗ Health check failed: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Health check error: {ex.Message}");
        }
        Console.WriteLine();
    }

    private static async Task TestDeviceInfoEndpoint()
    {
        Console.WriteLine("Testing Device Info Endpoint...");
        try
        {
            var response = await client.GetAsync($"{baseUrl}/api/device-info");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var deviceInfo = JsonSerializer.Deserialize<DeviceInfo>(content);
                
                Console.WriteLine("✓ Device Info retrieved successfully:");
                Console.WriteLine($"  Device Name: {deviceInfo?.DeviceName}");
                Console.WriteLine($"  Device ID: {deviceInfo?.DeviceId}");
                Console.WriteLine($"  IP Address: {deviceInfo?.IpAddress}");
                Console.WriteLine($"  MAC Address: {deviceInfo?.MacAddress}");
                Console.WriteLine($"  Last Updated: {deviceInfo?.LastUpdated}");
            }
            else
            {
                Console.WriteLine($"✗ Device info request failed: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Device info error: {ex.Message}");
        }
        Console.WriteLine();
    }

    private static async Task TestAsyncDeviceInfoEndpoint()
    {
        Console.WriteLine("Testing Async Device Info Endpoint...");
        try
        {
            var response = await client.GetAsync($"{baseUrl}/api/device-info/async");
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var deviceInfo = JsonSerializer.Deserialize<DeviceInfo>(content);
                
                Console.WriteLine("✓ Async Device Info retrieved successfully:");
                Console.WriteLine($"  Device Name: {deviceInfo?.DeviceName}");
                Console.WriteLine($"  Device ID: {deviceInfo?.DeviceId}");
                Console.WriteLine($"  IP Address: {deviceInfo?.IpAddress}");
                Console.WriteLine($"  MAC Address: {deviceInfo?.MacAddress}");
                Console.WriteLine($"  Last Updated: {deviceInfo?.LastUpdated}");
            }
            else
            {
                Console.WriteLine($"✗ Async device info request failed: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Async device info error: {ex.Message}");
        }
        Console.WriteLine();
    }
}
