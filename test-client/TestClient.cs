using System.Text.Json;

namespace TestClient;

public class DeviceInfo
{
    public string DeviceName { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
    public string ExternalIpAddress { get; set; } = string.Empty;
    public List<NetworkInterface> NetworkInterfaces { get; set; } = new();
    public DateTime LastUpdated { get; set; }
}

public class NetworkInterface
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public List<NetworkAddress> Addresses { get; set; } = new();
    public bool IsActive { get; set; }
}

public class NetworkAddress
{
    public string IpAddress { get; set; } = string.Empty;
    public string AddressFamily { get; set; } = string.Empty;
    public string SubnetMask { get; set; } = string.Empty;
    public string Gateway { get; set; } = string.Empty;
    public string DnsServers { get; set; } = string.Empty;
    public string IpType { get; set; } = string.Empty;
    public string IpTypeDescription { get; set; } = string.Empty;
    public bool IsVpnGateway { get; set; }
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
                Console.WriteLine($"  External IP: {deviceInfo?.ExternalIpAddress}");
                Console.WriteLine($"  Network Interfaces: {deviceInfo?.NetworkInterfaces.Count ?? 0}");
                Console.WriteLine($"  Last Updated: {deviceInfo?.LastUpdated}");
                
                if (deviceInfo?.NetworkInterfaces != null)
                {
                    Console.WriteLine("\n  Network Interfaces:");
                    foreach (var nic in deviceInfo.NetworkInterfaces)
                    {
                        Console.WriteLine($"    {nic.Name} ({nic.Type}) - {nic.Status}");
                        Console.WriteLine($"      MAC: {nic.MacAddress}");
                        Console.WriteLine($"      Active: {nic.IsActive}");
                        
                        if (nic.Addresses.Any())
                        {
                            Console.WriteLine("      Addresses:");
                            foreach (var addr in nic.Addresses)
                            {
                                var vpnIndicator = addr.IsVpnGateway ? " [VPN Gateway]" : "";
                                Console.WriteLine($"        {addr.IpAddress} ({addr.AddressFamily}) - {addr.IpTypeDescription}{vpnIndicator}");
                                if (!string.IsNullOrEmpty(addr.SubnetMask))
                                    Console.WriteLine($"          Subnet: {addr.SubnetMask}");
                                if (!string.IsNullOrEmpty(addr.Gateway))
                                    Console.WriteLine($"          Gateway: {addr.Gateway}");
                                if (!string.IsNullOrEmpty(addr.DnsServers))
                                    Console.WriteLine($"          DNS: {addr.DnsServers}");
                            }
                        }
                        Console.WriteLine();
                    }
                }
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
                Console.WriteLine($"  External IP: {deviceInfo?.ExternalIpAddress}");
                Console.WriteLine($"  Network Interfaces: {deviceInfo?.NetworkInterfaces.Count ?? 0}");
                Console.WriteLine($"  Last Updated: {deviceInfo?.LastUpdated}");
                
                if (deviceInfo?.NetworkInterfaces != null)
                {
                    Console.WriteLine("\n  Network Interfaces:");
                    foreach (var nic in deviceInfo.NetworkInterfaces)
                    {
                        Console.WriteLine($"    {nic.Name} ({nic.Type}) - {nic.Status}");
                        Console.WriteLine($"      MAC: {nic.MacAddress}");
                        Console.WriteLine($"      Active: {nic.IsActive}");
                        
                        if (nic.Addresses.Any())
                        {
                            Console.WriteLine("      Addresses:");
                            foreach (var addr in nic.Addresses)
                            {
                                var vpnIndicator = addr.IsVpnGateway ? " [VPN Gateway]" : "";
                                Console.WriteLine($"        {addr.IpAddress} ({addr.AddressFamily}) - {addr.IpTypeDescription}{vpnIndicator}");
                                if (!string.IsNullOrEmpty(addr.SubnetMask))
                                    Console.WriteLine($"          Subnet: {addr.SubnetMask}");
                                if (!string.IsNullOrEmpty(addr.Gateway))
                                    Console.WriteLine($"          Gateway: {addr.Gateway}");
                                if (!string.IsNullOrEmpty(addr.DnsServers))
                                    Console.WriteLine($"          DNS: {addr.DnsServers}");
                            }
                        }
                        Console.WriteLine();
                    }
                }
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
