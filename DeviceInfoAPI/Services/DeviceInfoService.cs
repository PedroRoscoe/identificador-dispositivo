using DeviceInfoAPI.Models;
using System.Management;
using System.Net;
using SystemNetNetworkInterface = System.Net.NetworkInformation.NetworkInterface;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace DeviceInfoAPI.Services;

public class DeviceInfoService : IDeviceInfoService
{
    private readonly HttpClient _httpClient;
    private readonly IIpStorageService _ipStorageService;

    public DeviceInfoService(IIpStorageService ipStorageService)
    {
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        _ipStorageService = ipStorageService;
    }

    public async Task<DeviceInfo> GetDeviceInfoAsync()
    {
        return await Task.Run(() => GetDeviceInfo());
    }

    public DeviceInfo GetDeviceInfo()
    {
        return new DeviceInfo
        {
            DeviceName = GetDeviceName(),
            DeviceId = GetDeviceId(),
            NetworkInterfaces = GetNetworkInterfaces(),
            ExternalIpAddress = GetExternalIpAddress(),
            LastUpdated = DateTime.UtcNow
        };
    }

    private string GetDeviceName()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_ComputerSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["Name"]?.ToString() ?? Environment.MachineName;
            }
        }
        catch (Exception)
        {
            // Fallback to environment variable
        }
        
        return Environment.MachineName;
    }

    private string GetDeviceId()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject obj in searcher.Get())
            {
                var uuid = obj["UUID"]?.ToString();
                if (!string.IsNullOrEmpty(uuid))
                {
                    return uuid;
                }
            }
        }
        catch (Exception)
        {
            // Fallback to machine name hash
        }

        // Fallback: generate a hash from machine name
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Environment.MachineName))
            .Replace("/", "_")
            .Replace("+", "-")
            .Replace("=", "")
            .Substring(0, Math.Min(16, Environment.MachineName.Length));
    }

    private List<Models.NetworkInterface> GetNetworkInterfaces()
    {
        var networkInterfaces = new List<Models.NetworkInterface>();
        
        try
        {
            var interfaces = SystemNetNetworkInterface.GetAllNetworkInterfaces();
            
            foreach (var nic in interfaces)
            {
                // Only process active interfaces
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                var addresses = GetNetworkAddresses(nic);
                
                // Only add interfaces that have valid IP addresses
                if (addresses.Any(addr => IsValidIpAddress(addr.IpAddress)))
                {
                    var networkInterface = new Models.NetworkInterface
                    {
                        Name = nic.Name,
                        Description = nic.Description,
                        Type = nic.NetworkInterfaceType.ToString(),
                        Status = nic.OperationalStatus.ToString(),
                        MacAddress = FormatMacAddress(nic.GetPhysicalAddress()),
                        IsActive = true,
                        Addresses = addresses.Where(addr => IsValidIpAddress(addr.IpAddress)).ToList()
                    };

                    networkInterfaces.Add(networkInterface);
                }
            }
        }
        catch (Exception)
        {
            // Fallback: create a basic interface with localhost
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
                        IpAddress = "127.0.0.1",
                        AddressFamily = "IPv4",
                        SubnetMask = "255.0.0.0",
                        Gateway = "",
                        DnsServers = "",
                        IpType = IpAddressType.Loopback,
                        IpTypeDescription = "Loopback address"
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

    private string GetExternalIpAddress()
    {
        try
        {
            // Check if we're on a VPN
            var isOnVpn = IsOnVpn();
            
            if (isOnVpn)
            {
                // If on VPN, return the stored external IP with timestamp
                var storedIp = _ipStorageService.GetLastKnownExternalIpAsync().Result;
                var lastUpdate = _ipStorageService.GetLastUpdateTimeAsync().Result;
                
                if (!string.IsNullOrEmpty(storedIp))
                {
                    var timeAgo = lastUpdate.HasValue ? GetTimeAgo(lastUpdate.Value) : "Unknown";
                    return $"{storedIp} (Stored - Last Updated: {timeAgo})";
                }
                else
                {
                    return "No stored external IP available (VPN Active)";
                }
            }
            else
            {
                // Not on VPN, get current external IP and store it
                var currentIp = GetCurrentExternalIp();
                
                if (!string.IsNullOrEmpty(currentIp) && currentIp != "Unable to determine")
                {
                    // Store the current IP for future use
                    _ipStorageService.SaveExternalIpAsync(currentIp).Wait();
                    return currentIp + " (Current - Stored for VPN use)";
                }
                else
                {
                    // Try to return stored IP as fallback
                    var storedIp = _ipStorageService.GetLastKnownExternalIpAsync().Result;
                    if (!string.IsNullOrEmpty(storedIp))
                    {
                        var lastUpdate = _ipStorageService.GetLastUpdateTimeAsync().Result;
                        var timeAgo = lastUpdate.HasValue ? GetTimeAgo(lastUpdate.Value) : "Unknown";
                        return $"{storedIp} (Stored - Last Updated: {timeAgo})";
                    }
                    
                    return "Unable to determine external IP";
                }
            }
        }
        catch
        {
            // Fallback to stored IP if available
            try
            {
                var storedIp = _ipStorageService.GetLastKnownExternalIpAsync().Result;
                if (!string.IsNullOrEmpty(storedIp))
                {
                    var lastUpdate = _ipStorageService.GetLastUpdateTimeAsync().Result;
                    var timeAgo = lastUpdate.HasValue ? GetTimeAgo(lastUpdate.Value) : "Unknown";
                    return $"{storedIp} (Stored - Last Updated: {timeAgo})";
                }
            }
            catch
            {
                // Ignore errors
            }
            
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
