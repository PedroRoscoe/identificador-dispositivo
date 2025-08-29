using DeviceInfoAPI.Models;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DeviceInfoAPI.Services;

public class DeviceInfoService : IDeviceInfoService
{
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
            IpAddress = GetIpAddress(),
            MacAddress = GetMacAddress(),
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

    private string GetIpAddress()
    {
        try
        {
            // Get the first non-loopback IPv4 address
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ipAddress = host.AddressList
                .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip));

            if (ipAddress != null)
            {
                return ipAddress.ToString();
            }

            // Fallback: try to get from network interfaces
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up &&
                    networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var properties = networkInterface.GetIPProperties();
                    var ipv4Address = properties.UnicastAddresses
                        .FirstOrDefault(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (ipv4Address != null)
                    {
                        return ipv4Address.Address.ToString();
                    }
                }
            }
        }
        catch (Exception)
        {
            // Fallback to localhost
        }

        return "127.0.0.1";
    }

    private string GetMacAddress()
    {
        try
        {
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up &&
                    networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var macAddress = networkInterface.GetPhysicalAddress();
                    if (macAddress.GetAddressBytes().Length > 0)
                    {
                        return BitConverter.ToString(macAddress.GetAddressBytes()).Replace("-", ":");
                    }
                }
            }
        }
        catch (Exception)
        {
            // Fallback to empty string
        }

        return "00:00:00:00:00:00";
    }
}
