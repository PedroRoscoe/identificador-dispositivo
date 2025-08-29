namespace DeviceInfoAPI.Models;

public class DeviceInfo
{
    public string DeviceName { get; set; } = string.Empty;
    public string DeviceId { get; set; } = string.Empty;
    public string ExternalIpAddress { get; set; } = string.Empty;
    public IpLocationInfo? IpLocationInfo { get; set; }
    public List<NetworkInterface> NetworkInterfaces { get; set; } = new();
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
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
    public IpAddressType IpType { get; set; }
    public string IpTypeDescription { get; set; } = string.Empty;
    public bool IsVpnGateway { get; set; }
}

public enum IpAddressType
{
    Internal,
    External,
    VPN,
    Loopback,
    LinkLocal,
    Unknown
}

public class IpLocationInfo
{
    public string Country { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string RegionName { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Zip { get; set; } = string.Empty;
    public double Lat { get; set; }
    public double Lon { get; set; }
    public string Timezone { get; set; } = string.Empty;
    public string Isp { get; set; } = string.Empty;
    public string Organization { get; set; } = string.Empty;
    public string AsNumber { get; set; } = string.Empty;
    public string Query { get; set; } = string.Empty;
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
}
