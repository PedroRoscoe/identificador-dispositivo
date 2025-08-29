using System.Text.Json;

namespace DeviceInfoAPI.Services;

public interface IIpStorageService
{
    Task<string?> GetLastKnownExternalIpAsync();
    Task SaveExternalIpAsync(string ipAddress);
    Task<DateTime?> GetLastUpdateTimeAsync();
}

public class IpStorageService : IIpStorageService
{
    private readonly string _storagePath;
    private readonly object _lockObject = new object();

    public IpStorageService()
    {
        // Store in user's app data folder
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appFolder = Path.Combine(appDataPath, "DeviceInfoAPI");
        
        // Create directory if it doesn't exist
        if (!Directory.Exists(appFolder))
        {
            Directory.CreateDirectory(appFolder);
        }
        
        _storagePath = Path.Combine(appFolder, "external_ip.json");
    }

    public async Task<string?> GetLastKnownExternalIpAsync()
    {
        try
        {
            if (!File.Exists(_storagePath))
                return null;

            lock (_lockObject)
            {
                var json = File.ReadAllText(_storagePath);
                var data = JsonSerializer.Deserialize<IpStorageData>(json);
                return data?.ExternalIpAddress;
            }
        }
        catch
        {
            return null;
        }
    }

    public async Task SaveExternalIpAsync(string ipAddress)
    {
        try
        {
            var data = new IpStorageData
            {
                ExternalIpAddress = ipAddress,
                LastUpdated = DateTime.UtcNow
            };

            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            });

            lock (_lockObject)
            {
                File.WriteAllText(_storagePath, json);
            }
        }
        catch
        {
            // Handle errors gracefully
        }
    }

    public async Task<DateTime?> GetLastUpdateTimeAsync()
    {
        try
        {
            if (!File.Exists(_storagePath))
                return null;

            lock (_lockObject)
            {
                var json = File.ReadAllText(_storagePath);
                var data = JsonSerializer.Deserialize<IpStorageData>(json);
                return data?.LastUpdated;
            }
        }
        catch
        {
            return null;
        }
    }

    private class IpStorageData
    {
        public string ExternalIpAddress { get; set; } = string.Empty;
        public DateTime LastUpdated { get; set; }
    }
}
