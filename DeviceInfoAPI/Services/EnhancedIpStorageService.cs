using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeviceInfoAPI.Models;

namespace DeviceInfoAPI.Services;

/// <summary>
/// Enhanced implementation of IP storage service with encryption and location data caching.
/// 
/// This service provides:
/// - Encrypted storage of IP addresses and location data
/// - Intelligent caching to avoid unnecessary IP-API calls
/// - Hash-based change detection for quick IP comparison
/// - Backward compatibility with existing unencrypted data
/// - Automatic migration to encrypted storage
/// </summary>
public class EnhancedIpStorageService : IEnhancedIpStorageService
{
    private readonly string _storagePath;
    private readonly object _lockObject = new object();
    private readonly IEncryptionService _encryptionService;
    private const string FileName = "enhanced_external_ip.json";

    public EnhancedIpStorageService(IEncryptionService encryptionService)
    {
        _encryptionService = encryptionService;
        
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appFolder = Path.Combine(appDataPath, "DeviceInfoAPI");
        
        if (!Directory.Exists(appFolder))
        {
            Directory.CreateDirectory(appFolder);
        }
        
        _storagePath = Path.Combine(appFolder, FileName);
    }

    public async Task<EnhancedIpStorage?> GetLastKnownExternalIpDataAsync()
    {
        try
        {
            if (!File.Exists(_storagePath))
                return null;

            lock (_lockObject)
            {
                var json = File.ReadAllText(_storagePath);
                var data = JsonSerializer.Deserialize<EnhancedIpStorage>(json);
                
                if (data != null && data.IsEncrypted)
                {
                    // Decrypt the data
                    data.ExternalIpAddress = _encryptionService.Decrypt(data.ExternalIpAddress);
                    // LocationInfo remains encrypted in storage, but can be decrypted on demand
                }
                
                return data;
            }
        }
        catch
        {
            return null;
        }
    }

    public async Task SaveExternalIpDataAsync(string ipAddress, IpLocationInfo? locationInfo)
    {
        try
        {
            var data = new EnhancedIpStorage
            {
                ExternalIpAddress = ipAddress,
                LastUpdated = DateTime.UtcNow,
                LocationInfo = null,
                IpHash = ComputeIpHash(ipAddress),
                IsEncrypted = true
            };

            // Encrypt sensitive data
            data.ExternalIpAddress = _encryptionService.Encrypt(data.ExternalIpAddress);
            
            if (locationInfo != null)
            {
                // Create encrypted location info
                data.LocationInfo = new EncryptedLocationInfo
                {
                    Country = _encryptionService.Encrypt(locationInfo.Country),
                    CountryCode = _encryptionService.Encrypt(locationInfo.CountryCode),
                    Region = _encryptionService.Encrypt(locationInfo.Region),
                    RegionName = _encryptionService.Encrypt(locationInfo.RegionName),
                    City = _encryptionService.Encrypt(locationInfo.City),
                    Zip = _encryptionService.Encrypt(locationInfo.Zip),
                    Lat = _encryptionService.Encrypt(locationInfo.Lat.ToString()),
                    Lon = _encryptionService.Encrypt(locationInfo.Lon.ToString()),
                    Timezone = _encryptionService.Encrypt(locationInfo.Timezone),
                    Isp = _encryptionService.Encrypt(locationInfo.Isp),
                    Organization = _encryptionService.Encrypt(locationInfo.Organization),
                    AsNumber = _encryptionService.Encrypt(locationInfo.AsNumber),
                    Query = _encryptionService.Encrypt(locationInfo.Query),
                    LastUpdated = locationInfo.LastUpdated
                };
            }

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

    public async Task<bool> IsStoredIpCurrentAsync(string currentIp)
    {
        try
        {
            var storedData = await GetLastKnownExternalIpDataAsync();
            if (storedData == null)
                return false;

            var currentHash = ComputeIpHash(currentIp);
            return storedData.IpHash == currentHash;
        }
        catch
        {
            return false;
        }
    }

    public async Task<DateTime?> GetLastUpdateTimeAsync()
    {
        try
        {
            var data = await GetLastKnownExternalIpDataAsync();
            return data?.LastUpdated;
        }
        catch
        {
            return null;
        }
    }

    public async Task MigrateToEncryptedStorageAsync()
    {
        try
        {
            // Check if old unencrypted file exists
            var oldFilePath = Path.Combine(
                Path.GetDirectoryName(_storagePath)!, 
                "external_ip.json"
            );

            if (!File.Exists(oldFilePath))
                return;

            // Read old data
            var oldJson = File.ReadAllText(oldFilePath);
            var oldData = JsonSerializer.Deserialize<JsonElement>(oldJson);

            if (oldData.ValueKind == JsonValueKind.Object)
            {
                // Extract IP address from old format
                string? oldIp = null;
                DateTime? oldTimestamp = null;

                if (oldData.TryGetProperty("ExternalIpAddress", out var ipProp))
                    oldIp = ipProp.GetString();
                if (oldData.TryGetProperty("LastUpdated", out var timeProp))
                    oldTimestamp = timeProp.GetDateTime();

                if (!string.IsNullOrEmpty(oldIp))
                {
                    // Store in new encrypted format
                    await SaveExternalIpDataAsync(oldIp, null);
                    
                    // Backup and remove old file
                    var backupPath = oldFilePath + ".backup";
                    File.Move(oldFilePath, backupPath);
                    
                    Console.WriteLine($"Migrated old IP data to encrypted storage. Backup saved to: {backupPath}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Migration failed: {ex.Message}");
        }
    }

    private string ComputeIpHash(string ipAddress)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(ipAddress);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }
}
