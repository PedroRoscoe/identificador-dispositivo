using DeviceInfoAPI.Services;

namespace DeviceInfoAPI.Models;

/// <summary>
/// Enhanced IP storage data that includes both the IP address and enriched location information.
/// This allows us to cache the IP-API response and avoid making unnecessary API calls
/// when the external IP hasn't changed.
/// </summary>
public class EnhancedIpStorage
{
    /// <summary>
    /// The external IP address that was stored.
    /// </summary>
    public string ExternalIpAddress { get; set; } = string.Empty;
    
    /// <summary>
    /// The timestamp when the external IP address was last updated.
    /// </summary>
    public DateTime LastUpdated { get; set; }
    
    /// <summary>
    /// The enriched location information from IP-API (encrypted for storage).
    /// This is cached to avoid repeated API calls for the same IP.
    /// </summary>
    public EncryptedLocationInfo? LocationInfo { get; set; }
    
    /// <summary>
    /// The hash of the IP address for quick change detection.
    /// This allows us to quickly determine if the IP has changed
    /// without making external API calls.
    /// </summary>
    public string IpHash { get; set; } = string.Empty;
    
    /// <summary>
    /// Indicates whether this data was encrypted when stored.
    /// This helps with backward compatibility and migration.
    /// </summary>
    public bool IsEncrypted { get; set; }
    
    /// <summary>
    /// Gets the decrypted location information as a regular IpLocationInfo object.
    /// This method should be called after the data has been decrypted.
    /// </summary>
    /// <param name="encryptionService">The encryption service to use for decryption</param>
    /// <returns>The decrypted location information, or null if not available</returns>
    public IpLocationInfo? GetDecryptedLocationInfo(IEncryptionService encryptionService)
    {
        if (LocationInfo == null) return null;
        
        try
        {
            var decryptedLocationInfo = new IpLocationInfo
            {
                Country = encryptionService.Decrypt(LocationInfo.Country),
                CountryCode = encryptionService.Decrypt(LocationInfo.CountryCode),
                Region = encryptionService.Decrypt(LocationInfo.Region),
                RegionName = encryptionService.Decrypt(LocationInfo.RegionName),
                City = encryptionService.Decrypt(LocationInfo.City),
                Zip = encryptionService.Decrypt(LocationInfo.Zip),
                Timezone = encryptionService.Decrypt(LocationInfo.Timezone),
                Isp = encryptionService.Decrypt(LocationInfo.Isp),
                Organization = encryptionService.Decrypt(LocationInfo.Organization),
                AsNumber = encryptionService.Decrypt(LocationInfo.AsNumber),
                Query = encryptionService.Decrypt(LocationInfo.Query),
                LastUpdated = LocationInfo.LastUpdated
            };
            
            // Decrypt and parse numeric coordinates
            if (double.TryParse(encryptionService.Decrypt(LocationInfo.Lat), out var lat))
                decryptedLocationInfo.Lat = lat;
            if (double.TryParse(encryptionService.Decrypt(LocationInfo.Lon), out var lon))
                decryptedLocationInfo.Lon = lon;
            
            return decryptedLocationInfo;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Encrypted location information for storage purposes.
/// This model stores all data as encrypted strings to ensure complete data protection.
/// </summary>
public class EncryptedLocationInfo
{
    public string Country { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string RegionName { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Zip { get; set; } = string.Empty;
    public string Lat { get; set; } = string.Empty;  // Encrypted string representation of double
    public string Lon { get; set; } = string.Empty;  // Encrypted string representation of double
    public string Timezone { get; set; } = string.Empty;
    public string Isp { get; set; } = string.Empty;
    public string Organization { get; set; } = string.Empty;
    public string AsNumber { get; set; } = string.Empty;
    public string Query { get; set; } = string.Empty;
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
}
