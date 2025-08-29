using DeviceInfoAPI.Models;

namespace DeviceInfoAPI.Services;

/// <summary>
/// Enhanced interface for IP storage service that includes location data caching.
/// 
/// This interface extends the basic IP storage functionality to include:
/// - Storage of enriched location information from IP-API
/// - Intelligent caching to avoid unnecessary API calls
/// - Hash-based change detection for quick IP comparison
/// - Encrypted storage for data security
/// 
/// For Java developers: This is similar to extending a service interface in Spring Boot
/// to add new functionality while maintaining backward compatibility.
/// </summary>
public interface IEnhancedIpStorageService
{
    /// <summary>
    /// Retrieves the last known external IP address and location information.
    /// </summary>
    /// <returns>The stored external IP data, or null if none exists</returns>
    Task<EnhancedIpStorage?> GetLastKnownExternalIpDataAsync();
    
    /// <summary>
    /// Saves external IP address and location information to persistent storage.
    /// </summary>
    /// <param name="ipAddress">The external IP address to store</param>
    /// <param name="locationInfo">The enriched location information from IP-API</param>
    Task SaveExternalIpDataAsync(string ipAddress, IpLocationInfo? locationInfo);
    
    /// <summary>
    /// Checks if the stored IP address is still current.
    /// </summary>
    /// <param name="currentIp">The current external IP address to check</param>
    /// <returns>true if the stored IP is current, false if it has changed</returns>
    Task<bool> IsStoredIpCurrentAsync(string currentIp);
    
    /// <summary>
    /// Retrieves the timestamp when the external IP was last updated.
    /// </summary>
    /// <returns>The last update timestamp, or null if no IP is stored</returns>
    Task<DateTime?> GetLastUpdateTimeAsync();
    
    /// <summary>
    /// Migrates existing unencrypted data to encrypted format.
    /// This ensures backward compatibility while improving security.
    /// </summary>
    Task MigrateToEncryptedStorageAsync();
}
