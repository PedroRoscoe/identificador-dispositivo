// ============================================================================
// IpStorageService.cs - Persistent storage for external IP addresses
// ============================================================================
// This service manages the persistent storage of external IP addresses
// to enable VPN-aware IP detection. It stores the last known external IP
// when not connected to a VPN, allowing the application to provide
// the "real" internet IP even when connected to a VPN.
//
// For Java developers: This is similar to a service that manages file-based
// persistence or uses a simple database to store configuration data.
// The file operations are equivalent to Java's File, FileReader, and FileWriter.
// ============================================================================

using System.Text.Json;  // JSON serialization/deserialization
using System.IO;          // File and directory operations

/// <summary>
/// Interface for the IP storage service that manages external IP address persistence.
/// 
/// This interface defines the contract for storing and retrieving external IP addresses
/// with timestamps. It enables the application to remember the "real" internet IP
/// address even when connected to a VPN.
/// 
/// For Java developers: This is similar to defining a service interface in Spring Boot
/// that other components can depend on through dependency injection.
/// </summary>
public interface IIpStorageService
{
    /// <summary>
    /// Retrieves the last known external IP address from persistent storage.
    /// </summary>
    /// <returns>The stored external IP address, or null if none exists</returns>
    Task<string?> GetLastKnownExternalIpAsync();
    
    /// <summary>
    /// Saves an external IP address to persistent storage with the current timestamp.
    /// </summary>
    /// <param name="ipAddress">The external IP address to store</param>
    Task SaveExternalIpAsync(string ipAddress);
    
    /// <summary>
    /// Retrieves the timestamp when the external IP was last updated.
    /// </summary>
    /// <returns>The last update timestamp, or null if no IP is stored</returns>
    Task<DateTime?> GetLastUpdateTimeAsync();
}

/// <summary>
/// Implementation of the IP storage service that persists external IP addresses to a JSON file.
/// 
/// This service stores external IP addresses in the user's AppData folder to ensure
/// persistence across application restarts and system reboots. It uses file-based
/// storage with JSON serialization for simplicity and human readability.
/// 
/// For Java developers: This class is similar to a service implementation in Spring Boot
/// that handles file I/O operations and data persistence.
/// 
/// Storage Strategy:
/// - Location: %APPDATA%\DeviceInfoAPI\external_ip.json
/// - Format: JSON with IP address and timestamp
/// - Thread Safety: Uses locks to prevent concurrent access issues
/// </summary>
public class IpStorageService : IIpStorageService
{
    // ============================================================================
    // PRIVATE FIELDS
    // ============================================================================
    
    /// <summary>
    /// Full path to the JSON file where external IP addresses are stored.
    /// This is constructed in the constructor to point to the user's AppData folder.
    /// </summary>
    private readonly string _storagePath;
    
    /// <summary>
    /// Lock object for thread-safe file operations.
    /// Prevents multiple threads from simultaneously reading/writing the storage file,
    /// which could cause data corruption or race conditions.
    /// 
    /// For Java developers: This is similar to using synchronized blocks or
    /// ReentrantLock for thread-safe file operations.
    /// </summary>
    private readonly object _lockObject = new object();

    /// <summary>
    /// Constructor for IpStorageService.
    /// 
    /// Initializes the storage path and ensures the storage directory exists.
    /// The service stores data in the user's AppData folder, which is the standard
    /// Windows location for application data and survives system restarts.
    /// 
    /// For Java developers: This is similar to initializing file paths and
    /// creating directories in a service constructor.
    /// </summary>
    public IpStorageService()
    {
        // ============================================================================
        // STORAGE PATH CONSTRUCTION
        // ============================================================================
        // Get the user's AppData folder path. This is the standard Windows location
        // for application data and is accessible without administrator privileges.
        // 
        // For Java developers: This is similar to using System.getProperty("user.home")
        // to get the user's home directory.
        // ============================================================================
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        
        // ============================================================================
        // APPLICATION-SPECIFIC FOLDER
        // ============================================================================
        // Create a subfolder specifically for our application to avoid conflicts
        // with other applications. This follows Windows application design guidelines.
        // ============================================================================
        var appFolder = Path.Combine(appDataPath, "DeviceInfoAPI");
        
        // ============================================================================
        // DIRECTORY CREATION
        // ============================================================================
        // Ensure the storage directory exists. If it doesn't exist, create it.
        // This prevents FileNotFound exceptions when trying to write the storage file.
        // 
        // For Java developers: This is similar to checking if a directory exists
        // and creating it if necessary using File.mkdirs().
        // ============================================================================
        if (!Directory.Exists(appFolder))
        {
            Directory.CreateDirectory(appFolder);
        }
        
        // ============================================================================
        // STORAGE FILE PATH
        // ============================================================================
        // Construct the full path to the JSON file where we'll store the IP data.
        // The file will be created automatically when we first write to it.
        // ============================================================================
        _storagePath = Path.Combine(appFolder, "external_ip.json");
    }

    /// <summary>
    /// Retrieves the last known external IP address from persistent storage.
    /// 
    /// This method reads the JSON storage file and extracts the stored external IP address.
    /// It uses thread-safe file operations to prevent concurrent access issues.
    /// 
    /// For Java developers: This is similar to reading a configuration file
    /// and parsing its contents, with proper exception handling.
    /// 
    /// Return values:
    /// - The stored external IP address if available
    /// - null if no IP is stored or if an error occurs
    /// </summary>
    /// <returns>The stored external IP address, or null if none exists</returns>
    public async Task<string?> GetLastKnownExternalIpAsync()
    {
        try
        {
            // ============================================================================
            // FILE EXISTENCE CHECK
            // ============================================================================
            // Check if the storage file exists before attempting to read it.
            // If the file doesn't exist, it means no external IP has been stored yet.
            // 
            // For Java developers: This is similar to checking File.exists() before
            // attempting to read a file.
            // ============================================================================
            if (!File.Exists(_storagePath))
                return null;

            // ============================================================================
            // THREAD-SAFE FILE READING
            // ============================================================================
            // Use a lock to ensure only one thread can read the file at a time.
            // This prevents race conditions and ensures data consistency.
            // 
            // For Java developers: This is similar to using synchronized blocks
            // or ReentrantLock for thread-safe file operations.
            // ============================================================================
            lock (_lockObject)
            {
                // ============================================================================
                // FILE READING AND DESERIALIZATION
                // ============================================================================
                // Read the entire file content as a string and deserialize it to
                // an IpStorageData object. This gives us access to the stored IP
                // address and timestamp.
                // 
                // For Java developers: This is similar to using FileReader to read
                // a file and Jackson ObjectMapper to deserialize JSON.
                // ============================================================================
                var json = File.ReadAllText(_storagePath);
                var data = JsonSerializer.Deserialize<IpStorageData>(json);
                return data?.ExternalIpAddress;
            }
        }
        catch
        {
            // ============================================================================
            // EXCEPTION HANDLING - Graceful degradation
            // ============================================================================
            // If any error occurs during file reading or JSON deserialization,
            // return null instead of throwing an exception. This ensures the
            // application continues to function even if the storage is corrupted.
            // 
            // For Java developers: This is similar to catching exceptions in
            // file operations and returning a default value.
            // ============================================================================
            return null;
        }
    }

    /// <summary>
    /// Saves an external IP address to persistent storage with the current timestamp.
    /// 
    /// This method creates or updates the storage file with the new external IP address
    /// and current UTC timestamp. It uses thread-safe file operations to prevent
    /// concurrent access issues.
    /// 
    /// For Java developers: This is similar to writing configuration data to a file
    /// with proper exception handling and thread safety.
    /// 
    /// The stored data includes:
    /// - External IP address (the parameter passed to this method)
    /// - Last updated timestamp (current UTC time)
    /// </summary>
    /// <param name="ipAddress">The external IP address to store</param>
    public async Task SaveExternalIpAsync(string ipAddress)
    {
        try
        {
            // ============================================================================
            // DATA OBJECT CREATION
            // ============================================================================
            // Create a new IpStorageData object with the IP address and current timestamp.
            // We use UTC time to ensure consistency across different time zones.
            // 
            // For Java developers: This is similar to creating a DTO or entity object
            // and setting its properties before persistence.
            // ============================================================================
            var data = new IpStorageData
            {
                ExternalIpAddress = ipAddress,        // Store the provided IP address
                LastUpdated = DateTime.UtcNow         // Store current UTC timestamp
            };

            // ============================================================================
            // JSON SERIALIZATION
            // ============================================================================
            // Convert the data object to a JSON string. We use WriteIndented = true
            // to make the JSON file human-readable for debugging purposes.
            // 
            // For Java developers: This is similar to using Jackson ObjectMapper
            // with pretty printing enabled for readable JSON output.
            // ============================================================================
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions 
            { 
                WriteIndented = true  // Format JSON with indentation for readability
            });

            // ============================================================================
            // THREAD-SAFE FILE WRITING
            // ============================================================================
            // Use a lock to ensure only one thread can write to the file at a time.
            // This prevents data corruption from concurrent writes.
            // 
            // For Java developers: This is similar to using synchronized blocks
            // or ReentrantLock for thread-safe file operations.
            // ============================================================================
            lock (_lockObject)
            {
                // ============================================================================
                // FILE WRITING
                // ============================================================================
                // Write the JSON string to the storage file. If the file doesn't exist,
                // it will be created automatically. If it exists, it will be overwritten.
                // 
                // For Java developers: This is similar to using FileWriter or
                // Files.write() to write content to a file.
                // ============================================================================
                File.WriteAllText(_storagePath, json);
            }
        }
        catch
        {
            // ============================================================================
            // EXCEPTION HANDLING - Silent failure
            // ============================================================================
            // If any error occurs during data creation, serialization, or file writing,
            // we silently catch the exception to prevent the application from crashing.
            // 
            // In production, you might want to log this error for debugging purposes.
            // 
            // For Java developers: This is similar to catching exceptions in
            // file operations and handling them gracefully without exposing
            // internal errors to the caller.
            // ============================================================================
            // Handle errors gracefully
        }
    }

    /// <summary>
    /// Retrieves the timestamp when the external IP was last updated.
    /// 
    /// This method reads the storage file and extracts the LastUpdated timestamp
    /// from the stored data. It's useful for displaying how long ago the IP
    /// was last updated (e.g., "15 minutes ago").
    /// 
    /// For Java developers: This is similar to reading metadata from a
    /// configuration file or database record.
    /// 
    /// Return values:
    /// - The last update timestamp if available
    /// - null if no timestamp is stored or if an error occurs
    /// </summary>
    /// <returns>The last update timestamp, or null if none exists</returns>
    public async Task<DateTime?> GetLastUpdateTimeAsync()
    {
        try
        {
            // ============================================================================
            // FILE EXISTENCE CHECK
            // ============================================================================
            // Check if the storage file exists before attempting to read it.
            // If the file doesn't exist, it means no external IP has been stored yet.
            // 
            // For Java developers: This is similar to checking File.exists() before
            // attempting to read a file.
            // ============================================================================
            if (!File.Exists(_storagePath))
                return null;

            // ============================================================================
            // THREAD-SAFE FILE READING
            // ============================================================================
            // Use a lock to ensure only one thread can read the file at a time.
            // This prevents race conditions and ensures data consistency.
            // 
            // For Java developers: This is similar to using synchronized blocks
            // or ReentrantLock for thread-safe file operations.
            // ============================================================================
            lock (_lockObject)
            {
                // ============================================================================
                // FILE READING AND DESERIALIZATION
                // ============================================================================
                // Read the entire file content as a string and deserialize it to
                // an IpStorageData object. We then extract the LastUpdated timestamp
                // from the deserialized data.
                // 
                // For Java developers: This is similar to using FileReader to read
                // a file and Jackson ObjectMapper to deserialize JSON.
                // ============================================================================
                var json = File.ReadAllText(_storagePath);
                var data = JsonSerializer.Deserialize<IpStorageData>(json);
                return data?.LastUpdated;  // Return the timestamp from the stored data
            }
        }
        catch
        {
            // ============================================================================
            // EXCEPTION HANDLING - Graceful degradation
            // ============================================================================
            // If any error occurs during file reading or JSON deserialization,
            // return null instead of throwing an exception. This ensures the
            // application continues to function even if the storage is corrupted.
            // 
            // For Java developers: This is similar to catching exceptions in
            // file operations and returning a default value.
            // ============================================================================
            return null;
        }
    }

    /// <summary>
    /// Private data class for storing external IP address information.
    /// 
    /// This class represents the structure of the data stored in the JSON file.
    /// It contains the external IP address and the timestamp when it was last updated.
    /// 
    /// For Java developers: This is similar to a private inner class or a DTO
    /// (Data Transfer Object) that represents the structure of stored data.
    /// 
    /// The class is marked as private because it's only used internally
    /// within this service and doesn't need to be exposed to other components.
    /// </summary>
    private class IpStorageData
    {
        /// <summary>
        /// The external IP address that was stored.
        /// 
        /// This is the "real" internet IP address that was detected when
        /// the system was not connected to a VPN. It's stored as a string
        /// to maintain flexibility with different IP address formats.
        /// 
        /// For Java developers: This is similar to a private field with
        /// getter and setter methods, but C# properties provide this
        /// functionality more concisely.
        /// </summary>
        public string ExternalIpAddress { get; set; } = string.Empty;
        
        /// <summary>
        /// The timestamp when the external IP address was last updated.
        /// 
        /// This timestamp is stored in UTC to ensure consistency across
        /// different time zones and daylight saving time changes.
        /// 
        /// For Java developers: This is similar to storing a Date or
        /// LocalDateTime object in Java, but C# uses DateTime for
        /// both date and time representation.
        /// </summary>
        public DateTime LastUpdated { get; set; }
    }
}
