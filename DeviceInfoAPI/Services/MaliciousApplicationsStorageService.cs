using DeviceInfoAPI.Models;
using System.Text.Json;

namespace DeviceInfoAPI.Services;

public class MaliciousApplicationsStorageService : IMaliciousApplicationsStorageService
{
    private readonly string _dataFilePath;
    private readonly IEncryptionService _encryptionService;
    private MaliciousApplicationsData? _cachedData;
    private readonly object _lock = new object();

    public MaliciousApplicationsStorageService(IEncryptionService encryptionService)
    {
        _encryptionService = encryptionService;
        _dataFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data", "MaliciousApplications.encrypted");
        
        // Ensure the Data directory exists
        var dataDir = Path.GetDirectoryName(_dataFilePath);
        if (!Directory.Exists(dataDir))
        {
            Directory.CreateDirectory(dataDir!);
        }
    }

    public async Task<MaliciousApplicationsData> LoadDataAsync()
    {
        lock (_lock)
        {
            if (_cachedData != null)
                return _cachedData;
        }

        try
        {
            if (!File.Exists(_dataFilePath))
            {
                var defaultData = new MaliciousApplicationsData
                {
                    Categories = new Dictionary<string, MaliciousApplicationsCategory>(),
                    LastUpdated = DateTime.UtcNow,
                    Version = "1.0"
                };
                
                lock (_lock)
                {
                    _cachedData = defaultData;
                }
                return defaultData;
            }

            var encryptedContent = await File.ReadAllTextAsync(_dataFilePath);
            var decryptedJson = _encryptionService.Decrypt(encryptedContent);
            var data = JsonSerializer.Deserialize<MaliciousApplicationsData>(decryptedJson);

            if (data == null)
            {
                throw new InvalidOperationException("Failed to deserialize malicious applications data");
            }

            lock (_lock)
            {
                _cachedData = data;
            }

            return data;
        }
        catch (Exception ex)
        {
            // Return default data if loading fails
            var defaultData = new MaliciousApplicationsData
            {
                Categories = new Dictionary<string, MaliciousApplicationsCategory>(),
                LastUpdated = DateTime.UtcNow,
                Version = "1.0"
            };
            
            lock (_lock)
            {
                _cachedData = defaultData;
            }
            return defaultData;
        }
    }

    public async Task SaveDataAsync(MaliciousApplicationsData data)
    {
        try
        {
            data.LastUpdated = DateTime.UtcNow;
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            var encryptedContent = _encryptionService.Encrypt(json);
            
            await File.WriteAllTextAsync(_dataFilePath, encryptedContent);
            
            lock (_lock)
            {
                _cachedData = data;
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to save malicious applications data: {ex.Message}", ex);
        }
    }

    public async Task<bool> AddApplicationAsync(string category, MaliciousApplicationDefinition application)
    {
        var data = await LoadDataAsync();
        
        if (!data.Categories.ContainsKey(category))
        {
            data.Categories[category] = new MaliciousApplicationsCategory
            {
                Category = category,
                Description = $"Category for {category}",
                Applications = new List<MaliciousApplicationDefinition>()
            };
        }

        // Check if application already exists
        if (data.Categories[category].Applications.Any(app => app.Name.Equals(application.Name, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        data.Categories[category].Applications.Add(application);
        await SaveDataAsync(data);
        return true;
    }

    public async Task<bool> RemoveApplicationAsync(string category, string applicationName)
    {
        var data = await LoadDataAsync();
        
        if (!data.Categories.ContainsKey(category))
        {
            return false;
        }

        var application = data.Categories[category].Applications.FirstOrDefault(app => 
            app.Name.Equals(applicationName, StringComparison.OrdinalIgnoreCase));
        
        if (application == null)
        {
            return false;
        }

        data.Categories[category].Applications.Remove(application);
        
        // Remove category if empty
        if (data.Categories[category].Applications.Count == 0)
        {
            data.Categories.Remove(category);
        }

        await SaveDataAsync(data);
        return true;
    }

    public async Task<bool> UpdateApplicationAsync(string category, string applicationName, MaliciousApplicationDefinition updatedApplication)
    {
        var data = await LoadDataAsync();
        
        if (!data.Categories.ContainsKey(category))
        {
            return false;
        }

        var index = data.Categories[category].Applications.FindIndex(app => 
            app.Name.Equals(applicationName, StringComparison.OrdinalIgnoreCase));
        
        if (index == -1)
        {
            return false;
        }

        data.Categories[category].Applications[index] = updatedApplication;
        await SaveDataAsync(data);
        return true;
    }

    public async Task<MaliciousApplicationDefinition?> GetApplicationAsync(string category, string applicationName)
    {
        var data = await LoadDataAsync();
        
        if (!data.Categories.ContainsKey(category))
        {
            return null;
        }

        return data.Categories[category].Applications.FirstOrDefault(app => 
            app.Name.Equals(applicationName, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<List<MaliciousApplicationDefinition>> GetApplicationsByCategoryAsync(string category)
    {
        var data = await LoadDataAsync();
        
        if (!data.Categories.ContainsKey(category))
        {
            return new List<MaliciousApplicationDefinition>();
        }

        return new List<MaliciousApplicationDefinition>(data.Categories[category].Applications);
    }

    public async Task<List<string>> GetCategoriesAsync()
    {
        var data = await LoadDataAsync();
        return new List<string>(data.Categories.Keys);
    }

    public async Task<bool> CategoryExistsAsync(string category)
    {
        var data = await LoadDataAsync();
        return data.Categories.ContainsKey(category);
    }

    public async Task<bool> ApplicationExistsAsync(string category, string applicationName)
    {
        var data = await LoadDataAsync();
        
        if (!data.Categories.ContainsKey(category))
        {
            return false;
        }

        return data.Categories[category].Applications.Any(app => 
            app.Name.Equals(applicationName, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<int> GetTotalApplicationsCountAsync()
    {
        var data = await LoadDataAsync();
        return data.Categories.Values.Sum(category => category.Applications.Count);
    }

    public async Task<Dictionary<string, int>> GetApplicationsCountByCategoryAsync()
    {
        var data = await LoadDataAsync();
        return data.Categories.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Applications.Count);
    }
}
