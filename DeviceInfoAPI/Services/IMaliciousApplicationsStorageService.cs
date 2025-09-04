using DeviceInfoAPI.Models;

namespace DeviceInfoAPI.Services;

public interface IMaliciousApplicationsStorageService
{
    Task<MaliciousApplicationsData> LoadDataAsync();
    Task SaveDataAsync(MaliciousApplicationsData data);
    Task<bool> AddApplicationAsync(string category, MaliciousApplicationDefinition application);
    Task<bool> RemoveApplicationAsync(string category, string applicationName);
    Task<bool> UpdateApplicationAsync(string category, string applicationName, MaliciousApplicationDefinition updatedApplication);
    Task<MaliciousApplicationDefinition?> GetApplicationAsync(string category, string applicationName);
    Task<List<MaliciousApplicationDefinition>> GetApplicationsByCategoryAsync(string category);
    Task<List<string>> GetCategoriesAsync();
    Task<bool> CategoryExistsAsync(string category);
    Task<bool> ApplicationExistsAsync(string category, string applicationName);
    Task<int> GetTotalApplicationsCountAsync();
    Task<Dictionary<string, int>> GetApplicationsCountByCategoryAsync();
}

