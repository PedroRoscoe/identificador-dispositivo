using System.Text.Json;
using DeviceInfoAPI.Models;
using Microsoft.Extensions.Logging;

namespace DeviceInfoAPI.Services;

public class MaliciousApplicationsMigrationService
{
    private readonly IMaliciousApplicationsStorageService _storageService;
    private readonly ILogger<MaliciousApplicationsMigrationService> _logger;
    private readonly string _jsonFilePath;

    public MaliciousApplicationsMigrationService(
        IMaliciousApplicationsStorageService storageService,
        ILogger<MaliciousApplicationsMigrationService> logger)
    {
        _storageService = storageService;
        _logger = logger;
        _jsonFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data", "MaliciousApplicationsList.json");
    }

    public async Task<bool> MigrateFromJsonAsync()
    {
        try
        {
            if (!File.Exists(_jsonFilePath))
            {
                _logger.LogInformation("No JSON file found to migrate from");
                return true;
            }

            _logger.LogInformation("Starting migration from JSON to encrypted format...");

            // Read the JSON file
            var jsonContent = await File.ReadAllTextAsync(_jsonFilePath);
            var data = JsonSerializer.Deserialize<MaliciousApplicationsData>(jsonContent);

            if (data == null)
            {
                _logger.LogError("Failed to deserialize JSON data");
                return false;
            }

            // Save to encrypted storage
            await _storageService.SaveDataAsync(data);

            // Backup the original JSON file
            var backupPath = _jsonFilePath + ".backup";
            File.Copy(_jsonFilePath, backupPath, true);

            // Optionally remove the original JSON file (uncomment if you want to)
            // File.Delete(_jsonFilePath);

            _logger.LogInformation("Migration completed successfully. Original file backed up to {BackupPath}", backupPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during migration from JSON to encrypted format");
            return false;
        }
    }

    public async Task<bool> ExportToJsonAsync(string outputPath = null)
    {
        try
        {
            outputPath ??= Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data", "MaliciousApplicationsList_exported.json");

            var data = await _storageService.LoadDataAsync();
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
            
            await File.WriteAllTextAsync(outputPath, json);
            
            _logger.LogInformation("Data exported to JSON successfully: {OutputPath}", outputPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting data to JSON");
            return false;
        }
    }
}
