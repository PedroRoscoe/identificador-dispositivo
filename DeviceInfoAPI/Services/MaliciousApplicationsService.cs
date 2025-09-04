using System.Diagnostics;
using System.Management;
using System.Text.Json;
using DeviceInfoAPI.Models;
using Microsoft.Win32;
using Microsoft.Extensions.Logging;

namespace DeviceInfoAPI.Services;

public class MaliciousApplicationsService : IMaliciousApplicationsService
{
    private readonly IMaliciousApplicationsStorageService _storageService;
    private readonly ILogger<MaliciousApplicationsService> _logger;

    public MaliciousApplicationsService(
        IMaliciousApplicationsStorageService storageService,
        ILogger<MaliciousApplicationsService> logger)
    {
        _storageService = storageService;
        _logger = logger;
    }



    public async Task<List<MaliciousApplicationDetection>> ScanForMaliciousApplicationsAsync()
    {
        var detections = new List<MaliciousApplicationDetection>();

        try
        {
            // Scan running processes
            var processDetections = await ScanRunningProcessesAsync();
            detections.AddRange(processDetections);

            // Scan file system
            var fileDetections = await ScanFileSystemAsync();
            detections.AddRange(fileDetections);

            // Scan registry
            var registryDetections = await ScanRegistryAsync();
            detections.AddRange(registryDetections);

            _logger.LogInformation("Completed malicious applications scan. Found {Count} threats", detections.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during malicious applications scan");
        }

        return detections;
    }

    public async Task<List<MaliciousApplicationDetection>> ScanRunningProcessesAsync()
    {
        var detections = new List<MaliciousApplicationDetection>();

        try
        {
            var processes = Process.GetProcesses();
            
            foreach (var process in processes)
            {
                try
                {
                    var detection = await CheckProcessForMaliciousActivityAsync(process);
                    if (detection != null)
                    {
                        detections.Add(detection);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error checking process {ProcessName}", process.ProcessName);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning running processes");
        }

        return detections;
    }

    public async Task<List<MaliciousApplicationDetection>> ScanFileSystemAsync()
    {
        var detections = new List<MaliciousApplicationDetection>();

        try
        {
            var maliciousAppsData = await _storageService.LoadDataAsync();
            if (maliciousAppsData?.Categories == null) return detections;

            var commonPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup)
            };

            foreach (var category in maliciousAppsData.Categories.Values)
            {
                foreach (var app in category.Applications)
                {
                    foreach (var processName in app.ProcessNames)
                    {
                        var fileName = Path.GetFileNameWithoutExtension(processName);
                        var exeName = Path.GetFileName(processName);

                        foreach (var path in commonPaths)
                        {
                            if (Directory.Exists(path))
                            {
                                var foundFiles = Directory.GetFiles(path, $"*{fileName}*", SearchOption.AllDirectories)
                                    .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                    .Take(5); // Limit search depth

                                foreach (var file in foundFiles)
                                {
                                    var detection = new MaliciousApplicationDetection
                                    {
                                        Name = app.Name,
                                        Category = category.Category,
                                        Description = app.Description,
                                        ThreatLevel = app.ThreatLevel,
                                        ThreatScore = GetThreatScore(app.ThreatLevel),
                                        DetectionMethod = "FileSystem",
                                        FilePath = file,
                                        ProcessName = exeName,
                                        IsActive = false,
                                        Status = "File Found",
                                        DetectionMethods = app.DetectionMethods,
                                        Mitigation = GetMitigationForThreat(app.ThreatLevel)
                                    };

                                    detections.Add(detection);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning file system");
        }

        return detections;
    }

    public async Task<List<MaliciousApplicationDetection>> ScanRegistryAsync()
    {
        var detections = new List<MaliciousApplicationDetection>();

        try
        {
            var maliciousAppsData = await _storageService.LoadDataAsync();
            if (maliciousAppsData?.Categories == null) return detections;

            var registryKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };

            foreach (var category in maliciousAppsData.Categories.Values)
            {
                foreach (var app in category.Applications)
                {
                    foreach (var processName in app.ProcessNames)
                    {
                        var fileName = Path.GetFileNameWithoutExtension(processName);

                        foreach (var keyPath in registryKeys)
                        {
                            try
                            {
                                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                                if (key != null)
                                {
                                    foreach (var valueName in key.GetValueNames())
                                    {
                                        if (valueName.Contains(fileName, StringComparison.OrdinalIgnoreCase))
                                        {
                                            var detection = new MaliciousApplicationDetection
                                            {
                                                Name = app.Name,
                                                Category = category.Category,
                                                Description = app.Description,
                                                ThreatLevel = app.ThreatLevel,
                                                ThreatScore = GetThreatScore(app.ThreatLevel),
                                                DetectionMethod = "Registry",
                                                RegistryPath = $"{keyPath}\\{valueName}",
                                                ProcessName = processName,
                                                IsActive = false,
                                                Status = "Registry Entry Found",
                                                DetectionMethods = app.DetectionMethods,
                                                Mitigation = GetMitigationForThreat(app.ThreatLevel)
                                            };

                                            detections.Add(detection);
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                _logger.LogDebug(ex, "Error accessing registry key {KeyPath}", keyPath);
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning registry");
        }

        return detections;
    }

    public async Task<MaliciousApplicationsReport> GenerateThreatReportAsync()
    {
        var report = new MaliciousApplicationsReport();
        
        try
        {
            var detections = await ScanForMaliciousApplicationsAsync();
            report.DetectedThreats = detections;
            report.TotalThreats = detections.Count;

            // Count threats by level
            report.CriticalThreats = detections.Count(d => d.ThreatLevel == "Critical");
            report.HighThreats = detections.Count(d => d.ThreatLevel == "High");
            report.MediumThreats = detections.Count(d => d.ThreatLevel == "Medium");
            report.LowThreats = detections.Count(d => d.ThreatLevel == "Low");

            // Calculate overall threat score
            report.OverallThreatScore = detections.Sum(d => d.ThreatScore);
            
            // Determine risk level
            report.RiskLevel = report.OverallThreatScore switch
            {
                >= 200 => "Critical",
                >= 100 => "High",
                >= 50 => "Medium",
                >= 10 => "Low",
                _ => "Safe"
            };

            // Group threats by category
            report.Categories = detections.Select(d => d.Category).Distinct().ToList();
            report.ThreatsByCategory = detections
                .GroupBy(d => d.Category)
                .ToDictionary(g => g.Key, g => g.Count());

            // Generate recommendations
            report.Recommendations = GenerateRecommendations(detections);
            report.RequiresImmediateAction = report.CriticalThreats > 0 || report.HighThreats > 2;

            _logger.LogInformation("Generated threat report: {TotalThreats} threats, Risk Level: {RiskLevel}", 
                report.TotalThreats, report.RiskLevel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating threat report");
        }

        return report;
    }

    public async Task<bool> IsApplicationMaliciousAsync(string processName)
    {
        try
        {
            var maliciousAppsData = await _storageService.LoadDataAsync();
            if (maliciousAppsData?.Categories == null) return false;

            foreach (var category in maliciousAppsData.Categories.Values)
            {
                foreach (var app in category.Applications)
                {
                    if (app.ProcessNames.Any(p => p.Equals(processName, StringComparison.OrdinalIgnoreCase)))
                    {
                        return true;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if application is malicious");
        }

        return false;
    }

    public async Task<int> GetThreatScoreAsync()
    {
        try
        {
            var detections = await ScanForMaliciousApplicationsAsync();
            return detections.Sum(d => d.ThreatScore);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calculating threat score");
            return 0;
        }
    }

    public async Task<List<string>> GetDetectedThreatsAsync()
    {
        try
        {
            var detections = await ScanForMaliciousApplicationsAsync();
            return detections.Select(d => $"{d.Name} ({d.ThreatLevel})").ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting detected threats");
            return new List<string>();
        }
    }

    private async Task<MaliciousApplicationDetection?> CheckProcessForMaliciousActivityAsync(Process process)
    {
        try
        {
            var maliciousAppsData = await _storageService.LoadDataAsync();
            if (maliciousAppsData?.Categories == null) return null;

            foreach (var category in maliciousAppsData.Categories.Values)
            {
                foreach (var app in category.Applications)
                {
                    if (app.ProcessNames.Any(p => p.Equals(process.ProcessName, StringComparison.OrdinalIgnoreCase)))
                    {
                        return new MaliciousApplicationDetection
                        {
                            Name = app.Name,
                            Category = category.Category,
                            Description = app.Description,
                            ThreatLevel = app.ThreatLevel,
                            ThreatScore = GetThreatScore(app.ThreatLevel),
                            DetectionMethod = "Process",
                            ProcessName = process.ProcessName,
                            FilePath = GetProcessFilePath(process),
                            IsActive = true,
                            Status = "Running",
                            DetectionMethods = app.DetectionMethods,
                            Mitigation = GetMitigationForThreat(app.ThreatLevel)
                        };
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking process {ProcessName}", process.ProcessName);
        }

        return null;
    }

    private string GetProcessFilePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private int GetThreatScore(string threatLevel)
    {
        return threatLevel switch
        {
            "Critical" => 100,
            "High" => 75,
            "Medium" => 50,
            "Low" => 25,
            _ => 0
        };
    }

    private string GetMitigationForThreat(string threatLevel)
    {
        return threatLevel switch
        {
            "Critical" => "Immediate removal required. Block network access and investigate thoroughly.",
            "High" => "Remove application and investigate for compromise indicators.",
            "Medium" => "Review application necessity and restrict permissions if needed.",
            "Low" => "Monitor usage and ensure legitimate purpose.",
            _ => "Review and assess risk."
        };
    }

    private List<string> GenerateRecommendations(List<MaliciousApplicationDetection> detections)
    {
        var recommendations = new List<string>();

        if (detections.Any(d => d.ThreatLevel == "Critical"))
        {
            recommendations.Add("CRITICAL: Immediate action required. Remove all critical threats immediately.");
        }

        if (detections.Any(d => d.ThreatLevel == "High"))
        {
            recommendations.Add("HIGH: Remove high-threat applications and investigate for compromise.");
        }

        if (detections.Any(d => d.Category == "Remote Access & Control"))
        {
            recommendations.Add("Review all remote access tools and ensure they are legitimate and necessary.");
        }

        if (detections.Any(d => d.Category == "Password Cracking & Recovery"))
        {
            recommendations.Add("Remove password cracking tools and review password policies.");
        }

        if (detections.Any(d => d.Category == "System Manipulation Tools"))
        {
            recommendations.Add("Restrict access to system manipulation tools to authorized personnel only.");
        }

        if (detections.Count == 0)
        {
            recommendations.Add("No malicious applications detected. Continue regular monitoring.");
        }

        return recommendations;
    }
}
