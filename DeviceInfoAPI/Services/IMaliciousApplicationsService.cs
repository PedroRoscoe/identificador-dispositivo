using DeviceInfoAPI.Models;

namespace DeviceInfoAPI.Services;

public interface IMaliciousApplicationsService
{
    Task<List<MaliciousApplicationDetection>> ScanForMaliciousApplicationsAsync();
    Task<List<MaliciousApplicationDetection>> ScanRunningProcessesAsync();
    Task<List<MaliciousApplicationDetection>> ScanFileSystemAsync();
    Task<List<MaliciousApplicationDetection>> ScanRegistryAsync();
    Task<MaliciousApplicationsReport> GenerateThreatReportAsync();
    Task<bool> IsApplicationMaliciousAsync(string processName);
    Task<int> GetThreatScoreAsync();
    Task<List<string>> GetDetectedThreatsAsync();
}

