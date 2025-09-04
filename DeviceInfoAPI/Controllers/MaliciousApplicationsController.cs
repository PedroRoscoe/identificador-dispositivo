using DeviceInfoAPI.Models;
using DeviceInfoAPI.Services;
using Microsoft.AspNetCore.Mvc;

namespace DeviceInfoAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MaliciousApplicationsController : ControllerBase
{
    private readonly IMaliciousApplicationsService _maliciousAppsService;
    private readonly ILogger<MaliciousApplicationsController> _logger;

    public MaliciousApplicationsController(
        IMaliciousApplicationsService maliciousAppsService,
        ILogger<MaliciousApplicationsController> logger)
    {
        _maliciousAppsService = maliciousAppsService;
        _logger = logger;
    }

    /// <summary>
    /// Scan for malicious applications across all detection methods
    /// </summary>
    [HttpGet("scan")]
    public async Task<ActionResult<List<MaliciousApplicationDetection>>> ScanForMaliciousApplications()
    {
        try
        {
            var detections = await _maliciousAppsService.ScanForMaliciousApplicationsAsync();
            return Ok(detections);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning for malicious applications");
            return StatusCode(500, "Internal server error during scan");
        }
    }

    /// <summary>
    /// Scan only running processes for malicious applications
    /// </summary>
    [HttpGet("scan/processes")]
    public async Task<ActionResult<List<MaliciousApplicationDetection>>> ScanRunningProcesses()
    {
        try
        {
            var detections = await _maliciousAppsService.ScanRunningProcessesAsync();
            return Ok(detections);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning running processes");
            return StatusCode(500, "Internal server error during process scan");
        }
    }

    /// <summary>
    /// Scan file system for malicious applications
    /// </summary>
    [HttpGet("scan/filesystem")]
    public async Task<ActionResult<List<MaliciousApplicationDetection>>> ScanFileSystem()
    {
        try
        {
            var detections = await _maliciousAppsService.ScanFileSystemAsync();
            return Ok(detections);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning file system");
            return StatusCode(500, "Internal server error during file system scan");
        }
    }

    /// <summary>
    /// Scan registry for malicious applications
    /// </summary>
    [HttpGet("scan/registry")]
    public async Task<ActionResult<List<MaliciousApplicationDetection>>> ScanRegistry()
    {
        try
        {
            var detections = await _maliciousAppsService.ScanRegistryAsync();
            return Ok(detections);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning registry");
            return StatusCode(500, "Internal server error during registry scan");
        }
    }

    /// <summary>
    /// Generate comprehensive threat report
    /// </summary>
    [HttpGet("report")]
    public async Task<ActionResult<MaliciousApplicationsReport>> GenerateThreatReport()
    {
        try
        {
            var report = await _maliciousAppsService.GenerateThreatReportAsync();
            return Ok(report);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating threat report");
            return StatusCode(500, "Internal server error during report generation");
        }
    }

    /// <summary>
    /// Check if a specific application is malicious
    /// </summary>
    [HttpGet("check/{processName}")]
    public async Task<ActionResult<bool>> IsApplicationMalicious(string processName)
    {
        try
        {
            var isMalicious = await _maliciousAppsService.IsApplicationMaliciousAsync(processName);
            return Ok(new { processName, isMalicious });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if application is malicious: {ProcessName}", processName);
            return StatusCode(500, "Internal server error during application check");
        }
    }

    /// <summary>
    /// Get overall threat score
    /// </summary>
    [HttpGet("threat-score")]
    public async Task<ActionResult<int>> GetThreatScore()
    {
        try
        {
            var threatScore = await _maliciousAppsService.GetThreatScoreAsync();
            return Ok(new { threatScore, riskLevel = GetRiskLevel(threatScore) });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting threat score");
            return StatusCode(500, "Internal server error getting threat score");
        }
    }

    /// <summary>
    /// Get list of detected threats
    /// </summary>
    [HttpGet("threats")]
    public async Task<ActionResult<List<string>>> GetDetectedThreats()
    {
        try
        {
            var threats = await _maliciousAppsService.GetDetectedThreatsAsync();
            return Ok(threats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting detected threats");
            return StatusCode(500, "Internal server error getting detected threats");
        }
    }

    /// <summary>
    /// Get threat summary with counts by level
    /// </summary>
    [HttpGet("summary")]
    public async Task<ActionResult<object>> GetThreatSummary()
    {
        try
        {
            var report = await _maliciousAppsService.GenerateThreatReportAsync();
            var summary = new
            {
                totalThreats = report.TotalThreats,
                criticalThreats = report.CriticalThreats,
                highThreats = report.HighThreats,
                mediumThreats = report.MediumThreats,
                lowThreats = report.LowThreats,
                overallThreatScore = report.OverallThreatScore,
                riskLevel = report.RiskLevel,
                requiresImmediateAction = report.RequiresImmediateAction,
                categories = report.ThreatsByCategory,
                generatedAt = report.GeneratedAt
            };
            return Ok(summary);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting threat summary");
            return StatusCode(500, "Internal server error getting threat summary");
        }
    }

    private string GetRiskLevel(int threatScore)
    {
        return threatScore switch
        {
            >= 200 => "Critical",
            >= 100 => "High",
            >= 50 => "Medium",
            >= 10 => "Low",
            _ => "Safe"
        };
    }
}

