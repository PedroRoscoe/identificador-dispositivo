using DeviceInfoAPI.Models;
using DeviceInfoAPI.Services;
using Microsoft.AspNetCore.Mvc;

namespace DeviceInfoAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class RiskAnalysisController : ControllerBase
{
    private readonly IRiskAnalysisService _riskAnalysisService;

    public RiskAnalysisController(IRiskAnalysisService riskAnalysisService)
    {
        _riskAnalysisService = riskAnalysisService;
    }

    /// <summary>
    /// Get comprehensive device information with risk analysis
    /// </summary>
    [HttpGet("enhanced-device-info")]
    public async Task<ActionResult<EnhancedDeviceInfo>> GetEnhancedDeviceInfo()
    {
        try
        {
            var enhancedInfo = await _riskAnalysisService.GetEnhancedDeviceInfoAsync();
            return Ok(enhancedInfo);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to get enhanced device info", details = ex.Message });
        }
    }

    /// <summary>
    /// Get detailed risk assessment for the device
    /// </summary>
    [HttpGet("risk-assessment")]
    public async Task<ActionResult<RiskScore>> GetRiskAssessment()
    {
        try
        {
            var enhancedInfo = await _riskAnalysisService.GetEnhancedDeviceInfoAsync();
            var riskScore = await _riskAnalysisService.CalculateRiskScoreAsync(enhancedInfo);
            return Ok(riskScore);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to calculate risk assessment", details = ex.Message });
        }
    }

    /// <summary>
    /// Get security posture analysis
    /// </summary>
    [HttpGet("security-posture")]
    public async Task<ActionResult<SecurityPosture>> GetSecurityPosture()
    {
        try
        {
            var securityPosture = await _riskAnalysisService.AnalyzeSecurityPostureAsync();
            return Ok(securityPosture);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to analyze security posture", details = ex.Message });
        }
    }

    /// <summary>
    /// Get network security analysis
    /// </summary>
    [HttpGet("network-security")]
    public async Task<ActionResult<NetworkSecurity>> GetNetworkSecurity()
    {
        try
        {
            var networkSecurity = await _riskAnalysisService.AnalyzeNetworkSecurityAsync();
            return Ok(networkSecurity);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to analyze network security", details = ex.Message });
        }
    }

    /// <summary>
    /// Get hardware profile analysis
    /// </summary>
    [HttpGet("hardware-profile")]
    public async Task<ActionResult<HardwareProfile>> GetHardwareProfile()
    {
        try
        {
            var hardwareProfile = await _riskAnalysisService.AnalyzeHardwareProfileAsync();
            return Ok(hardwareProfile);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to analyze hardware profile", details = ex.Message });
        }
    }

    /// <summary>
    /// Get user context analysis
    /// </summary>
    [HttpGet("user-context")]
    public async Task<ActionResult<UserContext>> GetUserContext()
    {
        try
        {
            var userContext = await _riskAnalysisService.AnalyzeUserContextAsync();
            return Ok(userContext);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to analyze user context", details = ex.Message });
        }
    }

    /// <summary>
    /// Get specific risk factors identified
    /// </summary>
    [HttpGet("risk-factors")]
    public async Task<ActionResult<List<RiskFactor>>> GetRiskFactors()
    {
        try
        {
            var enhancedInfo = await _riskAnalysisService.GetEnhancedDeviceInfoAsync();
            var riskFactors = await _riskAnalysisService.AnalyzeRiskFactorsAsync(enhancedInfo);
            return Ok(riskFactors);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to analyze risk factors", details = ex.Message });
        }
    }

    /// <summary>
    /// Get security recommendations
    /// </summary>
    [HttpGet("recommendations")]
    public async Task<ActionResult<List<SecurityRecommendation>>> GetRecommendations()
    {
        try
        {
            var enhancedInfo = await _riskAnalysisService.GetEnhancedDeviceInfoAsync();
            var recommendations = await _riskAnalysisService.GenerateRecommendationsAsync(enhancedInfo);
            return Ok(recommendations);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to generate recommendations", details = ex.Message });
        }
    }

    /// <summary>
    /// Get risk summary with key metrics
    /// </summary>
    [HttpGet("risk-summary")]
    public async Task<ActionResult<object>> GetRiskSummary()
    {
        try
        {
            var enhancedInfo = await _riskAnalysisService.GetEnhancedDeviceInfoAsync();
            var riskScore = await _riskAnalysisService.CalculateRiskScoreAsync(enhancedInfo);

            var summary = new
            {
                OverallRiskLevel = riskScore.RiskLevel,
                OverallScore = riskScore.OverallScore,
                CategoryScores = riskScore.CategoryScores,
                RiskFactorsCount = riskScore.RiskFactors.Count,
                RecommendationsCount = riskScore.Recommendations.Count,
                CriticalIssues = riskScore.RiskFactors.Count(rf => rf.Severity >= 4),
                HighPriorityRecommendations = riskScore.Recommendations.Count(r => r.Priority >= 4),
                LastCalculated = riskScore.CalculatedAt,
                DeviceName = enhancedInfo.BasicInfo.DeviceName,
                Location = enhancedInfo.BasicInfo.IpLocationInfo?.City ?? "Unknown"
            };

            return Ok(summary);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Failed to generate risk summary", details = ex.Message });
        }
    }
}
