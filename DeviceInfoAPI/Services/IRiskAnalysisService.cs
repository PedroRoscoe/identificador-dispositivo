using DeviceInfoAPI.Models;

namespace DeviceInfoAPI.Services;

public interface IRiskAnalysisService
{
    Task<EnhancedDeviceInfo> GetEnhancedDeviceInfoAsync();
    Task<RiskScore> CalculateRiskScoreAsync(EnhancedDeviceInfo deviceInfo);
    Task<List<RiskFactor>> AnalyzeRiskFactorsAsync(EnhancedDeviceInfo deviceInfo);
    Task<List<SecurityRecommendation>> GenerateRecommendationsAsync(EnhancedDeviceInfo deviceInfo);
    Task<SecurityPosture> AnalyzeSecurityPostureAsync();
    Task<NetworkSecurity> AnalyzeNetworkSecurityAsync();
    Task<HardwareProfile> AnalyzeHardwareProfileAsync();
    Task<UserContext> AnalyzeUserContextAsync();
}
