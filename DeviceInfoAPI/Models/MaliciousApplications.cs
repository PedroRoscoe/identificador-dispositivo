using System.Text.Json.Serialization;

namespace DeviceInfoAPI.Models;

public class MaliciousApplicationDetection
{
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string ThreatLevel { get; set; } = string.Empty;
    public int ThreatScore { get; set; }
    public string DetectionMethod { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string RegistryPath { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; }
    public string Status { get; set; } = string.Empty; // Running, Stopped, Removed
    public List<string> DetectionMethods { get; set; } = new();
    public string Mitigation { get; set; } = string.Empty;
}

public class MaliciousApplicationsReport
{
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public int TotalThreats { get; set; }
    public int CriticalThreats { get; set; }
    public int HighThreats { get; set; }
    public int MediumThreats { get; set; }
    public int LowThreats { get; set; }
    public int OverallThreatScore { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
    public List<MaliciousApplicationDetection> DetectedThreats { get; set; } = new();
    public List<string> Categories { get; set; } = new();
    public Dictionary<string, int> ThreatsByCategory { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
    public bool RequiresImmediateAction { get; set; }
}

public class MaliciousApplicationDefinition
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;
    
    [JsonPropertyName("processNames")]
    public List<string> ProcessNames { get; set; } = new();
    
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;
    
    [JsonPropertyName("threatLevel")]
    public string ThreatLevel { get; set; } = string.Empty;
    
    [JsonPropertyName("detectionMethods")]
    public List<string> DetectionMethods { get; set; } = new();
}

public class MaliciousApplicationsCategory
{
    [JsonPropertyName("category")]
    public string Category { get; set; } = string.Empty;
    
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;
    
    [JsonPropertyName("applications")]
    public List<MaliciousApplicationDefinition> Applications { get; set; } = new();
}

public class MaliciousApplicationsData
{
    [JsonPropertyName("maliciousApplications")]
    public Dictionary<string, MaliciousApplicationsCategory> Categories { get; set; } = new();
    
    [JsonPropertyName("detectionRules")]
    public DetectionRules DetectionRules { get; set; } = new();
    
    [JsonPropertyName("riskScoring")]
    public Dictionary<string, int> RiskScoring { get; set; } = new();
    
    [JsonPropertyName("lastUpdated")]
    public DateTime LastUpdated { get; set; }
    
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;
}

public class DetectionRules
{
    [JsonPropertyName("processMonitoring")]
    public MonitoringRule ProcessMonitoring { get; set; } = new();
    
    [JsonPropertyName("fileSystemMonitoring")]
    public MonitoringRule FileSystemMonitoring { get; set; } = new();
    
    [JsonPropertyName("registryMonitoring")]
    public MonitoringRule RegistryMonitoring { get; set; } = new();
    
    [JsonPropertyName("networkMonitoring")]
    public MonitoringRule NetworkMonitoring { get; set; } = new();
}

public class MonitoringRule
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }
    
    [JsonPropertyName("checkInterval")]
    public int CheckInterval { get; set; }
    
    [JsonPropertyName("alertThreshold")]
    public int AlertThreshold { get; set; }
}

