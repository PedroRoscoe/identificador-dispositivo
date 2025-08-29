using System.ComponentModel.DataAnnotations;

namespace DeviceInfoAPI.Models;

public class EnhancedDeviceInfo
{
    public DeviceInfo BasicInfo { get; set; } = new();
    public SecurityPosture SecurityInfo { get; set; } = new();
    public NetworkSecurity NetworkInfo { get; set; } = new();
    public HardwareProfile HardwareInfo { get; set; } = new();
    public UserContext UserInfo { get; set; } = new();
    public RiskScore RiskAssessment { get; set; } = new();
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
}

public class SecurityPosture
{
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public DateTime LastUpdate { get; set; }
    public bool IsAntivirusInstalled { get; set; }
    public string AntivirusName { get; set; } = string.Empty;
    public bool IsAntivirusUpToDate { get; set; }
    public bool IsFirewallEnabled { get; set; }
    public bool IsUacEnabled { get; set; }
    public bool IsBitLockerEnabled { get; set; }
    public bool IsWindowsDefenderEnabled { get; set; }
    public List<string> InstalledSecuritySoftware { get; set; } = new();
    public int SecurityScore { get; set; } // 0-100
}

public class NetworkSecurity
{
    public List<string> DnsServers { get; set; } = new();
    public bool IsProxyDetected { get; set; }
    public string ProxyAddress { get; set; } = string.Empty;
    public List<string> ActiveConnections { get; set; } = new();
    public List<int> OpenPorts { get; set; } = new();
    public bool IsVpnActive { get; set; }
    public string VpnProvider { get; set; } = string.Empty;
    public List<string> NetworkAdapters { get; set; } = new();
    public int NetworkSecurityScore { get; set; } // 0-100
}

public class HardwareProfile
{
    public string CpuModel { get; set; } = string.Empty;
    public string CpuManufacturer { get; set; } = string.Empty;
    public int RamSizeGb { get; set; }
    public string GpuModel { get; set; } = string.Empty;
    public string MotherboardModel { get; set; } = string.Empty;
    public string BiosVersion { get; set; } = string.Empty;
    public string BiosManufacturer { get; set; } = string.Empty;
    public string DeviceSerialNumber { get; set; } = string.Empty;
    public bool IsVirtualMachine { get; set; }
    public bool IsContainer { get; set; }
    public string ScreenResolution { get; set; } = string.Empty;
    public int ColorDepth { get; set; }
    public string HardwareHash { get; set; } = string.Empty;
    public int HardwareScore { get; set; } // 0-100
}

public class UserContext
{
    // Basic User Information
    public string WindowsUsername { get; set; } = string.Empty;
    public string UserDomain { get; set; } = string.Empty;
    public string UserSid { get; set; } = string.Empty;
    public string UserEmail { get; set; } = string.Empty;
    public string UserFullName { get; set; } = string.Empty;
    public string UserProfilePath { get; set; } = string.Empty;
    
    // Account Security & Privileges
    public string UserAccountType { get; set; } = string.Empty; // Admin/Standard
    public bool IsAdministrator { get; set; }
    public bool IsElevated { get; set; }
    public List<string> UserGroups { get; set; } = new();
    public List<string> UserPrivileges { get; set; } = new();
    
    // Account Status
    public DateTime LastLogin { get; set; }
    public DateTime AccountCreated { get; set; }
    public DateTime PasswordLastSet { get; set; }
    public DateTime PasswordExpires { get; set; }
    public bool IsAccountLocked { get; set; }
    public bool IsPasswordExpired { get; set; }
    public int FailedLoginAttempts { get; set; }
    
    // System Context
    public string TimeZone { get; set; } = string.Empty;
    public string Language { get; set; } = string.Empty;
    public string KeyboardLayout { get; set; } = string.Empty;
    public string PowerPlan { get; set; } = string.Empty;
    public string WorkingDirectory { get; set; } = string.Empty;
    
    // User Behavior & Activity
    public List<string> RecentApplications { get; set; } = new();
    public List<string> RecentDocuments { get; set; } = new();
    public List<string> StartupPrograms { get; set; } = new();
    public int UserBehaviorScore { get; set; } // 0-100
    
    // Security Context
    public bool IsUacEnabled { get; set; }
    public string UacLevel { get; set; } = string.Empty;
    public bool IsRemoteSession { get; set; }
    public string SessionType { get; set; } = string.Empty;
}

public class RiskScore
{
    public int OverallScore { get; set; } // 0-100
    public Dictionary<string, int> CategoryScores { get; set; } = new();
    public List<RiskFactor> RiskFactors { get; set; } = new();
    public List<SecurityRecommendation> Recommendations { get; set; } = new();
    public string RiskLevel { get; set; } = string.Empty; // Low, Medium, High, Critical
    public DateTime CalculatedAt { get; set; } = DateTime.UtcNow;
}

public class RiskFactor
{
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int Severity { get; set; } // 1-5
    public string Impact { get; set; } = string.Empty;
    public string Mitigation { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}

public class SecurityRecommendation
{
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int Priority { get; set; } // 1-5
    public string ActionRequired { get; set; } = string.Empty;
    public string ExpectedOutcome { get; set; } = string.Empty;
}

public enum RiskLevel
{
    Low = 0,        // 0-25
    Medium = 1,     // 26-50
    High = 2,       // 51-75
    Critical = 3    // 76-100
}
