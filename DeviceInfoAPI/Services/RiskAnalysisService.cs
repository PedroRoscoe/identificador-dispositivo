using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using DeviceInfoAPI.Models;
using Microsoft.Win32;
// System.Windows.Forms is not available in .NET Core, using alternative approach

namespace DeviceInfoAPI.Services;

public class RiskAnalysisService : IRiskAnalysisService
{
    private readonly IDeviceInfoService _deviceInfoService;

    public RiskAnalysisService(IDeviceInfoService deviceInfoService)
    {
        _deviceInfoService = deviceInfoService;
    }

    public async Task<EnhancedDeviceInfo> GetEnhancedDeviceInfoAsync()
    {
        var basicInfo = await _deviceInfoService.GetDeviceInfoAsync();
        
        var enhancedInfo = new EnhancedDeviceInfo
        {
            BasicInfo = basicInfo,
            SecurityInfo = await AnalyzeSecurityPostureAsync(),
            NetworkInfo = await AnalyzeNetworkSecurityAsync(),
            HardwareInfo = await AnalyzeHardwareProfileAsync(),
            UserInfo = await AnalyzeUserContextAsync()
        };

        enhancedInfo.RiskAssessment = await CalculateRiskScoreAsync(enhancedInfo);
        
        return enhancedInfo;
    }

    public async Task<RiskScore> CalculateRiskScoreAsync(EnhancedDeviceInfo deviceInfo)
    {
        var riskScore = new RiskScore();
        
        // Calculate category scores
        riskScore.CategoryScores["Security"] = deviceInfo.SecurityInfo.SecurityScore;
        riskScore.CategoryScores["Network"] = deviceInfo.NetworkInfo.NetworkSecurityScore;
        riskScore.CategoryScores["Hardware"] = deviceInfo.HardwareInfo.HardwareScore;
        riskScore.CategoryScores["UserBehavior"] = deviceInfo.UserInfo.UserBehaviorScore;

        // Calculate overall score (weighted average)
        var weights = new Dictionary<string, double>
        {
            ["Security"] = 0.4,      // 40% weight
            ["Network"] = 0.3,       // 30% weight
            ["Hardware"] = 0.2,      // 20% weight
            ["UserBehavior"] = 0.1   // 10% weight
        };

        double weightedSum = 0;
        double totalWeight = 0;

        foreach (var category in riskScore.CategoryScores)
        {
            if (weights.ContainsKey(category.Key))
            {
                weightedSum += category.Value * weights[category.Key];
                totalWeight += weights[category.Key];
            }
        }

        riskScore.OverallScore = totalWeight > 0 ? (int)Math.Round(weightedSum / totalWeight) : 0;

        // Determine risk level
        riskScore.RiskLevel = riskScore.OverallScore switch
        {
            <= 25 => "Low",
            <= 50 => "Medium",
            <= 75 => "High",
            _ => "Critical"
        };

        // Analyze risk factors
        riskScore.RiskFactors = await AnalyzeRiskFactorsAsync(deviceInfo);
        
        // Generate recommendations
        riskScore.Recommendations = await GenerateRecommendationsAsync(deviceInfo);
        
        riskScore.CalculatedAt = DateTime.UtcNow;

        return riskScore;
    }

    public async Task<List<RiskFactor>> AnalyzeRiskFactorsAsync(EnhancedDeviceInfo deviceInfo)
    {
        var riskFactors = new List<RiskFactor>();

        // Security posture risks
        if (deviceInfo.SecurityInfo.SecurityScore < 50)
        {
            riskFactors.Add(new RiskFactor
            {
                Category = "Security",
                Description = "Low security posture detected",
                Severity = 4,
                Impact = "High risk of security breaches",
                Mitigation = "Update security software and enable all security features",
                DetectedAt = DateTime.UtcNow
            });
        }

        if (!deviceInfo.SecurityInfo.IsAntivirusInstalled)
        {
            riskFactors.Add(new RiskFactor
            {
                Category = "Security",
                Description = "No antivirus software detected",
                Severity = 5,
                Impact = "Critical vulnerability to malware",
                Mitigation = "Install and configure reputable antivirus software",
                DetectedAt = DateTime.UtcNow
            });
        }

        if (!deviceInfo.SecurityInfo.IsFirewallEnabled)
        {
            riskFactors.Add(new RiskFactor
            {
                Category = "Security",
                Description = "Firewall is disabled",
                Severity = 4,
                Impact = "Network exposure to external threats",
                Mitigation = "Enable Windows Firewall or install third-party firewall",
                DetectedAt = DateTime.UtcNow
            });
        }

        // Network security risks
        if (deviceInfo.NetworkInfo.IsVpnActive)
        {
            riskFactors.Add(new RiskFactor
            {
                Category = "Network",
                Description = "VPN connection detected",
                Severity = 2,
                Impact = "Potential masking of real location",
                Mitigation = "Monitor VPN usage and verify legitimate connections",
                DetectedAt = DateTime.UtcNow
            });
        }

        if (deviceInfo.NetworkInfo.OpenPorts.Count > 10)
        {
            riskFactors.Add(new RiskFactor
            {
                Category = "Network",
                Description = "Multiple open ports detected",
                Severity = 3,
                Impact = "Increased attack surface",
                Mitigation = "Close unnecessary ports and review firewall rules",
                DetectedAt = DateTime.UtcNow
            });
        }

        // Hardware risks
        if (deviceInfo.HardwareInfo.IsVirtualMachine)
        {
            riskFactors.Add(new RiskFactor
            {
                Category = "Hardware",
                Description = "Virtual machine environment detected",
                Severity = 2,
                Impact = "Potential for environment manipulation",
                Mitigation = "Verify VM integrity and monitor for suspicious activity",
                DetectedAt = DateTime.UtcNow
            });
        }

        // User behavior risks
        if (deviceInfo.UserInfo.FailedLoginAttempts > 3)
        {
            riskFactors.Add(new RiskFactor
            {
                Category = "UserBehavior",
                Description = "Multiple failed login attempts detected",
                Severity = 4,
                Impact = "Potential brute force attack",
                Mitigation = "Investigate failed login attempts and consider account lockout",
                DetectedAt = DateTime.UtcNow
            });
        }

        return riskFactors;
    }

    public async Task<List<SecurityRecommendation>> GenerateRecommendationsAsync(EnhancedDeviceInfo deviceInfo)
    {
        var recommendations = new List<SecurityRecommendation>();

        // Security recommendations
        if (!deviceInfo.SecurityInfo.IsAntivirusInstalled)
        {
            recommendations.Add(new SecurityRecommendation
            {
                Category = "Security",
                Title = "Install Antivirus Software",
                Description = "No antivirus software is currently installed",
                Priority = 5,
                ActionRequired = "Install and configure reputable antivirus software",
                ExpectedOutcome = "Protection against malware and viruses"
            });
        }

        if (!deviceInfo.SecurityInfo.IsFirewallEnabled)
        {
            recommendations.Add(new SecurityRecommendation
            {
                Category = "Security",
                Title = "Enable Firewall",
                Description = "Windows Firewall is currently disabled",
                Priority = 4,
                ActionRequired = "Enable Windows Firewall or install third-party firewall",
                ExpectedOutcome = "Network protection against external threats"
            });
        }

        if (!deviceInfo.SecurityInfo.IsUacEnabled)
        {
            recommendations.Add(new SecurityRecommendation
            {
                Category = "Security",
                Title = "Enable User Account Control",
                Description = "UAC is disabled, reducing security",
                Priority = 3,
                ActionRequired = "Enable UAC in Windows settings",
                ExpectedOutcome = "Prevention of unauthorized system changes"
            });
        }

        // Network recommendations
        if (deviceInfo.NetworkInfo.DnsServers.Count == 0)
        {
            recommendations.Add(new SecurityRecommendation
            {
                Category = "Network",
                Title = "Configure DNS Servers",
                Description = "No DNS servers configured",
                Priority = 3,
                ActionRequired = "Configure secure DNS servers (e.g., 8.8.8.8, 1.1.1.1)",
                ExpectedOutcome = "Secure and reliable internet connectivity"
            });
        }

        // Hardware recommendations
        if (deviceInfo.HardwareInfo.BiosVersion.Contains("legacy", StringComparison.OrdinalIgnoreCase))
        {
            recommendations.Add(new SecurityRecommendation
            {
                Category = "Hardware",
                Title = "Update BIOS/UEFI",
                Description = "Legacy BIOS detected, consider updating to UEFI",
                Priority = 2,
                ActionRequired = "Check for BIOS/UEFI updates from manufacturer",
                ExpectedOutcome = "Enhanced security features and performance"
            });
        }

        return recommendations;
    }

    public async Task<SecurityPosture> AnalyzeSecurityPostureAsync()
    {
        var securityPosture = new SecurityPosture();
        int score = 100; // Start with perfect score

        try
        {
            // OS Information
            var osInfo = Environment.OSVersion;
            securityPosture.OsVersion = osInfo.VersionString;
            securityPosture.OsBuild = osInfo.Version.Build.ToString();

            // Check Windows Update
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect");
                if (key != null)
                {
                    var lastUpdate = key.GetValue("LastSuccessTime");
                    if (lastUpdate != null && DateTime.TryParse(lastUpdate.ToString(), out var updateTime))
                    {
                        securityPosture.LastUpdate = updateTime;
                        var daysSinceUpdate = (DateTime.Now - updateTime).Days;
                        if (daysSinceUpdate > 30)
                        {
                            score -= 20; // Reduce score for outdated system
                        }
                    }
                }
            }
            catch
            {
                // Continue if registry access fails
            }

            // Check Windows Defender
            try
            {
                using var defenderKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender");
                if (defenderKey != null)
                {
                    securityPosture.IsWindowsDefenderEnabled = true;
                    score += 10; // Bonus for Windows Defender
                }
                else
                {
                    securityPosture.IsWindowsDefenderEnabled = false;
                    score -= 15;
                }
            }
            catch
            {
                securityPosture.IsWindowsDefenderEnabled = false;
                score -= 15;
            }

            // Check Firewall
            try
            {
                using var firewallKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile");
                if (firewallKey != null)
                {
                    var firewallEnabled = firewallKey.GetValue("EnableFirewall");
                    securityPosture.IsFirewallEnabled = firewallEnabled?.ToString() == "1";
                    if (!securityPosture.IsFirewallEnabled)
                    {
                        score -= 20;
                    }
                }
            }
            catch
            {
                securityPosture.IsFirewallEnabled = false;
                score -= 20;
            }

            // Check UAC
            try
            {
                using var uacKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                if (uacKey != null)
                {
                    var uacEnabled = uacKey.GetValue("EnableLUA");
                    securityPosture.IsUacEnabled = uacEnabled?.ToString() == "1";
                    if (!securityPosture.IsUacEnabled)
                    {
                        score -= 15;
                    }
                }
            }
            catch
            {
                securityPosture.IsUacEnabled = false;
                score -= 15;
            }

            // Check BitLocker
            try
            {
                using var bitlockerKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\FVE");
                if (bitlockerKey != null)
                {
                    securityPosture.IsBitLockerEnabled = true;
                    score += 10; // Bonus for BitLocker
                }
            }
            catch
            {
                securityPosture.IsBitLockerEnabled = false;
            }

            // Check for antivirus software
            var antivirusProducts = GetInstalledAntivirusSoftware();
            if (antivirusProducts.Any())
            {
                securityPosture.IsAntivirusInstalled = true;
                securityPosture.AntivirusName = string.Join(", ", antivirusProducts);
                securityPosture.InstalledSecuritySoftware.AddRange(antivirusProducts);
                score += 15; // Bonus for antivirus
            }
            else
            {
                securityPosture.IsAntivirusInstalled = false;
                score -= 25; // Significant penalty for no antivirus
            }

            // Ensure score is within bounds
            securityPosture.SecurityScore = Math.Max(0, Math.Min(100, score));
        }
        catch (Exception ex)
        {
            // Log error and set default values
            securityPosture.SecurityScore = 0;
        }

        return securityPosture;
    }

    public async Task<NetworkSecurity> AnalyzeNetworkSecurityAsync()
    {
        var networkSecurity = new NetworkSecurity();
        int score = 100;

        try
        {
            // Get DNS servers
            var dnsServers = GetDnsServers();
            networkSecurity.DnsServers.AddRange(dnsServers);

            // Check for suspicious DNS servers
            var suspiciousDns = new[] { "8.8.8.8", "1.1.1.1" };
            if (!dnsServers.Any(dns => suspiciousDns.Contains(dns)))
            {
                score -= 10; // Penalty for non-standard DNS
            }

            // Check for proxy
            var proxyInfo = GetProxyInformation();
            networkSecurity.IsProxyDetected = proxyInfo.IsProxy;
            networkSecurity.ProxyAddress = proxyInfo.Address;
            if (proxyInfo.IsProxy)
            {
                score -= 15; // Penalty for proxy usage
            }

            // Get active connections
            var connections = GetActiveConnections();
            networkSecurity.ActiveConnections.AddRange(connections);

            // Get open ports
            var openPorts = GetOpenPorts();
            networkSecurity.OpenPorts.AddRange(openPorts);

            // Check for VPN
            var vpnInfo = GetVpnInformation();
            networkSecurity.IsVpnActive = vpnInfo.IsVpn;
            networkSecurity.VpnProvider = vpnInfo.Provider;
            if (vpnInfo.IsVpn)
            {
                score -= 10; // Penalty for VPN usage
            }

            // Get network adapters
            var adapters = GetNetworkAdapters();
            networkSecurity.NetworkAdapters.AddRange(adapters);

            // Ensure score is within bounds
            networkSecurity.NetworkSecurityScore = Math.Max(0, Math.Min(100, score));
        }
        catch (Exception ex)
        {
            networkSecurity.NetworkSecurityScore = 0;
        }

        return networkSecurity;
    }

    public async Task<HardwareProfile> AnalyzeHardwareProfileAsync()
    {
        var hardwareProfile = new HardwareProfile();
        int score = 100;

        try
        {
            // CPU Information
            using var cpuSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor");
            foreach (ManagementObject obj in cpuSearcher.Get())
            {
                hardwareProfile.CpuModel = obj["Name"]?.ToString() ?? "";
                hardwareProfile.CpuManufacturer = obj["Manufacturer"]?.ToString() ?? "";
                break;
            }

            // RAM Information
            using var ramSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory");
            int totalRam = 0;
            foreach (ManagementObject obj in ramSearcher.Get())
            {
                if (int.TryParse(obj["Capacity"]?.ToString(), out var capacity))
                {
                    totalRam += capacity;
                }
            }
            hardwareProfile.RamSizeGb = totalRam / (1024 * 1024 * 1024);

            // GPU Information
            using var gpuSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
            foreach (ManagementObject obj in gpuSearcher.Get())
            {
                hardwareProfile.GpuModel = obj["Name"]?.ToString() ?? "";
                break;
            }

            // Motherboard Information
            using var mbSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");
            foreach (ManagementObject obj in mbSearcher.Get())
            {
                hardwareProfile.MotherboardModel = obj["Product"]?.ToString() ?? "";
                break;
            }

            // BIOS Information
            using var biosSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
            foreach (ManagementObject obj in biosSearcher.Get())
            {
                hardwareProfile.BiosVersion = obj["Version"]?.ToString() ?? "";
                hardwareProfile.BiosManufacturer = obj["Manufacturer"]?.ToString() ?? "";
                break;
            }

            // Check for virtualization
            hardwareProfile.IsVirtualMachine = IsVirtualMachine();
            if (hardwareProfile.IsVirtualMachine)
            {
                score -= 20; // Penalty for VM environment
            }

            // Check for container
            hardwareProfile.IsContainer = IsContainer();
            if (hardwareProfile.IsContainer)
            {
                score -= 25; // Penalty for container environment
            }

            // Screen resolution (simplified for .NET Core)
            hardwareProfile.ScreenResolution = "Unknown"; // Would need P/Invoke or alternative approach
            hardwareProfile.ColorDepth = 32; // Default assumption

            // Generate hardware hash
            hardwareProfile.HardwareHash = GenerateHardwareHash();

            // Ensure score is within bounds
            hardwareProfile.HardwareScore = Math.Max(0, Math.Min(100, score));
        }
        catch (Exception ex)
        {
            hardwareProfile.HardwareScore = 0;
        }

        return hardwareProfile;
    }

    public async Task<UserContext> AnalyzeUserContextAsync()
    {
        var userContext = new UserContext();
        int score = 100;

        try
        {
            // Get current Windows identity and principal
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);

            // Basic User Information
            userContext.WindowsUsername = identity.Name ?? Environment.UserName;
            userContext.UserDomain = Environment.UserDomainName ?? "LOCAL";
            userContext.UserSid = identity.User?.Value ?? "Unknown";
            userContext.UserProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            userContext.WorkingDirectory = Environment.CurrentDirectory;

            // Account Security & Privileges
            userContext.IsAdministrator = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            
            // Enhanced admin detection - check multiple methods
            if (!userContext.IsAdministrator)
            {
                // Try to detect admin privileges through alternative methods
                try
                {
                    // Check if we can access admin-only registry keys
                    using var testKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                    if (testKey != null)
                    {
                        userContext.IsAdministrator = true;
                    }
                }
                catch
                {
                    // Continue if registry access fails
                }
                
                // Check if we can access WMI with elevated privileges
                if (!userContext.IsAdministrator)
                {
                    try
                    {
                        using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                        var results = searcher.Get();
                        if (results.Count > 0)
                        {
                            userContext.IsAdministrator = true;
                        }
                    }
                    catch
                    {
                        // Continue if WMI access fails
                    }
                }
            }
            
            userContext.UserAccountType = userContext.IsAdministrator ? "Administrator" : "Standard";
            
            // Check if current process is elevated (running with admin privileges)
            userContext.IsElevated = IsProcessElevated();
            
            // Get user groups and privileges
            userContext.UserGroups = GetUserGroups(identity);
            userContext.UserPrivileges = GetUserPrivileges(identity);

            // Account Status
            userContext.LastLogin = DateTime.Now; // Current session
            userContext.AccountCreated = GetAccountCreationDate();
            userContext.PasswordLastSet = GetPasswordLastSetDate();
            userContext.PasswordExpires = GetPasswordExpirationDate();
            userContext.IsAccountLocked = false; // Would need event log analysis
            userContext.IsPasswordExpired = false; // Would need event log analysis
            userContext.FailedLoginAttempts = GetFailedLoginAttempts();

            // System Context
            userContext.TimeZone = TimeZoneInfo.Local.DisplayName;
            userContext.Language = System.Globalization.CultureInfo.CurrentCulture.DisplayName;
            userContext.KeyboardLayout = System.Globalization.CultureInfo.CurrentCulture.KeyboardLayoutId.ToString();
            userContext.PowerPlan = GetCurrentPowerPlan();

            // User Behavior & Activity
            userContext.RecentApplications = GetRecentApplications();
            userContext.RecentDocuments = GetRecentDocuments();
            userContext.StartupPrograms = GetStartupPrograms();

            // Security Context
            userContext.IsUacEnabled = IsUacEnabled();
            userContext.UacLevel = GetUacLevel();
            userContext.IsRemoteSession = IsRemoteSession();
            userContext.SessionType = GetSessionType();

            // Get user email and full name from Active Directory or local system
            var userInfo = GetUserEmailAndFullName();
            userContext.UserEmail = userInfo.Email;
            userContext.UserFullName = userInfo.FullName;
            
            // Try to detect the actual logged-in user's admin status
            var actualUserAdminStatus = GetActualUserAdminStatus();
            if (actualUserAdminStatus.HasValue)
            {
                userContext.IsAdministrator = actualUserAdminStatus.Value;
                userContext.UserAccountType = userContext.IsAdministrator ? "Administrator" : "Standard";
            }

            // Calculate risk score based on various factors
            score = CalculateUserRiskScore(userContext);

            // Ensure score is within bounds
            userContext.UserBehaviorScore = Math.Max(0, Math.Min(100, score));
        }
        catch (Exception ex)
        {
            userContext.UserBehaviorScore = 0;
        }

        return userContext;
    }

    #region Helper Methods

    private List<string> GetInstalledAntivirusSoftware()
    {
        var antivirusProducts = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM AntiVirusProduct");
            foreach (ManagementObject obj in searcher.Get())
            {
                var productName = obj["displayName"]?.ToString();
                if (!string.IsNullOrEmpty(productName))
                {
                    antivirusProducts.Add(productName);
                }
            }
        }
        catch
        {
            // Continue if WMI query fails
        }
        return antivirusProducts;
    }

    private List<string> GetDnsServers()
    {
        var dnsServers = new List<string>();
        try
        {
                    var networkInterfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
        foreach (var networkInterface in networkInterfaces)
        {
            if (networkInterface.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
            {
                var properties = networkInterface.GetIPProperties();
                foreach (var dns in properties.DnsAddresses)
                {
                    if (!dnsServers.Contains(dns.ToString()))
                    {
                        dnsServers.Add(dns.ToString());
                    }
                }
            }
        }
        }
        catch
        {
            // Continue if network query fails
        }
        return dnsServers;
    }

    private (bool IsProxy, string Address) GetProxyInformation()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key != null)
            {
                var proxyEnable = key.GetValue("ProxyEnable");
                if (proxyEnable?.ToString() == "1")
                {
                    var proxyServer = key.GetValue("ProxyServer")?.ToString() ?? "";
                    return (true, proxyServer);
                }
            }
        }
        catch
        {
            // Continue if registry access fails
        }
        return (false, "");
    }

    private List<string> GetActiveConnections()
    {
        var connections = new List<string>();
        try
        {
            var tcpConnections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            foreach (var connection in tcpConnections.Take(10)) // Limit to first 10
            {
                connections.Add($"{connection.LocalEndPoint} -> {connection.RemoteEndPoint}");
            }
        }
        catch
        {
            // Continue if connection query fails
        }
        return connections;
    }

    private List<int> GetOpenPorts()
    {
        var openPorts = new List<int>();
        try
        {
            var tcpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            foreach (var listener in tcpListeners)
            {
                openPorts.Add(listener.Port);
            }
        }
        catch
        {
            // Continue if port query fails
        }
        return openPorts;
    }

    private (bool IsVpn, string Provider) GetVpnInformation()
    {
        // Simplified VPN detection - would need more sophisticated logic
        return (false, "");
    }

    private List<string> GetNetworkAdapters()
    {
        var adapters = new List<string>();
        try
        {
                    var networkInterfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
        foreach (var networkInterface in networkInterfaces)
        {
            if (networkInterface.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
            {
                adapters.Add($"{networkInterface.Name} ({networkInterface.NetworkInterfaceType})");
            }
        }
        }
        catch
        {
            // Continue if adapter query fails
        }
        return adapters;
    }

    private bool IsVirtualMachine()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
            foreach (ManagementObject obj in searcher.Get())
            {
                var manufacturer = obj["Manufacturer"]?.ToString()?.ToLower() ?? "";
                var model = obj["Model"]?.ToString()?.ToLower() ?? "";
                
                if (manufacturer.Contains("vmware") || manufacturer.Contains("microsoft") || 
                    manufacturer.Contains("innotek") || manufacturer.Contains("parallels") ||
                    model.Contains("virtual") || model.Contains("vm"))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Continue if WMI query fails
        }
        return false;
    }

    private bool IsContainer()
    {
        // Simplified container detection
        return Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true";
    }

    private string GenerateHardwareHash()
    {
        try
        {
            var hardwareInfo = $"{Environment.MachineName}_{Environment.ProcessorCount}_{Environment.OSVersion}";
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var bytes = System.Text.Encoding.UTF8.GetBytes(hardwareInfo);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
        catch
        {
            return "unknown";
        }
    }

    private string GetCurrentPowerPlan()
    {
        try
        {
            using var process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "powercfg";
            process.StartInfo.Arguments = "/getactivescheme";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            if (output.Contains("GUID:"))
            {
                var lines = output.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Contains("GUID:"))
                    {
                        var parts = line.Split('(');
                        if (parts.Length > 1)
                        {
                            return parts[1].TrimEnd(')');
                        }
                    }
                }
            }
        }
        catch
        {
            // Continue if power plan query fails
        }
        return "Unknown";
    }

    private List<string> GetRecentApplications()
    {
        var recentApps = new List<string>();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (key != null)
            {
                // This is a simplified approach - real implementation would need to decode the UserAssist data
                recentApps.Add("Recent applications analysis not implemented");
            }
        }
        catch
        {
            // Continue if registry access fails
        }
        return recentApps;
    }

    // Enhanced User Context Helper Methods
    private bool IsProcessElevated()
    {
        try
        {
            // Method 1: Check if current process is elevated
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            var isElevated = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            
            // Method 2: Check if we can access admin-only registry keys
            if (!isElevated)
            {
                try
                {
                    using var testKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                    if (testKey != null)
                    {
                        // If we can access this key, we likely have admin privileges
                        isElevated = true;
                    }
                }
                catch
                {
                    // Continue if access fails
                }
            }
            
            // Method 3: Check if we can access WMI with elevated privileges
            if (!isElevated)
            {
                try
                {
                    using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                    var results = searcher.Get();
                    if (results.Count > 0)
                    {
                        // If WMI works, we might have elevated privileges
                        isElevated = true;
                    }
                }
                catch
                {
                    // Continue if WMI access fails
                }
            }
            
            return isElevated;
        }
        catch
        {
            return false;
        }
    }

    private List<string> GetUserGroups(System.Security.Principal.WindowsIdentity identity)
    {
        var groups = new List<string>();
        try
        {
            foreach (var group in identity.Groups)
            {
                try
                {
                    var groupName = group.Translate(typeof(System.Security.Principal.SecurityIdentifier));
                    if (groupName != null)
                    {
                        groups.Add(groupName.ToString());
                    }
                }
                catch
                {
                    // Continue if group translation fails
                }
            }
        }
        catch
        {
            // Continue if group enumeration fails
        }
        return groups;
    }

    private List<string> GetUserPrivileges(System.Security.Principal.WindowsIdentity identity)
    {
        var privileges = new List<string>();
        try
        {
            var token = identity.Token;
            if (token != IntPtr.Zero)
            {
                // Get token privileges using P/Invoke (simplified)
                privileges.Add("Token privileges analysis not implemented");
            }
        }
        catch
        {
            // Continue if privilege analysis fails
        }
        return privileges;
    }

    private DateTime GetAccountCreationDate()
    {
        try
        {
            // Try to get from registry or WMI
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{S-1-5-21-*}");
            if (key != null)
            {
                var profileLoadTime = key.GetValue("ProfileLoadTimeLow");
                if (profileLoadTime != null)
                {
                    // Convert FILETIME to DateTime
                    return DateTime.FromFileTimeUtc(Convert.ToInt64(profileLoadTime));
                }
            }
        }
        catch
        {
            // Continue if registry access fails
        }
        return DateTime.MinValue;
    }

    private DateTime GetPasswordLastSetDate()
    {
        try
        {
            // This would require Active Directory or local user management APIs
            // For now, return a placeholder
            return DateTime.MinValue;
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    private DateTime GetPasswordExpirationDate()
    {
        try
        {
            // This would require Active Directory or local user management APIs
            // For now, return a placeholder
            return DateTime.MinValue;
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    private int GetFailedLoginAttempts()
    {
        try
        {
            // This would require event log analysis
            // For now, return a placeholder
            return 0;
        }
        catch
        {
            return 0;
        }
    }

    private List<string> GetRecentDocuments()
    {
        var recentDocs = new List<string>();
        try
        {
            var recentFolder = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            if (Directory.Exists(recentFolder))
            {
                var files = Directory.GetFiles(recentFolder, "*.lnk", SearchOption.TopDirectoryOnly)
                    .Take(10)
                    .Select(f => Path.GetFileNameWithoutExtension(f))
                    .Where(f => !string.IsNullOrEmpty(f));
                recentDocs.AddRange(files);
            }
        }
        catch
        {
            // Continue if recent documents access fails
        }
        return recentDocs;
    }

    private List<string> GetStartupPrograms()
    {
        var startupPrograms = new List<string>();
        try
        {
            // Registry startup locations
            var startupKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
            };

            foreach (var keyPath in startupKeys)
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                    if (key != null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            startupPrograms.Add($"{valueName}: {keyPath}");
                        }
                    }
                }
                catch
                {
                    // Continue if individual key access fails
                }
            }
        }
        catch
        {
            // Continue if startup programs analysis fails
        }
        return startupPrograms;
    }

    private bool IsUacEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key != null)
            {
                var uacEnabled = key.GetValue("EnableLUA");
                return uacEnabled?.ToString() == "1";
            }
        }
        catch
        {
            // Continue if registry access fails
        }
        return false;
    }

    private string GetUacLevel()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key != null)
            {
                var consentPromptBehavior = key.GetValue("ConsentPromptBehaviorAdmin");
                var secureDesktop = key.GetValue("PromptOnSecureDesktop");
                
                if (consentPromptBehavior?.ToString() == "0" && secureDesktop?.ToString() == "0")
                    return "Disabled";
                else if (consentPromptBehavior?.ToString() == "1")
                    return "Prompt for credentials";
                else if (consentPromptBehavior?.ToString() == "2")
                    return "Prompt for consent";
                else if (consentPromptBehavior?.ToString() == "3")
                    return "Prompt for credentials on secure desktop";
                else if (consentPromptBehavior?.ToString() == "4")
                    return "Prompt for consent on secure desktop";
                else if (consentPromptBehavior?.ToString() == "5")
                    return "Prompt for credentials and consent on secure desktop";
            }
        }
        catch
        {
            // Continue if registry access fails
        }
        return "Unknown";
    }

    private bool IsRemoteSession()
    {
        try
        {
            return Environment.GetEnvironmentVariable("SESSIONNAME")?.StartsWith("RDP") == true ||
                   Environment.GetEnvironmentVariable("CLIENTNAME") != null;
        }
        catch
        {
            return false;
        }
    }

    private string GetSessionType()
    {
        try
        {
            if (IsRemoteSession())
            {
                if (Environment.GetEnvironmentVariable("SESSIONNAME")?.StartsWith("RDP") == true)
                    return "Remote Desktop";
                else if (Environment.GetEnvironmentVariable("CLIENTNAME") != null)
                    return "Terminal Services";
                else
                    return "Remote";
            }
            return "Local";
        }
        catch
        {
            return "Unknown";
        }
    }

    private (string Email, string FullName) GetUserEmailAndFullName()
    {
        try
        {
            // Try to get from environment variables or system
            var fullName = Environment.GetEnvironmentVariable("USERNAME") ?? Environment.UserName;
            var email = $"{fullName}@{Environment.UserDomainName ?? "local"}.com";
            
            // Try to get real full name from WMI
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_UserAccount WHERE Name = '" + fullName + "'");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var realFullName = obj["FullName"]?.ToString();
                    if (!string.IsNullOrEmpty(realFullName))
                    {
                        fullName = realFullName;
                    }
                }
            }
            catch
            {
                // Continue if WMI query fails
            }
            
            return (email, fullName);
        }
        catch
        {
            return ("unknown@local.com", Environment.UserName ?? "Unknown");
        }
    }

    private bool? GetActualUserAdminStatus()
    {
        try
        {
            // Method 1: Check for interactive session and get the actual user
            var sessionId = GetActiveSessionId();
            if (sessionId.HasValue)
            {
                var sessionUser = GetUserFromSession(sessionId.Value);
                if (!string.IsNullOrEmpty(sessionUser))
                {
                    return IsUserAdmin(sessionUser);
                }
            }
            
            // Method 2: Check if we can access user profile directories
            var userProfiles = GetUserProfileDirectories();
            foreach (var profile in userProfiles)
            {
                if (IsUserAdmin(profile))
                {
                    return true;
                }
            }
            
            return null; // Could not determine
        }
        catch
        {
            return null;
        }
    }

    private int? GetActiveSessionId()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_TSSession WHERE ConnectionState = 1");
            foreach (ManagementObject obj in searcher.Get())
            {
                var sessionId = obj["SessionId"]?.ToString();
                if (int.TryParse(sessionId, out var id))
                {
                    return id;
                }
            }
        }
        catch
        {
            // Continue if WMI query fails
        }
        return null;
    }

    private string GetUserFromSession(int sessionId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_TSSession WHERE SessionId = {sessionId}");
            foreach (ManagementObject obj in searcher.Get())
            {
                return obj["UserName"]?.ToString() ?? "";
            }
        }
        catch
        {
            // Continue if WMI query fails
        }
        return "";
    }

    private List<string> GetUserProfileDirectories()
    {
        var profiles = new List<string>();
        try
        {
            var profilesPath = Environment.GetEnvironmentVariable("SystemDrive") + "\\Users";
            if (Directory.Exists(profilesPath))
            {
                var directories = Directory.GetDirectories(profilesPath);
                foreach (var dir in directories)
                {
                    var dirName = Path.GetFileName(dir);
                    if (!dirName.StartsWith("Default") && !dirName.StartsWith("Public") && !dirName.StartsWith("Administrator"))
                    {
                        profiles.Add(dirName);
                    }
                }
            }
        }
        catch
        {
            // Continue if directory access fails
        }
        return profiles;
    }

    private bool IsUserAdmin(string username)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_GroupUser WHERE GroupComponent = 'Win32_Group.Name=\"Administrators\",Domain=\"{Environment.MachineName}\"'");
            foreach (ManagementObject obj in searcher.Get())
            {
                var partComponent = obj["PartComponent"]?.ToString() ?? "";
                if (partComponent.Contains($"Name=\"{username}\""))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Continue if WMI query fails
        }
        return false;
    }

    private int CalculateUserRiskScore(UserContext userContext)
    {
        int score = 100;

        // Admin account penalty
        if (userContext.IsAdministrator)
        {
            score -= 15; // Higher penalty for admin accounts
        }

        // Elevated process penalty
        if (userContext.IsElevated)
        {
            score -= 10;
        }

        // UAC disabled penalty
        if (!userContext.IsUacEnabled)
        {
            score -= 20;
        }

        // Remote session penalty
        if (userContext.IsRemoteSession)
        {
            score -= 10;
        }

        // Failed login attempts penalty
        if (userContext.FailedLoginAttempts > 0)
        {
            score -= Math.Min(20, userContext.FailedLoginAttempts * 5);
        }

        // Account lockout penalty
        if (userContext.IsAccountLocked)
        {
            score -= 25;
        }

        // Password expired penalty
        if (userContext.IsPasswordExpired)
        {
            score -= 15;
        }

        // Ensure score is within bounds
        return Math.Max(0, Math.Min(100, score));
    }

    #endregion
}
