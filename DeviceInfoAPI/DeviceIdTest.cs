using System;
using System.Management;
using Microsoft.Win32;
using System.Net.NetworkInformation;
using System.Linq;
using System.Collections.Generic; // Added for List<string>

namespace DeviceInfoAPI
{
    public class DeviceIdTest
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("=== Windows Device Identifier Test ===");
            Console.WriteLine("Querying all available device identifiers...\n");

            try
            {
                // Test all identifier sources
                TestWmiIdentifiers();
                TestRegistryIdentifiers();
                TestNetworkIdentifiers();
                TestEnvironmentIdentifiers();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during testing: {ex.Message}");
            }

            Console.WriteLine("\n=== Test Complete ===");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static void TestWmiIdentifiers()
        {
            Console.WriteLine("--- WMI (Windows Management Instrumentation) Identifiers ---");
            
            try
            {
                // BIOS/UEFI UUID
                using var searcher1 = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct");
                foreach (ManagementObject obj in searcher1.Get())
                {
                    var uuid = obj["UUID"]?.ToString();
                    if (!string.IsNullOrEmpty(uuid))
                    {
                        Console.WriteLine($"BIOS/UEFI UUID: {uuid}");
                    }
                }

                // Computer System Info
                using var searcher2 = new ManagementObjectSearcher("SELECT Name, GUID, SID FROM Win32_ComputerSystem");
                foreach (ManagementObject obj in searcher2.Get())
                {
                    var name = obj["Name"]?.ToString();
                    var guid = obj["GUID"]?.ToString();
                    var sid = obj["SID"]?.ToString();

                    if (!string.IsNullOrEmpty(name))
                        Console.WriteLine($"Computer Name: {name}");
                    if (!string.IsNullOrEmpty(guid))
                        Console.WriteLine($"Computer GUID: {guid}");
                    if (!string.IsNullOrEmpty(sid))
                        Console.WriteLine($"Computer SID: {sid}");
                }

                // Additional System Product Info
                using var searcher3 = new ManagementObjectSearcher("SELECT Name, IdentifyingNumber, SKU, Vendor FROM Win32_ComputerSystemProduct");
                foreach (ManagementObject obj in searcher3.Get())
                {
                    var name = obj["Name"]?.ToString();
                    var identifyingNumber = obj["IdentifyingNumber"]?.ToString();
                    var sku = obj["SKU"]?.ToString();
                    var vendor = obj["Vendor"]?.ToString();

                    if (!string.IsNullOrEmpty(name))
                        Console.WriteLine($"System Product Name: {name}");
                    if (!string.IsNullOrEmpty(identifyingNumber))
                        Console.WriteLine($"Identifying Number: {identifyingNumber}");
                    if (!string.IsNullOrEmpty(sku))
                        Console.WriteLine($"SKU: {sku}");
                    if (!string.IsNullOrEmpty(vendor))
                        Console.WriteLine($"Vendor: {vendor}");
                }

                // Hardware Hash (Windows 10+)
                using var searcher4 = new ManagementObjectSearcher("SELECT HardwareID FROM Win32_ComputerSystemProduct");
                foreach (ManagementObject obj in searcher4.Get())
                {
                    var hardwareId = obj["HardwareID"]?.ToString();
                    if (!string.IsNullOrEmpty(hardwareId))
                    {
                        Console.WriteLine($"Hardware ID: {hardwareId}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WMI Error: {ex.Message}");
            }
        }

        private static void TestRegistryIdentifiers()
        {
            Console.WriteLine("\n--- Registry Identifiers ---");
            
            try
            {
                // Windows NT CurrentVersion
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (key != null)
                {
                    var productId = key.GetValue("ProductId")?.ToString();
                    var installationId = key.GetValue("InstallationId")?.ToString();
                    var machineGuid = key.GetValue("MachineGuid")?.ToString();
                    var productName = key.GetValue("ProductName")?.ToString();
                    var buildLab = key.GetValue("BuildLab")?.ToString();

                    if (!string.IsNullOrEmpty(productId))
                        Console.WriteLine($"Product ID: {productId}");
                    if (!string.IsNullOrEmpty(installationId))
                        Console.WriteLine($"Installation ID: {installationId}");
                    if (!string.IsNullOrEmpty(machineGuid))
                        Console.WriteLine($"Machine GUID: {machineGuid}");
                    if (!string.IsNullOrEmpty(productName))
                        Console.WriteLine($"Product Name: {productName}");
                    if (!string.IsNullOrEmpty(buildLab))
                        Console.WriteLine($"Build Lab: {buildLab}");
                }

                // Windows CurrentVersion
                using var key2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion");
                if (key2 != null)
                {
                    var devicePath = key2.GetValue("DevicePath")?.ToString();
                    if (!string.IsNullOrEmpty(devicePath))
                        Console.WriteLine($"Device Path: {devicePath}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Registry Error: {ex.Message}");
            }
        }

        private static void TestNetworkIdentifiers()
        {
            Console.WriteLine("\n--- Network Interface Identifiers ---");
            
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                var macAddresses = new List<string>();

                foreach (var nic in interfaces)
                {
                    if (nic.OperationalStatus == OperationalStatus.Up)
                    {
                        var mac = nic.GetPhysicalAddress();
                        if (mac != null && mac.GetAddressBytes().Length > 0)
                        {
                            var macString = BitConverter.ToString(mac.GetAddressBytes()).Replace("-", ":");
                            macAddresses.Add(macString);
                            Console.WriteLine($"MAC Address ({nic.Name}): {macString}");
                        }
                    }
                }

                if (macAddresses.Any())
                {
                    Console.WriteLine($"Total Active MAC Addresses: {macAddresses.Count}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Network Error: {ex.Message}");
            }
        }

        private static void TestEnvironmentIdentifiers()
        {
            Console.WriteLine("\n--- Environment Identifiers ---");
            
            try
            {
                var machineName = Environment.MachineName;
                var userName = Environment.UserName;
                var userDomainName = Environment.UserDomainName;
                var osVersion = Environment.OSVersion.ToString();
                var processorCount = Environment.ProcessorCount;
                var systemPageSize = Environment.SystemPageSize;
                var workingSet = Environment.WorkingSet;
                var tickCount = Environment.TickCount;

                Console.WriteLine($"Machine Name: {machineName}");
                Console.WriteLine($"User Name: {userName}");
                Console.WriteLine($"User Domain: {userDomainName}");
                Console.WriteLine($"OS Version: {osVersion}");
                Console.WriteLine($"Processor Count: {processorCount}");
                Console.WriteLine($"System Page Size: {systemPageSize}");
                Console.WriteLine($"Working Set: {workingSet}");
                Console.WriteLine($"Tick Count: {tickCount}");

                // Generate a hash from machine name as fallback
                var fallbackId = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(machineName))
                    .Replace("/", "_")
                    .Replace("+", "-")
                    .Replace("=", "")
                    .Substring(0, Math.Min(16, machineName.Length));
                
                Console.WriteLine($"Fallback ID (from machine name): {fallbackId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Environment Error: {ex.Message}");
            }
        }
    }
}
