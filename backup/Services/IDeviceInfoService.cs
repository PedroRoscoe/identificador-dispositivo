using DeviceInfoAPI.Models;

namespace DeviceInfoAPI.Services;

public interface IDeviceInfoService
{
    Task<DeviceInfo> GetDeviceInfoAsync();
    DeviceInfo GetDeviceInfo();
}
