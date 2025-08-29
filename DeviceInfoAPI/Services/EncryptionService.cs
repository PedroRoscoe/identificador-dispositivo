using System.Security.Cryptography;
using System.Text;

namespace DeviceInfoAPI.Services;

public class EncryptionService : IEncryptionService
{
    private readonly byte[] _key;
    private const int KeySize = 256;
    private const int IvSize = 128;

    public EncryptionService()
    {
        var machineId = GetMachineId();
        _key = DeriveKey(machineId, KeySize / 8);
    }

    public string Encrypt(string plainText)
    {
        try
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            var result = new byte[aes.IV.Length + encryptedBytes.Length];
            Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
            Array.Copy(encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);

            return Convert.ToBase64String(result);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Encryption failed: {ex.Message}");
            return plainText;
        }
    }

    public string Decrypt(string encryptedText)
    {
        try
        {
            if (string.IsNullOrEmpty(encryptedText))
                return encryptedText;

            var encryptedBytes = Convert.FromBase64String(encryptedText);

            if (encryptedBytes.Length < IvSize / 8 + 1)
            {
                Console.WriteLine("Encrypted data is too short to be valid");
                return encryptedText;
            }

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var iv = new byte[IvSize / 8];
            Array.Copy(encryptedBytes, 0, iv, 0, iv.Length);
            aes.IV = iv;

            var data = new byte[encryptedBytes.Length - iv.Length];
            Array.Copy(encryptedBytes, iv.Length, data, 0, data.Length);

            using var decryptor = aes.CreateDecryptor();
            var decryptedBytes = decryptor.TransformFinalBlock(data, 0, data.Length);

            return Encoding.UTF8.GetString(decryptedBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption failed: {ex.Message}");
            return encryptedText;
        }
    }

    public bool IsEncrypted(string text)
    {
        try
        {
            if (string.IsNullOrEmpty(text))
                return false;

            var decrypted = Decrypt(text);
            return decrypted != text;
        }
        catch
        {
            return false;
        }
    }

    private string GetMachineId()
    {
        var components = new[]
        {
            Environment.MachineName,
            Environment.ProcessorCount.ToString(),
            Environment.OSVersion.ToString(),
            Environment.UserName,
            Environment.GetFolderPath(Environment.SpecialFolder.System)
        };

        return string.Join("|", components);
    }

    private byte[] DeriveKey(string password, int keySize)
    {
        const int iterations = 100000;
        var salt = Encoding.UTF8.GetBytes("DeviceInfoAPI_Salt_v1.0");

        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterations);
        return deriveBytes.GetBytes(keySize);
    }
}
