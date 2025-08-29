// ============================================================================
// IEncryptionService.cs - Interface for encryption and decryption operations
// ============================================================================
// This interface defines the contract for encrypting and decrypting sensitive data
// stored in files. It provides methods for both encryption and decryption operations
// to ensure data integrity and prevent tampering.
//
// For Java developers: This is similar to defining a service interface in Spring Boot
// that other components can depend on through dependency injection.
// ============================================================================

namespace DeviceInfoAPI.Services;

/// <summary>
/// Interface for encryption and decryption operations.
/// 
/// This interface defines the contract for encrypting and decrypting sensitive data
/// to ensure data integrity and prevent unauthorized tampering. It provides methods
/// for both encryption and decryption operations.
/// 
/// For Java developers: This is similar to defining a service interface in Spring Boot
/// that other components can depend on through dependency injection.
/// </summary>
public interface IEncryptionService
{
    /// <summary>
    /// Encrypts a string value using a secure encryption algorithm.
    /// </summary>
    /// <param name="plainText">The plain text string to encrypt</param>
    /// <returns>The encrypted string in base64 format</returns>
    string Encrypt(string plainText);
    
    /// <summary>
    /// Decrypts an encrypted string back to its original plain text.
    /// </summary>
    /// <param name="encryptedText">The encrypted string in base64 format</param>
    /// <returns>The decrypted plain text string</returns>
    string Decrypt(string encryptedText);
    
    /// <summary>
    /// Checks if a string is encrypted by attempting to decrypt it.
    /// </summary>
    /// <param name="text">The text to check</param>
    /// <returns>true if the text is encrypted, false otherwise</returns>
    bool IsEncrypted(string text);
}
