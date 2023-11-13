using Application.Models;
using Application.Services.Interfaces;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace Application.Services;

public class CryptoServerService : ICryptoServerService
{
    private readonly RSA _rsa;
    private readonly ILogger<CryptoServerService> _logger;

    public CryptoServerService(RSA rsa, ILogger<CryptoServerService> logger)
    {
        _rsa = rsa;
        _logger = logger;
    }

    public string Decrypt(DecryptRequest request)
    {
        var key = DecryptKey(request.EncryptedKey);
        var iv = DecryptKey(request.EncryptedIV);
        var text = DecryptText(key, iv, request.EncryptedText);

        return text;
    }

    public string GetPublicKey()
    {
        var publicKey = _rsa.ExportRSAPublicKey();
        var base64PublicKey = Convert.ToBase64String(publicKey);

        var publicKeyLogString =
               "\n===============   Start   ===============\n" +
               $"{base64PublicKey}" +
               "\n===============    End    ===============\n";

        _logger.LogInformation(publicKeyLogString);

        return base64PublicKey;
    }

    private string DecryptText(string key, string iv, string encryptedText)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var ivBytes = Encoding.UTF8.GetBytes(iv);
        var encryptedBytes = Convert.FromBase64String(encryptedText);

        var result = DecryptStringFromBytes_Aes(encryptedBytes, keyBytes, ivBytes);

        return result;
    }

    private string DecryptKey(string key)
    {
        var encryptedBytes = Encoding.UTF8.GetBytes(key);
        var decryptedBytes = _rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);
        var decryptedKey = Encoding.UTF8.GetString(decryptedBytes);

        return decryptedKey;
    }

    private string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {
        if (cipherText is null || cipherText.Length <= 0)
        {
            throw new ArgumentNullException(nameof(cipherText));
        }

        if (Key is null || Key.Length <= 0)
        {
            throw new ArgumentNullException(nameof(Key));
        }

        if (IV is null || IV.Length <= 0)
        {
            throw new ArgumentNullException(nameof(IV));
        }

        using var aesAlg = Aes.Create();

        aesAlg.Key = Key;
        aesAlg.IV = IV;

        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        using var msDecrypt = new MemoryStream(cipherText);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        var plaintext = srDecrypt.ReadToEnd();

        return plaintext;
    }
}
