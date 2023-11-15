using Application.Models;
using Application.Services.Interfaces;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Application.Services;

public class CryptoServerService : ICryptoServerService
{
    private readonly RSA _rsaPrivate;
    private readonly RSA _rsaPublic;
    private readonly ILogger<CryptoServerService> _logger;

    public CryptoServerService(X509Certificate2 certificate, ILogger<CryptoServerService> logger)
    {
        _logger = logger;
        _rsaPrivate = certificate.GetRSAPrivateKey();
        _rsaPublic = certificate.GetRSAPublicKey();
    }

    public string Decrypt(DecryptRequest request)
    {
        var keyBytes = DecryptKeyToBytes(request.EncryptedKey);
        var ivBytes = DecryptKeyToBytes(request.EncryptedIV);
        var text = DecryptText(keyBytes, ivBytes, request.EncryptedText);

        return text;
    }

    public string GetPublicKey()
    {
        var publicKey = _rsaPublic.ExportRSAPublicKey();
        var base64PublicKey = Convert.ToBase64String(publicKey);

        var publicKeyLogString =
               "\n===============   Start   ===============\n" +
               $"{base64PublicKey}" +
               "\n===============    End    ===============\n";

        _logger.LogInformation(publicKeyLogString);

        return base64PublicKey;
    }

    private string DecryptText(byte[] keyBytes, byte[] ivBytes, string encryptedText)
    {
        var encryptedBytes = Convert.FromBase64String(encryptedText);

        var result = DecryptStringFromBytes_Aes(encryptedBytes, keyBytes, ivBytes);

        return result;
    }

    private byte[] DecryptKeyToBytes(string key)
    {
        var encryptedBytes = Convert.FromBase64String(key);
        var decryptedBytes = _rsaPrivate.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

        return decryptedBytes;
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
