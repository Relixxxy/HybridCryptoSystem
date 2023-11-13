using Application.Models;
using Application.Services.Interfaces;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;

namespace Application.Services;

public class CryptoClientService : ICryptoClientService
{
    private readonly RSA _rsa;
    private readonly Aes _aes;
    private readonly HttpClient _httpClient;
    private readonly ILogger<CryptoClientService> _logger;

    public CryptoClientService(
        RSA rsa,
        Aes aes,
        HttpClient httpClient,
        ILogger<CryptoClientService> logger)
    {
        _rsa = rsa;
        _aes = aes;
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<string> EncryptDecryptAsync(string text)
    {
        await SetPublicKeyAsync();

        var encryptedKey = EncryptKey(_aes.Key);
        var encryptedIV = EncryptKey(_aes.IV);
        var encryptedText = EncryptText(text);

        var request = new DecryptRequest
        {
            EncryptedText = encryptedText,
            EncryptedKey = encryptedKey,
            EncryptedIV = encryptedIV
        };

        var json = JsonSerializer.Serialize(request);

        var httpContent = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _httpClient.PostAsync("decrypt", httpContent);

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync();

            return content;
        }

        return string.Empty;
    }

    private async Task SetPublicKeyAsync()
    {
        var response = await _httpClient.GetAsync("key");

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync();

            var publicKeyBytes = Convert.FromBase64String(content);

            _rsa.ImportRSAPublicKey(publicKeyBytes, out _);

            var publicKeyLogString =
                "\n===============   Start   ===============\n" +
                $"{content}" +
                "\n===============    End    ===============\n";

            _logger.LogInformation("Public key successfuly set.{0}", publicKeyLogString);
        }
    }

    private string EncryptKey(byte[] keyBytes)
    {
        var encryptedBytes = _rsa.Encrypt(keyBytes, RSAEncryptionPadding.Pkcs1);
        var encryptedKey = Encoding.UTF8.GetString(encryptedBytes);

        return encryptedKey;
    }

    private string EncryptText(string plainText)
    {
        if (plainText is null || plainText.Length <= 0)
        {
            throw new ArgumentNullException(nameof(plainText));
        }

        ICryptoTransform encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV);

        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
            swEncrypt.Flush();
        }

        var encryptedBytes = msEncrypt.ToArray();

        return Convert.ToBase64String(encryptedBytes);
    }
}
