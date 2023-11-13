namespace Application.Services.Interfaces;

public interface ICryptoClientService
{
    public Task<string> EncryptDecryptAsync(string text);
}
