namespace Application.Services.Interfaces;

public interface ICryptoClientService
{
    public string Encrypt(string text);

    public string Decrypt(string text);
}
