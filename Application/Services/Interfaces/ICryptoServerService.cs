using Application.Models;

namespace Application.Services.Interfaces;

public interface ICryptoServerService
{
    public string GetPublicKey();

    public string Decrypt(DecryptRequest request);
}
