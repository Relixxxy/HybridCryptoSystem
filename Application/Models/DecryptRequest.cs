namespace Application.Models;

public class DecryptRequest
{
    public string EncryptedKey { get; init; } = default!;

    public string EncryptedIV { get; init; } = default!;

    public string EncryptedText { get; init; } = default!;

}
