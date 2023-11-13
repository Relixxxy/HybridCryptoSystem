using Application.Models;
using Application.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CryptoController : ControllerBase
{
    private readonly ICryptoServerService _cryptoService;

    public CryptoController(ICryptoServerService cryptoService)
    {
        _cryptoService = cryptoService;
    }

    [HttpGet("key")]
    public IActionResult GetPublicKey()
    {
        var result = _cryptoService.GetPublicKey();

        return Ok(result);
    }

    [HttpPost("decrypt")]
    public IActionResult Decrypt(DecryptRequest request)
    {
        var result = _cryptoService.Decrypt(request);

        return Ok(result);
    }
}
