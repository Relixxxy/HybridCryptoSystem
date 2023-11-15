using Application.Services;
using Application.Services.Interfaces;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<ICryptoServerService, CryptoServerService>();
builder.Services.AddSingleton(RSA.Create(1024));
builder.Services.AddSingleton(serviceProvider =>
{
    var rsa = serviceProvider.GetRequiredService<RSA>();
    var certificateRequest = new CertificateRequest("CN=PavlenkoVladyslav", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    store.Add(certificate);
    store.Close();

    return certificate;
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
