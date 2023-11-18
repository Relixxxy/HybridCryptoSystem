using Application.Services;
using Application.Services.Interfaces;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<ICryptoServerService, CryptoServerService>();
builder.Services.AddScoped(serviceProvider =>
{
    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);

    var cert = store.Certificates.Find(X509FindType.FindBySubjectName, "PavlenkoVladyslav", false).FirstOrDefault();

    if (cert is null)
    {
        cert = CreateCertificate("p@ssw0rd!");
        
        store.Add(cert);
    }

    store.Close();

    return cert;
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

X509Certificate2 CreateCertificate(string password)
{
    var rsa = RSA.Create(1024);
    var certificateRequest = new CertificateRequest("CN=PavlenkoVladyslav", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

    var certWithPassword = new X509Certificate2(
            certificate.Export(X509ContentType.Pfx, password),
            password,
            X509KeyStorageFlags.PersistKeySet);

    return certWithPassword;
}