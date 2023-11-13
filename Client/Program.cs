using Application.Services;
using Application.Services.Interfaces;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

builder.Services.AddHttpClient<ICryptoClientService, CryptoClientService>(
    options =>
    {
        options.BaseAddress = new Uri("http://localhost:5001/api/crypto/");
    });
builder.Services.AddScoped(_ => RSA.Create());
builder.Services.AddScoped(_ => Aes.Create());

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
