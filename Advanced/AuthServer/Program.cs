using AuthServer.Data;
using AuthServer.Options;
using AuthServer.Services;

using Microsoft.EntityFrameworkCore;

using OpenIddict.Validation.AspNetCore;

using System.Security.Cryptography.X509Certificates;

using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
builder.Services.Configure<OidcOptions>(builder.Configuration.GetSection(OidcOptions.SectionName));
// --- Add services to the container. ---

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {

        var oidc = builder.Configuration.GetSection(OidcOptions.SectionName).Get<OidcOptions>();

        options.SetAuthorizationEndpointUris("/connect/authorize")
                     .SetTokenEndpointUris("/connect/token");
        //options.RegisterScopes("api_a", "api_b");
        options.AllowClientCredentialsFlow()
               .AllowCustomFlow(GrantTypes.TokenExchange);
        // Register the signing and encryption credentials.
        //options.AddDevelopmentEncryptionCertificate()
        //options.AddDevelopmentSigningCertificate();

       // options.RegisterClaims(OpenIddict.Abstractions.OpenIddictConstants.Claims.Audience); // Add this line
        
        //var encryptionCert =  X509CertificateLoader.LoadPkcs12FromFile("oidc.pfx", "password");
        //var signingCert = X509CertificateLoader.LoadPkcs12FromFile("oidc.pfx", "password");

        var encryptionCert =  X509CertificateLoader.LoadPkcs12FromFile(oidc.Certificates.Path, oidc.Certificates.Password);
        var signingCert = X509CertificateLoader.LoadPkcs12FromFile(oidc.Certificates.Path, oidc.Certificates.Password);

        options.AddEncryptionCertificate(encryptionCert)
               .AddSigningCertificate(signingCert);

        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough();
    });

builder.Services.AddHostedService<TestData>();
builder.Services.AddControllers();

builder.Services.AddAuthorization(); // Kept this as per minimal sample.
//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
//});
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseForwardedHeaders();
app.MapControllers();
app.UseCors();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization(); // Kept this as per minimal sample.

// app.MapControllers(); // Removed this line.

app.MapGet("/", () => "AuthServer is running. Use the /connect/token endpoint to get a token."); // Kept this.
//app.UseEndpoints(options => {
//    options.MapControllers();
//    options.MapDefaultControllerRoute();
//});
app.Run();
