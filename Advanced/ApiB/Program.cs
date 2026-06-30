using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Validation.AspNetCore;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var authority = builder.Configuration["Oidc:Authority"] ?? throw new InvalidOperationException("Oidc:Authority is missing.");
        var audience = builder.Configuration["Oidc:Audience"] ?? throw new InvalidOperationException("Oidc:Audience is missing.");
        var cerPath = builder.Configuration["Oidc:Certificates:Path"] ?? throw new InvalidOperationException("Oidc:Certificates:Path is missing.");
        var cerPassword = builder.Configuration["Oidc:Certificates:Password"] ?? throw new InvalidOperationException("Oidc:Certificates:Password is missing.");
        var requireHttpsMetadata = builder.Configuration.GetValue("Oidc:RequireHttpsMetadata", !builder.Environment.IsDevelopment());

        //options.Authority = "https://localhost:7215";
        //options.Audience = "api_b_resource";
        //options.RequireHttpsMetadata = false;

        options.Authority = authority;
        options.Audience = audience;
        options.RequireHttpsMetadata = requireHttpsMetadata;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            //TokenDecryptionKey = new X509SecurityKey(X509CertificateLoader.LoadPkcs12FromFile("oidc.pfx", "password")),
            TokenDecryptionKey = new X509SecurityKey(X509CertificateLoader.LoadPkcs12FromFile(cerPath, cerPassword)),
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// A protected endpoint that requires a valid access token.
//app.MapGet("/data", [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)] (ClaimsPrincipal user) =>
app.MapGet("/data", [Authorize] (ClaimsPrincipal user) =>
{
    // The 'act' (actor) claim contains info about the original caller.
    var actor = user.FindFirst("act");
    var originalCaller = "Unknown";
    if (actor is not null)
    {
        try
        {
            // The 'act' claim can be a complex JSON object.
            // We parse it to find the original subject ('sub').
            var actClaim = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(actor.Value);
            if (actClaim.TryGetProperty("sub", out var sub))
            {
                originalCaller = sub.GetString() ?? "Unknown";
            }
        }
        catch { /* The claim might not be valid JSON, ignore */ }
    }
    
    var claims = user.Claims.Select(c => new { c.Type, c.Value });
    
    return new
    {
        message = "Hello from the super secret ApiB!",
        caller_is_client = user.FindFirst(OpenIddict.Abstractions.OpenIddictConstants.Claims.ClientId)?.Value,
        original_caller_was = originalCaller,
        all_claims = claims
    };
})
.WithName("GetData");

app.Run();
