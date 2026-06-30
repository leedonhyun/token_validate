using ApiA.Services;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Validation.AspNetCore;

using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
var builder = WebApplication.CreateBuilder(args);

// --- 1. Add services to the container. ---

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        //options.Authority = "https://localhost:7215";
        //options.Audience = "api_a_resource";
        //options.RequireHttpsMetadata = false;
        var authority = builder.Configuration["Oidc:Authority"] ?? throw new InvalidOperationException("Oidc:Authority is missing.");
        var audience = builder.Configuration["Oidc:Audience"] ?? throw new InvalidOperationException("Oidc:Audience is missing.");
        var certPath = builder.Configuration["Oidc:Certificates:Path"] ?? throw new InvalidOperationException("Oidc:Certificates:Path is missing.");
        var certPassword = builder.Configuration["Oidc:Certificates:Password"] ?? throw new InvalidOperationException("Oidc:Certificates:Password is missing.");
        var requireHttpsMetadata = builder.Configuration.GetValue("Oidc:RequireHttpsMetadata", !builder.Environment.IsDevelopment());

        options.Authority = authority;
        options.Audience = audience;
        options.RequireHttpsMetadata = requireHttpsMetadata;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            //TokenDecryptionKey = new X509SecurityKey(X509CertificateLoader.LoadPkcs12FromFile("oidc.pfx", "password")),
            TokenDecryptionKey = new X509SecurityKey(X509CertificateLoader.LoadPkcs12FromFile(certPath, certPassword)),
            ValidAudience = audience
        };
    });

//builder.Services.AddAuthorization();
builder.Services.AddAuthorization();

// Register services needed for manual token management
builder.Services.AddMemoryCache();
builder.Services.AddHttpClient();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<TokenExchangeService>();

var app = builder.Build();

// --- 2. Configure the HTTP request pipeline. ---

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

//app.MapGet("/forward", [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)] async (
app.MapGet("/forward", [Authorize] async (
    HttpContext context,
    TokenExchangeService tokenService,
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration) =>
{
    // 1. Get the incoming token that authenticated the call to this API
    var subjectToken = await context.GetTokenAsync("access_token");
    if (string.IsNullOrWhiteSpace(subjectToken))
    {
        return Results.Unauthorized();
    }

    try
    {
        // 2. Exchange the incoming token for a new one to call the downstream API
        var newToken = await tokenService.GetExchangedTokenAsync(subjectToken);

        // 3. Call the downstream API (ApiB) with the new token
        var downstreamApiUrl = configuration["DownstreamApi:ApiBDataUrl"] ?? throw new InvalidOperationException("DownstreamApi:ApiBDataUrl is missing.");

        var apiClient = httpClientFactory.CreateClient();
        apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", newToken);

//        var response = await apiClient.GetAsync("https://localhost:7193/data");
        var response = await apiClient.GetAsync(downstreamApiUrl);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();

        return Results.Content(content, "application/json");
    }
    catch (Exception ex)
    {
        // In a real app, use structured logging
        Console.WriteLine(ex);
        return Results.Problem("An error occurred while forwarding the request.", statusCode: 500);
    }
})
.WithName("ForwardToApiB");


app.Run();
