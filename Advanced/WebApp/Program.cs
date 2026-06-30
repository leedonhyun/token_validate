using System.Net.Http.Headers;
using System.Text.Json;
using WebApp.Services;

var builder = WebApplication.CreateBuilder(args);

// --- 1. Add services to the container. ---

builder.Services.AddMemoryCache();
builder.Services.AddHttpClient();
builder.Services.AddScoped<ClientCredentialsTokenService>();

var app = builder.Build();

// --- 2. Configure the HTTP request pipeline. ---

app.UseHttpsRedirection();

app.MapGet("/", async (
    ClientCredentialsTokenService tokenService, 
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration) =>
{
    try
    {
        // 1. Get a token for ApiA
        var token = await tokenService.GetTokenAsync();

        // 2. Call ApiA with the token
        var apiClient = httpClientFactory.CreateClient();
        var apiAForwardUrl = configuration["DownstreamApi:ApiAForwardUrl"] ?? throw new InvalidOperationException("ApiA:ForwardUrl is missing.");
        apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        
        var response = await apiClient.GetAsync(apiAForwardUrl);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();

        // 3. Display the final result from ApiB
        using var jsonDoc = JsonDocument.Parse(content);
        var prettyJson = JsonSerializer.Serialize(jsonDoc, new JsonSerializerOptions { WriteIndented = true });

        return Results.Content(
            $"""
            <html>
                <body>
                    <h1>Success! (Manual Token Management)</h1>
                    <p>Called WebApp -> ApiA -> ApiB and got the final response from ApiB:</p>
                    <pre style="background-color: #f0f0f0; padding: 15px;"><code>{prettyJson}</code></pre>
                </body>
            </html>
            """,
            "text/html");
    }
    catch (Exception ex)
    {
        return Results.Content(
            $"""
            <html>
                <body>
                    <h1>Error!</h1>
                    <p>Failed to complete the call chain.</p>
                    <p><strong>Error:</strong> {ex.Message}</p>
                    <hr/>
                    <p><strong>Details:</strong></p>
                    <pre style="background-color: #f0f0f0; padding: 15px;"><code>{ex.ToString()}</code></pre>
                </body>
            </html>
            """,
            "text/html");
    }
});

app.Run();
