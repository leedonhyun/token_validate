using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;

namespace WebApp.Services;

public class ClientCredentialsTokenService
{
    private const string CacheKey = "ClientCredentialsToken";
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _configuration;

    public ClientCredentialsTokenService(IHttpClientFactory httpClientFactory, IMemoryCache cache, IConfiguration configuration)
    {
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _configuration = configuration;
    }

    public async Task<string?> GetTokenAsync()
    {
        // Try to get the token from the cache first.
        if (_cache.TryGetValue(CacheKey, out string? cachedToken))
        {
            return cachedToken;
        }

        // --- Token not in cache, request a new one ---
        var client = _httpClientFactory.CreateClient();
        var tokenEndpoint = _configuration["TokenClient:TokenEndpoint"] ?? throw new InvalidOperationException("TokenClient:TokenEndpoint is missing.");
        var clientId = _configuration["TokenClient:ClientId"] ?? throw new InvalidOperationException("TokenClient:ClientId is missing.");
        var clientSecret = _configuration["TokenClient:ClientSecret"] ?? throw new InvalidOperationException("TokenClient:ClientSecret is missing.");
        var scope = _configuration["TokenClient:Scope"] ?? throw new InvalidOperationException("TokenClient:Scope is missing.");

        var requestBody = new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", clientId },
            { "client_secret", clientSecret },
            { "scope", scope }
        };

        //var tokenResponse = await client.PostAsync("https://localhost:7215/connect/token", new FormUrlEncodedContent(requestBody));
        var tokenResponse = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(requestBody));

        if (!tokenResponse.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Request for client credentials token failed: {await tokenResponse.Content.ReadAsStringAsync()} (Status: {tokenResponse.StatusCode})", null, tokenResponse.StatusCode);
        }

        var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonSerializer.Deserialize<TokenResponse>(tokenResponseContent);

        if (string.IsNullOrEmpty(tokenData?.AccessToken))
        {
            throw new InvalidOperationException("Failed to retrieve access token from response.");
        }

        // Cache the new token. Set an absolute expiration slightly before the token's actual expiry.
        var cacheEntryOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromSeconds(tokenData.ExpiresIn - 30)); // 30-second buffer

        _cache.Set(CacheKey, tokenData.AccessToken, cacheEntryOptions);

        return tokenData.AccessToken;
    }

    private class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }
}
