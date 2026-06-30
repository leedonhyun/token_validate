using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Caching.Memory;

namespace ApiA.Services;

public class TokenExchangeService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _configuration;

    public TokenExchangeService(IHttpClientFactory httpClientFactory, IMemoryCache cache, IConfiguration configuration)
    {
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _configuration = configuration;
    }

    public async Task<string?> GetExchangedTokenAsync(string subjectToken)
    {
        // Use the subject token itself as the cache key.
        var cacheKey = $"exchanged-token:{subjectToken}";

        // Try to get the token from the cache.
        if (_cache.TryGetValue(cacheKey, out string? cachedToken))
        {
            //return cachedToken;
        }

        // --- Token not in cache, request a new one ---
        var client = _httpClientFactory.CreateClient();
        
        var tokenEndpoint = _configuration["TokenExchange:TokenEndpoint"] ?? throw new InvalidOperationException("TokenExchange:TokenEndpoint is missing.");
        var clientId = _configuration["TokenExchange:ClientId"] ?? throw new InvalidOperationException("TokenExchange:ClientId is missing.");
        var clientSecret = _configuration["TokenExchange:ClientSecret"] ?? throw new InvalidOperationException("TokenExchange:ClientSecret is missing.");
        var scope = _configuration["TokenExchange:Scope"] ?? throw new InvalidOperationException("TokenExchange:Scope is missing.");

        var requestBody = new Dictionary<string, string>
        {
            { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
            { "client_id", clientId},
            { "client_secret", clientSecret },
            { "subject_token", subjectToken },
            { "subject_token_type", "urn:ietf:params:oauth:token-type:access_token" },
            { "scope", scope }
        };

        //var tokenResponse = await client.PostAsync("https://localhost:7215/connect/token", new FormUrlEncodedContent(requestBody));
        var tokenResponse = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(requestBody));

        if (!tokenResponse.IsSuccessStatusCode)
        {
            // In a real app, handle this error more gracefully.
            throw new HttpRequestException($"Token exchange failed: {await tokenResponse.Content.ReadAsStringAsync()} (Status: {tokenResponse.StatusCode})", null, tokenResponse.StatusCode);
        }

        var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();
        var tokenData = JsonSerializer.Deserialize<TokenResponse>(tokenResponseContent);

        if (string.IsNullOrEmpty(tokenData?.AccessToken))
        {
            throw new InvalidOperationException("Failed to retrieve access token from token exchange response.");
        }

        // Cache the new token. Set an absolute expiration slightly before the token's actual expiry.
        var cacheEntryOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(TimeSpan.FromSeconds(tokenData.ExpiresIn - 30)); // 30-second buffer

        _cache.Set(cacheKey, tokenData.AccessToken, cacheEntryOptions);

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
