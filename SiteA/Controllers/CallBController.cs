using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;

namespace SiteA.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class CallBController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public CallBController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var client = _httpClientFactory.CreateClient();

            // 1. Request Token_A from TokenServer manually
            var tokenRequestBody = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", "client_a" },
                { "client_secret", "secret_a" },
                { "scope", "api_b" }
            };

            var tokenResponse = await client.PostAsync("https://localhost:7215/connect/token", new FormUrlEncodedContent(tokenRequestBody));

            if (!tokenResponse.IsSuccessStatusCode)
            {
                return StatusCode((int)tokenResponse.StatusCode, await tokenResponse.Content.ReadAsStringAsync());
            }

            var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<JsonElement>(tokenResponseContent);
            var accessToken = tokenData.TryGetProperty("access_token", out var token) ? token.GetString() : null;

            if (string.IsNullOrEmpty(accessToken))
            {
                return BadRequest("Failed to retrieve access token.");
            }

            // 2. Call SiteB's endpoint which will then perform the exchange and call SiteC
            var apiClient = _httpClientFactory.CreateClient();
            apiClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await apiClient.GetAsync("https://localhost:7260/exchange/exchange-and-call-c");
            if (!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());
            }

            var content = await response.Content.ReadAsStringAsync();
            return Content(content, "application/json");
        }
    }
}
