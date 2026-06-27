using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Text.Json;

namespace SiteB.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ExchangeController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public ExchangeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet]
        [Route("protected")]
        [Authorize]
        public IActionResult GetProtectedData()
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value });
            return new JsonResult(new { message = "Hello from SiteB's protected endpoint!", claims });
        }

        [HttpGet]
        [Route("exchange-and-call-c")] // Renamed for clarity
        [Authorize]
        public async Task<IActionResult> ExchangeAndCallC()
        {
            // 1. Get Token_A
            var originalToken = await HttpContext.GetTokenAsync("access_token");
            if (string.IsNullOrWhiteSpace(originalToken))
            {
                return BadRequest("Original token not found.");
            }

            var client = _httpClientFactory.CreateClient();

            // 2. Exchange Token_A for Token_B_to_C
            var requestBody = new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                { "client_id", "client_b" },
                { "client_secret", "secret_b" },
                { "subject_token", originalToken },
                { "subject_token_type", "urn:ietf:params:oauth:token-type:access_token" },
                { "scope", "api_c" }
            };
            var tokenResponse = await client.PostAsync("https://localhost:7215/connect/token", new FormUrlEncodedContent(requestBody));

            if (!tokenResponse.IsSuccessStatusCode)
            {
                return StatusCode((int)tokenResponse.StatusCode, "Token exchange failed: " + await tokenResponse.Content.ReadAsStringAsync());
            }

            var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<JsonElement>(tokenResponseContent);
            var newToken = tokenData.TryGetProperty("access_token", out var token) ? token.GetString() : null;

            if (string.IsNullOrEmpty(newToken))
            {
                return BadRequest("Failed to retrieve exchanged token.");
            }

            // 3. Call SiteC with the new token
            var siteCClient = _httpClientFactory.CreateClient();
            siteCClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", newToken);

            var siteCResponse = await siteCClient.GetAsync("https://localhost:7193/data");
            
            if (!siteCResponse.IsSuccessStatusCode)
            {
                return StatusCode((int)siteCResponse.StatusCode, "Call to SiteC failed: " + await siteCResponse.Content.ReadAsStringAsync());
            }
            
            var siteCContent = await siteCResponse.Content.ReadAsStringAsync();
            return Content(siteCContent, "application/json");
        }
    }
}
