using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace SiteA.Controllers
{
    [ApiController]
    [Route("api/custom-header")]
    public class CustomHeaderController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public CustomHeaderController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet("call-b")]
        public async Task<IActionResult> CallB()
        {
            var client = _httpClientFactory.CreateClient();
            
            // 1. Get a new simple token from the TokenServer
            var tokenGenerationResponse = await client.GetAsync("https://localhost:7215/api/simple-token/generate");
            if (!tokenGenerationResponse.IsSuccessStatusCode)
            {
                return StatusCode(500, "Failed to generate a simple token from TokenServer.");
            }

            var tokenContent = await tokenGenerationResponse.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<JsonElement>(tokenContent);
            var simpleToken = tokenData.TryGetProperty("token", out var token) ? token.GetString() : null;

            if (string.IsNullOrEmpty(simpleToken))
            {
                return StatusCode(500, "Could not parse the simple token from TokenServer's response.");
            }

            // 2. Call SiteB with the custom header and the new token
            var siteBClient = _httpClientFactory.CreateClient();
            siteBClient.DefaultRequestHeaders.Add("X-Custom-Auth-Token", simpleToken);
            
            var response = await siteBClient.GetAsync("https://localhost:7260/api/custom-legacy/call-c");

            if (!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());
            }

            var content = await response.Content.ReadAsStringAsync();
            return Content(content, "application/json");
        }
    }
}
