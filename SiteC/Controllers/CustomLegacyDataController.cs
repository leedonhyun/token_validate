using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SiteC.Controllers
{
    [ApiController]
    [Route("api/custom-legacy")]
    public class CustomLegacyDataController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public CustomLegacyDataController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet("data")]
        public async Task<IActionResult> Get()
        {
            if (!Request.Headers.TryGetValue("X-Custom-Auth-Token", out var receivedTokenHeader))
            {
                return Unauthorized("Missing custom token.");
            }

            var receivedToken = receivedTokenHeader.ToString();
            var client = _httpClientFactory.CreateClient();
            var requestBody = new { token = receivedToken };
            var content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

            var response = await client.PostAsync("https://localhost:7215/api/simple-token/validate", content);

            if (!response.IsSuccessStatusCode)
            {
                return StatusCode(500, "Validation endpoint returned an error.");
            }

            var responseContent = await response.Content.ReadAsStringAsync();
            var validationData = JsonSerializer.Deserialize<JsonElement>(responseContent);

            if (!validationData.TryGetProperty("active", out var active) || active.GetBoolean() == false)
            {
                return Unauthorized("Token is not active according to TokenServer.");
            }
            
            return new JsonResult(new { 
                message = "Hello from SiteC! Authenticated via CUSTOM HEADER and validated by TokenServer.",
                validated_token = receivedToken
            });
        }
    }
}
