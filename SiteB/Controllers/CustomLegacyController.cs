using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace SiteB.Controllers
{
    [ApiController]
    [Route("api/custom-legacy")]
    public class CustomLegacyController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public CustomLegacyController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet("call-c")]
        public async Task<IActionResult> CallC()
        {
            // 1. Validate incoming token from SiteA by asking TokenServer
            if (!Request.Headers.TryGetValue("X-Custom-Auth-Token", out var receivedTokenHeader))
            {
                return Unauthorized("Missing custom token.");
            }

            var receivedToken = receivedTokenHeader.ToString();
            var validationClient = _httpClientFactory.CreateClient();
            var requestBody = new { token = receivedToken };
            var content = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");

            var validationResponse = await validationClient.PostAsync("https://localhost:7215/api/simple-token/validate", content);

            if (!validationResponse.IsSuccessStatusCode)
            {
                return StatusCode(500, "Validation endpoint returned an error.");
            }

            var responseContent = await validationResponse.Content.ReadAsStringAsync();
            var validationData = JsonSerializer.Deserialize<JsonElement>(responseContent);

            if (!validationData.TryGetProperty("active", out var active) || active.GetBoolean() == false)
            {
                return Unauthorized("Token is not active according to TokenServer.");
            }

            // 2. Call SiteC with the same (now validated) token
            var siteCClient = _httpClientFactory.CreateClient();
            siteCClient.DefaultRequestHeaders.Add("X-Custom-Auth-Token", receivedToken);
            
            var siteCResponse = await siteCClient.GetAsync("https://localhost:7193/api/custom-legacy/data");

            if (!siteCResponse.IsSuccessStatusCode)
            {
                return StatusCode((int)siteCResponse.StatusCode, "Call to SiteC failed: " + await siteCResponse.Content.ReadAsStringAsync());
            }
            
            var siteCContent = await siteCResponse.Content.ReadAsStringAsync();
            return Content(siteCContent, "application/json");
        }
    }
}
