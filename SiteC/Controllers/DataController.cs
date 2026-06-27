using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SiteC.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize] // Keep this for initial validation before the method is hit
    public class DataController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public DataController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            // --- Token Introspection ---
            var token = await HttpContext.GetTokenAsync("access_token");
            if (string.IsNullOrEmpty(token))
            {
                return Unauthorized("Token not found.");
            }

            var client = _httpClientFactory.CreateClient();
            var introspectionRequestBody = new Dictionary<string, string>
            {
                { "client_id", "client_c" },
                { "client_secret", "secret_c" },
                { "token", token }
            };

            var introspectionResponse = await client.PostAsync("https://localhost:7215/connect/introspect", new FormUrlEncodedContent(introspectionRequestBody));

            if (!introspectionResponse.IsSuccessStatusCode)
            {
                return StatusCode(500, "Introspection endpoint returned an error.");
            }

            var introspectionContent = await introspectionResponse.Content.ReadAsStringAsync();
            var introspectionData = JsonSerializer.Deserialize<JsonElement>(introspectionContent);

            if (!introspectionData.TryGetProperty("active", out var active) || active.GetBoolean() == false)
            {
                return Unauthorized("Token is not active.");
            }
            
            // --- Original Logic (using claims from introspection response) ---
            var claims = introspectionData.GetProperty("claims").EnumerateArray();
            var actClaim = claims.FirstOrDefault(c => c.GetProperty("type").GetString() == "act");
            string originalCaller = "Unknown";

            if (actClaim.ValueKind != JsonValueKind.Undefined)
            {
                try
                {
                    var actClaimValue = actClaim.GetProperty("value").GetString() ?? "";
                    var act = JsonSerializer.Deserialize<JsonElement>(actClaimValue);
                    if (act.TryGetProperty("sub", out var sub))
                    {
                        originalCaller = sub.GetString() ?? "Unknown";
                    }
                }
                catch
                {
                    originalCaller = "Invalid 'act' claim format";
                }
            }

            return new JsonResult(new { 
                message = "Hello from SiteC! Token validated via INTROSPECTION.",
                caller_is_client = claims.FirstOrDefault(c => c.GetProperty("type").GetString() == "client_id").GetProperty("value").GetString(),
                original_caller_was = originalCaller,
                all_claims_from_introspection = introspectionData.GetProperty("claims")
            });
        }

        [HttpGet]
        [Route("Self")]
        public IActionResult SelfValidate()
        {
            // The 'act' claim contains the information about the original actor (SiteA)
            var actorClaim = User.Claims.FirstOrDefault(c => c.Type == "act");
            string originalCaller = "Unknown";

            if (actorClaim != null)
            {
                try
                {
                    var act = JsonSerializer.Deserialize<JsonElement>(actorClaim.Value);
                    if (act.TryGetProperty("sub", out var sub))
                    {
                        originalCaller = sub.GetString() ?? "Unknown";
                    }
                }
                catch
                {
                    // Handle case where 'act' claim is not valid JSON
                    originalCaller = "Invalid 'act' claim format";
                }
            }

            var claims = User.Claims.Select(c => new { c.Type, c.Value });

            return new JsonResult(new
            {
                message = "Hello from SiteC! This data is top secret.",
                caller_is_client = User.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value,
                original_caller_was = originalCaller,
                all_claims = claims
            });
        }

    }
}
