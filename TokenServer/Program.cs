using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// --- Configuration ---
var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("a-super-secret-key-that-is-long-enough"));
var issuer = "https://localhost:7215"; 

var clients = new Dictionary<string, string>
{
    { "client_a", "secret_a" },
    { "client_b", "secret_b" },
    { "client_c", "secret_c" } // Client for SiteC to use introspection
};

// --- Token Endpoint ---
app.MapPost("/connect/token", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var grantType = form["grant_type"].ToString();
    var clientId = form["client_id"].ToString();
    var clientSecret = form["client_secret"].ToString();

    if (string.IsNullOrEmpty(clientId) || !clients.ContainsKey(clientId) || clients[clientId] != clientSecret)
    {
        return Results.BadRequest(new { error = "invalid_client" });
    }

    if (grantType == "client_credentials")
    {
        // ... (logic remains the same)
        var scope = form["scope"].ToString();
        var audience = scope == "api_b" ? "api_b" : null;
        if (audience == null) return Results.BadRequest(new { error = "invalid_scope" });
        var claims = new[] { new Claim("client_id", clientId), new Claim(JwtRegisteredClaimNames.Sub, clientId), new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) };
        var token = CreateJwtToken(claims, audience, issuer, securityKey);
        return Results.Ok(new { access_token = token, token_type = "Bearer", expires_in = 3600 });
    }
    else if (grantType == "urn:ietf:params:oauth:grant-type:token-exchange")
    {
        // ... (logic remains the same)
        var subjectToken = form["subject_token"].ToString();
        var subjectTokenType = form["subject_token_type"].ToString();
        var requestedAudience = form["scope"] == "api_c" ? "api_c" : null;
        if (subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" || requestedAudience == null) return Results.BadRequest(new { error = "invalid_request" });
        var validationParameters = new TokenValidationParameters { ValidIssuer = issuer, ValidAudience = "api_b", IssuerSigningKey = securityKey, ValidateLifetime = true };
        var handler = new JwtSecurityTokenHandler();
        try
        {
            var validatedPrincipal = handler.ValidateToken(subjectToken, validationParameters, out _);
            var originalClientId = validatedPrincipal.FindFirst("client_id")?.Value;
            if (originalClientId == null) return Results.BadRequest(new { error = "invalid_grant", error_description = "subject_token missing client_id" });
            var claims = new[] { new Claim("client_id", clientId), new Claim(JwtRegisteredClaimNames.Sub, validatedPrincipal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? string.Empty), new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), new Claim("act", JsonSerializer.Serialize(new { sub = originalClientId }), JsonClaimValueTypes.Json) };
            var token = CreateJwtToken(claims, requestedAudience, issuer, securityKey);
            return Results.Ok(new { access_token = token, token_type = "Bearer", expires_in = 3600 });
        }
        catch (SecurityTokenException) { return Results.BadRequest(new { error = "invalid_grant" }); }
    }

    return Results.BadRequest(new { error = "unsupported_grant_type" });
});

// --- Introspection Endpoint ---
app.MapPost("/connect/introspect", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var clientId = form["client_id"].ToString();
    var clientSecret = form["client_secret"].ToString();
    var tokenToIntrospect = form["token"].ToString();

    // The introspection endpoint itself must be protected.
    // Here, we protect it by requiring a valid client_id/secret.
    if (string.IsNullOrEmpty(clientId) || !clients.ContainsKey(clientId) || clients[clientId] != clientSecret)
    {
        return Results.Unauthorized();
    }
    
    if (string.IsNullOrEmpty(tokenToIntrospect))
    {
        return Results.BadRequest(new { error = "invalid_request" });
    }

    var validationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = false, // Introspection can be for any audience
        ValidIssuer = issuer,
        IssuerSigningKey = securityKey,
        ValidateLifetime = true,
    };
    
    var handler = new JwtSecurityTokenHandler();
    try
    {
        // Validate the token
        var principal = handler.ValidateToken(tokenToIntrospect, validationParameters, out _);
        
        // If validation is successful, return active and claims
        var claims = principal.Claims.Select(c => new { c.Type, c.Value }).ToList();
        return Results.Ok(new { active = true, claims = claims, client_id = principal.FindFirst("client_id")?.Value });
    }
    catch (SecurityTokenException)
    {
        // If validation fails, return inactive
        return Results.Ok(new { active = false });
    }
});


app.Run();

// --- Helper Method ---
string CreateJwtToken(IEnumerable<Claim> claims, string audience, string issuer, SecurityKey signingKey)
{
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),
        Audience = audience,
        Issuer = issuer,
        SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature)
    };
    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}