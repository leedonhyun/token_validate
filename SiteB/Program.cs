using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// --- Configuration ---
// This key must be identical to the one in TokenServer to validate the token signature.
var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("a-super-secret-key-that-is-long-enough"));

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddHttpClient(); // For token exchange

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "https://localhost:7215", // Address of TokenServer
            ValidAudience = "api_b",
            IssuerSigningKey = securityKey
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
