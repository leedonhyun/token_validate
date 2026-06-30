using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using AuthServer.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;
using AuthServer.Options;
using Microsoft.Extensions.Options;

namespace AuthServer.Services;

public class TestData : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly OidcOptions _options;

    public TestData(IServiceProvider serviceProvider, IOptions<OidcOptions> options)
    {
        _serviceProvider = serviceProvider;
        _options = options.Value;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Create WebApp client
        //if (await manager.FindByClientIdAsync("webapp_client", cancellationToken) is null)
        if (await manager.FindByClientIdAsync(_options.WebAppClient.ClientId, cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                //ClientId = "webapp_client",
                //ClientSecret = "webapp_secret",
                //DisplayName = "WebApp Client",
                ClientId = _options.WebAppClient.ClientId,
                ClientSecret = _options.WebAppClient.ClientSecret,
                DisplayName = _options.WebAppClient.DisplayName,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Scopes.Roles, 
                    //Permissions.Prefixes.Scope + "api_a",
                    Permissions.Prefixes.Scope + _options.ApiAScope.Name,
                }
            }, cancellationToken);
        }

        // Create ApiA client (for token exchange)
        //if (await manager.FindByClientIdAsync("apia_client", cancellationToken) is null)
        if (await manager.FindByClientIdAsync(_options.ApiAClient.ClientId, cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                //ClientId = "apia_client",
                //ClientSecret = "apia_secret",
                //DisplayName = "ApiA Client",
                ClientId = _options.ApiAClient.ClientId,
                ClientSecret = _options.ApiAClient.ClientSecret,
                DisplayName = _options.ApiAClient.DisplayName,
                //        Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange // Enforce PKCE
                //},
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.GrantTypes.TokenExchange,
                    Permissions.Scopes.Roles,
                    //Permissions.Prefixes.Scope + "api_b",
                    Permissions.Prefixes.Scope + _options.ApiBScope.Name,
                        //Permissions.GrantTypes.AuthorizationCode,

                }
            }, cancellationToken);
        }

        var scopeManager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

        //if (await scopeManager.FindByNameAsync("api_a", cancellationToken) is null)
        if (await scopeManager.FindByNameAsync(_options.ApiAScope.Name, cancellationToken) is null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                //Name = "api_a",
                //Resources = { "api_a_resource" }

                Name = _options.ApiAScope.Name,
                Resources = { _options.ApiAScope.Resource }
            });
        }

        //if (await scopeManager.FindByNameAsync("api_b", cancellationToken) is null)
        if (await scopeManager.FindByNameAsync(_options.ApiBScope.Name, cancellationToken) is null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                //Name = "api_b",
                //Resources = { "api_b_resource" },

                Name = _options.ApiBScope.Name,
                Resources = { _options.ApiBScope.Resource }

            });
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}