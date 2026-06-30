using AuthServer.Options;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthServer.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly OidcOptions _oidcOptions;
        private readonly ILogger<AuthorizationController> _logger;
        private readonly JwtSecurityTokenHandler _tokenHandler = new();
        private readonly TokenValidationParameters _subjectTokenValidationParameters;
        //private readonly SignInManager<ApplicationUser> _signInManager;
        public AuthorizationController(IOpenIddictApplicationManager applicationManager
            , IOptions<OidcOptions> oidcOptions
            , ILogger<AuthorizationController> logger)
        {
            _applicationManager = applicationManager;
            _oidcOptions = oidcOptions.Value;
            _logger = logger;

            var validSubjectAudiences = new[]
            {
                _oidcOptions.ApiAScope.Resource,
                _oidcOptions.ApiBScope.Resource
            }
            .Where(resource => !string.IsNullOrWhiteSpace(resource))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

            if(validSubjectAudiences.Length == 0)
            {
                throw new InvalidOperationException("No valid subject audience is configured for token exchange.");
            }

            var cert = X509CertificateLoader.LoadPkcs12FromFile(_oidcOptions.Certificates.Path, _oidcOptions.Certificates.Password);
            var key = new X509SecurityKey(cert);

            var configuredAuthority = NormalizeIssuer(_oidcOptions.Authority);
            _subjectTokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                //ValidIssuer = _oidcOptions.Authority,
                ValidIssuers = new[] { configuredAuthority,$"{configuredAuthority}/" },
                ValidateAudience = true,
                ValidAudiences = validSubjectAudiences,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                IssuerSigningKey = key,
                TokenDecryptionKey = key,
                ClockSkew = TimeSpan.FromMinutes(1)

            };
        }

        private static string NormalizeIssuer(string issuer)
        {
            if (string.IsNullOrWhiteSpace(issuer))
            {
                throw new ArgumentException("Issuer cannot be null or whitespace.", nameof(issuer));
            }
            // Remove trailing slashes
            return issuer.Trim().TrimEnd('/');
        }
        [HttpPost("~/connect/token"), Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            //if (request.IsClientCredentialsGrantType())
            //{
            //    // Note: the client credentials are automatically validated by OpenIddict:
            //    // if client_id or client_secret are invalid, this action won't be invoked.

            //    var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
            //        throw new InvalidOperationException("The application cannot be found.");

            //    // Create a new ClaimsIdentity containing the claims that
            //    // will be used to create an id_token, a token or a code.
            //    var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

            //    // Use the client_id as the subject identifier.
            //    identity.SetClaim(Claims.Subject, await _applicationManager.GetClientIdAsync(application));
            //    identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

            //    identity.SetDestinations(static claim => claim.Type switch
            //    {
            //        // Allow the "name" claim to be stored in both the access and identity tokens
            //        // when the "profile" scope was granted (by calling principal.SetScopes(...)).
            //        Claims.Name when claim.Subject.HasScope(Scopes.Profile)
            //            => [Destinations.AccessToken, Destinations.IdentityToken],

            //        // Otherwise, only store the claim in the access tokens.
            //        _ => [Destinations.AccessToken]
            //    });

            //    return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            //}

            if (request.GrantType == "urn:ietf:params:oauth:grant-type:token-exchange")
            {
                var subjectToken = request.SubjectToken;
                var subjectTokenType = request.SubjectTokenType;
                var requestedScopes = request.GetScopes().ToList();

                if(string.IsNullOrWhiteSpace(subjectToken))
                {
                    var errorProperties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The subject token is missing."
                    });
                    return Forbid(errorProperties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }
                // 1. Ensure the subject token type matches what you support
                if (subjectTokenType != "urn:ietf:params:oauth:token-type:access_token")
                {
                     throw new InvalidOperationException("Invalid subject token type.");
                }

                ClaimsPrincipal subjectPrincipal;
                try
                {
                    subjectPrincipal = _tokenHandler.ValidateToken(subjectToken, _subjectTokenValidationParameters, out _ );

                }
                catch(Exception ex) {

                    _logger.LogWarning(ex, @"Failed to validate subject token; client_id: {ClientId}.", request.ClientId);
                    var errorProperties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The subject token is invalid."
                    });
                    return Forbid(errorProperties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                } 

                var sourceSubject = subjectPrincipal.FindFirst(Claims.Subject)?.Value
                    ?? subjectPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if(string.IsNullOrWhiteSpace(sourceSubject))
                {
                    var errorProperties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The subject token does not contain a valid subject claim."
                    });
                    return Forbid(errorProperties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                if(!IsAllowedTokenExchangePair(sourceSubject,request.ClientId))
                {
                    var errorProperties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token exchange is not allowed for this client."
                    });
                    return Forbid(errorProperties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                // 2. Validate the subjectToken here (e.g., call out to external service or check local DB)

                // 3. Create claims and issue the new token
                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                //identity.AddClaim(new Claim(Claims.Subject, "user_id_from_validated_token"));
                identity.AddClaim(new Claim(Claims.Subject, sourceSubject));
                identity.AddClaim(new Claim("act", JsonSerializer.Serialize(new { sub = request.ClientId })));

                identity.SetDestinations(static claim => claim.Type switch
                {
                    Claims.Name when claim.Subject.HasScope(Scopes.Profile)
                        => [Destinations.AccessToken, Destinations.IdentityToken],
                    _ => [Destinations.AccessToken]
                });

                var principal = new ClaimsPrincipal(identity);
                principal.SetScopes(request.GetScopes());

                var scopeManager = HttpContext.RequestServices.GetRequiredService<IOpenIddictScopeManager>();
                var resources = new List<string>();
                foreach (var scope in requestedScopes)
                {
                    var scopeObj = await scopeManager.FindByNameAsync(scope);
                    if (scopeObj != null)
                    {
                        var res = await scopeManager.GetResourcesAsync(scopeObj);
                        resources.AddRange(res);
                    }
                }
                //if(request.GetScopes().Contains("api_b") && resources.Count ==0)
                //{

                //    resources.Add("api_b_resource");
                //}
                //principal.SetResources(resources);

                if(resources.Count == 0)
                {
                    resources.AddRange(request.GetResources());
                }

                if(resources.Count == 0 && requestedScopes.Count > 0)
                {
                    var errorProperties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The requested scopes are invalid or not allowed."
                    });

                    return Forbid(errorProperties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                }

                principal.SetResources(resources);

                var properties = new AuthenticationProperties();

                return SignIn(new ClaimsPrincipal(identity), properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (request.IsClientCredentialsGrantType())
            {
                var application = await _applicationManager.FindByClientIdAsync(request.ClientId)
                    ?? throw new InvalidOperationException("The application cannot be found.");

                var clientId = await _applicationManager.GetClientIdAsync(application);

                var identity = new ClaimsIdentity(
                    TokenValidationParameters.DefaultAuthenticationType,
                    Claims.Name, Claims.Role);

                identity.SetClaim(Claims.Subject, clientId);
                identity.SetClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));
              //  identity.SetClaim(Claims.Audience, await _applicationManager.get(application));

                identity.SetDestinations(static claim => claim.Type switch
                {
                    Claims.Name when claim.Subject.HasScope(Scopes.Profile)
                        => [Destinations.AccessToken, Destinations.IdentityToken],
                    _ => [Destinations.AccessToken]
                });

                var principal = new ClaimsPrincipal(identity);
                //principal.SetPresenters([clientId!, "apia_client"]);
                var presenters = await GetAllowedPresenterClientIdsAsync(clientId);
                principal.SetPresenters(presenters);
                // 1) 스코프 설정
                principal.SetScopes(request.GetScopes());

                // 2) DB에서 스코프 → 리소스 자동 조회
                var scopeManager = HttpContext.RequestServices.GetRequiredService<IOpenIddictScopeManager>();

                var resources = new List<string>();

                foreach (var scope in request.GetScopes())
                {
                    var scopeObj = await scopeManager.FindByNameAsync(scope);
                    if (scopeObj != null)
                    {
                        var res = await scopeManager.GetResourcesAsync(scopeObj);
                        resources.AddRange(res);
                    }
                }

                // 3) principal에 리소스 설정 → aud 자동 생성됨
                principal.SetResources(resources);
//                principal.SetScopes(request.GetScopes());


                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new NotImplementedException("The specified grant is not implemented.");
        }

        private bool IsAllowedTokenExchangePair(string sourceSubject, string requesterClientId)
        {
            // Define allowed token exchange pairs
            if (string.IsNullOrWhiteSpace(requesterClientId))
            {
                return false;
            }
            if(!_oidcOptions.TokenExchange.AllowedPresenters.TryGetValue(sourceSubject, out var allowed))
            {
                return false;
            }

            return allowed.Any(candiate => string.Equals(candiate, requesterClientId, StringComparison.Ordinal));
        }
        private async Task<HashSet<string>> GetAllowedPresenterClientIdsAsync(string sourceClientId)
        {
            var presenterIds = new HashSet<string>(StringComparer.Ordinal);

            presenterIds.Add(sourceClientId);

            if(!_oidcOptions.TokenExchange.AllowedPresenters.TryGetValue(sourceClientId, out var configuredPresenters))
            {
                return presenterIds;
            }

            foreach(var presenterId in configuredPresenters)
            {
                if(string.IsNullOrWhiteSpace(presenterId))
                {
                    continue;
                }

                var application = await _applicationManager.FindByClientIdAsync(presenterId);
                if(application == null)
                {
                    continue;
                }


                var permissions = await _applicationManager.GetPermissionsAsync(application);
                var hasTokenExchange = permissions.Any(p => string.Equals(p, Permissions.GrantTypes.TokenExchange, StringComparison.Ordinal));

                if(!hasTokenExchange)
                {
                    continue;
                }

                var clientId = await _applicationManager.GetClientIdAsync(application);
                if(!string.IsNullOrWhiteSpace(clientId))
                {
                    presenterIds.Add(clientId);
                }
            }

            return presenterIds;
            //if (!string.IsNullOrWhiteSpace(sourceClientId))
            //{
            //    presenters.Add(sourceClientId);
            //}


            //await foreach(var app in _applicationManager.ListAsync())
            //{
            //    var permissions = await _applicationManager.GetPermissionsAsync(app);
            //    var canExchange = false;

            //    foreach (var permission in permissions)
            //    {
            //        if(string.Equals(permission, Permissions.GrantTypes.TokenExchange, StringComparison.Ordinal))
            //        {
            //            canExchange = true;
            //            break;
            //        }
            //    }

            //    if(!canExchange)
            //    {
            //        continue;
            //    }
            //    var clientId = await _applicationManager.GetClientIdAsync(app);
            //    if (!string.IsNullOrWhiteSpace(clientId))
            //    {
            //        presenters.Add(clientId);
            //    }
            //}

            //return presenters;
        }

        //private async Task<IActionResult> HandleExchangeCodeGrantType()
        //{
        //    // Retrieve the claims principal stored in the authorization code/device code/refresh token.
        //    var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

        //    // Retrieve the user profile corresponding to the authorization code/refresh token.
        //    // Note: if you want to automatically invalidate the authorization code/refresh token
        //    // when the user password/roles change, use the following line instead:
        //    // var user = _signInManager.ValidateSecurityStampAsync(info.Principal);
        //    var user = await _userManager.GetUserAsync(principal);
        //    if (user == null)
        //    {
        //        return Forbid(
        //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        //            properties: new AuthenticationProperties(new Dictionary<string, string>
        //            {
        //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
        //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The token is no longer valid."
        //            }));
        //    }

        //    // Ensure the user is still allowed to sign in.
        //    if (!await _signInManager.CanSignInAsync(user))
        //    {
        //        return Forbid(
        //            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        //            properties: new AuthenticationProperties(new Dictionary<string, string>
        //            {
        //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
        //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
        //            }));
        //    }

        //    foreach (var claim in principal.Claims)
        //    {
        //        claim.SetDestinations(GetDestinations(claim, principal));
        //    }

        //    // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        //    return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        //}

        //private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        //{
        //    // Note: by default, claims are NOT automatically included in the access and identity tokens.
        //    // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        //    // whether they should be included in access tokens, in identity tokens or in both.

        //    switch (claim.Type)
        //    {
        //        case Claims.Name:
        //            yield return Destinations.AccessToken;

        //            if (principal.HasScope(Scopes.Profile))
        //                yield return Destinations.IdentityToken;

        //            yield break;

        //        case Claims.Email:
        //            yield return Destinations.AccessToken;

        //            if (principal.HasScope(Scopes.Email))
        //                yield return Destinations.IdentityToken;

        //            yield break;

        //        case Claims.Role:
        //            yield return Destinations.AccessToken;

        //            if (principal.HasScope(Scopes.Roles))
        //                yield return Destinations.IdentityToken;

        //            yield break;

        //        // Never include the security stamp in the access and identity tokens, as it's a secret value.
        //        case "AspNet.Identity.SecurityStamp": yield break;

        //        default:
        //            yield return Destinations.AccessToken;
        //            yield break;
        //    }
        //}
    }
}
