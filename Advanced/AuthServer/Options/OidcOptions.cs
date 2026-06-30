namespace AuthServer.Options;

public class OidcOptions
{
    public const string SectionName = "Oidc";

    public string Authority { get; set; } = string.Empty;


    public CertificatesOptions Certificates { get; set; } = new ();

    public ClientOptions WebAppClient { get; set; } = new ();
    public ClientOptions ApiAClient { get; set; } = new ();

    public ScopeOptions ApiAScope { get; set; } = new ();
    public ScopeOptions ApiBScope { get; set; } = new ();

    public TokenExchangeScopeOptions TokenExchange { get; set; } = new ();
}

public class CertificatesOptions
{
    public string Path { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class ClientOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
}

public class ScopeOptions
{
    public string Name { get; set; } = string.Empty;
    public string Resource { get; set; } = string.Empty;
}

public class TokenExchangeScopeOptions
{
    public Dictionary<string, List<string>> AllowedPresenters { get; set; } = new (StringComparer.Ordinal);
}
