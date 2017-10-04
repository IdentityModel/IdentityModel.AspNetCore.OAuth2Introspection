# IdentityModel.AspNetCore.OAuth2Introspection

ASP.NET Core 2 authentication handler for OAuth 2.0 token introspection

https://tools.ietf.org/html/rfc7662

## Configuration

```csharp
services.AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme)
    .AddOAuth2Introspection(options =>
    {
        options.Authority = "https://base_address_of_token_service";

        options.ClientId = "client_id_for_introspection_endpoint";
        options.ClientSecret = "client_secret_for_introspection_endpoint";
    });
```
