# IdentityModel.AspNetCore.OAuth2Introspection

ASP.NET Core authentication handler for OAuth 2.0 token introspection

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

## Configuring Backchannel HTTP Client

If configuration, such as using a proxy, is required for the HTTP client calling the Authority then it can be done by registering a named HTTP Client as follows

```csharp
services.AddHttpClient(OAuth2IntrospectionDefaults.BackChannelHttpClientName) 
    .AddHttpMessageHandler(() => 
    {
        //Configure client/handler for the back channel HTTP Client here
        return new HttpClientHandler
            {
                UseProxy = true,
                Proxy = new WebProxy(WebProxyUri, true)
            };
    }
```
