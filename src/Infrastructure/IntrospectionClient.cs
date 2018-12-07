using IdentityModel.Client;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure
{
    internal class IntrospectionClient
    {
        private readonly HttpClient _client;
        private readonly IntrospectionClientOptions _options;

        public IntrospectionClient(HttpClient client, IntrospectionClientOptions options)
        {
            _client = client;
            _options = options;
        }

        public Task<IntrospectionResponse> Introspect(string token, string tokenTypeHint = null)
        {
            return _client.IntrospectTokenAsync(new TokenIntrospectionRequest
            {
                Address = _options.Address,
                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody,

                Token = token,
                TokenTypeHint = tokenTypeHint
            });
        }
    }
}