using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection.RequestHandling
{
    public class DefaultIntrospectionRequestGenerator : IIntrospectionRequestGenerator
    {
        public ValueTask<IntrospectionRequest> GenerateRequestAsync(
            HttpRequest httpRequest, 
            OAuth2IntrospectionOptions options, 
            string token)
        {
            // Default introspection request
            return new ValueTask<IntrospectionRequest>(new IntrospectionRequest
            {
                Token = token,
                TokenTypeHint = OidcConstants.TokenTypes.AccessToken,
                ClientId = options.ClientId,
                ClientSecret = options.ClientSecret
            });
        }

        public ValueTask<bool> UseCacheAsync(HttpRequest httpRequest, IEnumerable<Claim> cachedClaims)
        {
            // Always use cached claims
            return new ValueTask<bool>(true);
        }
    }
}
