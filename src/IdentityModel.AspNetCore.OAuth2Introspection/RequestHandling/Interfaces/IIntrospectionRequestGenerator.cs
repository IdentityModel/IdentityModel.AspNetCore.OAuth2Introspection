using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection.RequestHandling
{
    /// <summary>
    /// Customization point for generating introspection requests.
    /// </summary>
    public interface IIntrospectionRequestGenerator
    {
        /// <summary>
        /// Generates an introspection request.
        /// </summary>
        /// <param name="httpRequest"></param>
        /// <param name="options"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        ValueTask<IntrospectionRequest> GenerateRequestAsync(HttpRequest httpRequest, OAuth2IntrospectionOptions options, string token);

        /// <summary>
        /// Determines if the cached claims are still valid and should be used.
        /// </summary>
        /// <param name="httpRequest"></param>
        /// <param name="claims"></param>
        /// <returns></returns>
        ValueTask<bool> UseCacheAsync(HttpRequest httpRequest, IEnumerable<Claim> cachedClaims);
    }
}
