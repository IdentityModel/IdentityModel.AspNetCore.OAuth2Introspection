using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    /// <summary>
    /// Context for the RequestSending event
    /// </summary>
    public class RequestSendingContext : BaseContext<OAuth2IntrospectionOptions>
    {
        /// <summary>
        /// ctor
        /// </summary>
        public RequestSendingContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuth2IntrospectionOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        /// The <see cref="TokenIntrospectionRequest"/> request
        /// </summary>
        public TokenIntrospectionRequest TokenIntrospectionRequest { get; set; }
    }
}
