using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Tinkoff.IdentityModel.AspNetCore.OAuth2Introspection
{
    /// <summary>
    /// Context for the SendingRequest event
    /// </summary>
    public class SendingRequestContext : BaseContext<OAuth2IntrospectionOptions>
    {
        /// <summary>
        /// ctor
        /// </summary>
        public SendingRequestContext(
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
