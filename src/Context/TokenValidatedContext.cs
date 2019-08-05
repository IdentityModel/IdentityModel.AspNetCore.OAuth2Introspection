using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    public class TokenValidatedContext : ResultContext<OAuth2IntrospectionOptions>
    {
        public TokenValidatedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuth2IntrospectionOptions options)
            : base(context, scheme, options) { }

        public string SecurityToken { get; set; }
    }
}
