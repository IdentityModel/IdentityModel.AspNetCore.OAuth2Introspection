using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    public class AuthenticationFailedContext : ResultContext<OAuth2IntrospectionOptions>
    {
        public AuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            OAuth2IntrospectionOptions options)
            : base(context, scheme, options) { }

        public string Error { get; set; }
    }
}
