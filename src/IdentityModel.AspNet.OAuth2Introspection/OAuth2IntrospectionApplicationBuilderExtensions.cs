// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.AspNet.OAuth2Introspection;
using System;

namespace Microsoft.AspNet.Builder
{
    public static class OAuth2IntrospectionApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseOAuth2IntrospectionAuthentication(this IApplicationBuilder app, Action<OAuth2IntrospectionOptions> configureOptions)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            var options = new OAuth2IntrospectionOptions();
            if (configureOptions != null)
            {
                configureOptions(options);
            }

            return app.UseMiddleware<OAuth2IntrospectionMiddleware>(options);
        }

        public static IApplicationBuilder UseOAuth2IntrospectionAuthentication(this IApplicationBuilder app, OAuth2IntrospectionOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<OAuth2IntrospectionMiddleware>(options);
        }
    }
}