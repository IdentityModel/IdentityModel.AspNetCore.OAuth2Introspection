// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.AspNetCore.Builder
{
    public static class OAuth2IntrospectionApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseOAuth2IntrospectionAuthentication(this IApplicationBuilder app, OAuth2IntrospectionOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<OAuth2IntrospectionMiddleware>(Options.Create(options));
        }
    }
}