// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OAuth2IntrospectionExtensions
    {
        public static AuthenticationBuilder AddOAuth2Introspection(this AuthenticationBuilder builder) 
            => builder.AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme);

        public static AuthenticationBuilder AddOAuth2Introspection(this AuthenticationBuilder builder, string authenticationScheme) 
            => builder.AddOAuth2Introspection(authenticationScheme, configureOptions: null);

        public static AuthenticationBuilder AddOAuth2Introspection(this AuthenticationBuilder services, Action<OAuth2IntrospectionOptions> configureOptions) 
            => services.AddOAuth2Introspection(OAuth2IntrospectionDefaults.AuthenticationScheme, configureOptions: configureOptions);

        public static AuthenticationBuilder AddOAuth2Introspection(this AuthenticationBuilder builder, string authenticationScheme, Action<OAuth2IntrospectionOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OAuth2IntrospectionOptions>, PostConfigureOAuth2IntrospectionOptions>());
            return builder.AddScheme<OAuth2IntrospectionOptions, OAuth2IntrospectionHandler>(authenticationScheme, configureOptions);
        }
    }
}