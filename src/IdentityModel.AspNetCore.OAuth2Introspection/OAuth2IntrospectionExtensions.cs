// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OAuth2IntrospectionExtensions
    {
        public static IServiceCollection AddOAuth2IntrospectionAuthentication(this IServiceCollection services) 
            => services.AddOAuth2IntrospectionAuthentication("Bearer");

        public static IServiceCollection AddOAuth2IntrospectionAuthentication(this IServiceCollection services, string authenticationScheme) 
            => services.AddOAuth2IntrospectionAuthentication(authenticationScheme, configureOptions: null);

        public static IServiceCollection AddOAuth2IntrospectionAuthentication(this IServiceCollection services, Action<OAuth2IntrospectionOptions> configureOptions) 
            => services.AddOAuth2IntrospectionAuthentication("Bearer", configureOptions);

        public static IServiceCollection AddOAuth2IntrospectionAuthentication(this IServiceCollection services, string authenticationScheme, Action<OAuth2IntrospectionOptions> configureOptions)
        {
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OAuth2IntrospectionOptions>, PostConfigureOAuth2IntrospectionOptions>());
            return services.AddScheme<OAuth2IntrospectionOptions, OAuth2IntrospectionHandler>(authenticationScheme, configureOptions);
        }
    }
}