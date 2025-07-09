// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Hosting;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using System.Text;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;
using IdentityModel.AspNetCore.OAuth2Introspection;

namespace Tests.Util
{
    internal static class PipelineFactory
    {
        public static TestServer CreateServer(Action<OAuth2IntrospectionOptions> options, DelegatingHandler backChannelHandler, bool addCaching = false)
        {
            return new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    if (addCaching)
                    {
                        services.AddDistributedMemoryCache();
                    }

                    services
                        .AddAuthentication(OAuth2IntrospectionDefaults.AuthenticationScheme)
                        .AddOAuth2Introspection(options);

                    if (backChannelHandler != null)
                    {
                        services.AddHttpClient(OAuth2IntrospectionDefaults.BackChannelHttpClientName)
                            .AddHttpMessageHandler(() => backChannelHandler);
                    }
                })
                .Configure(app =>
                {
                    app.UseAuthentication();
                    
                    app.Run(async context =>
                    {
                        var user = context.User;

                        if (user.Identity.IsAuthenticated)
                        {
                            var responseObject = new Dictionary<string, string>
                            {
                                {"token", await context.GetTokenAsync("access_token") }
                            };

                            var json = SimpleJson.SimpleJson.SerializeObject(responseObject);

                            context.Response.StatusCode = 200;
                            await context.Response.WriteAsync(json, Encoding.UTF8);
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                        }
                    });
                }));
        }

        public static HttpClient CreateClient(Action<OAuth2IntrospectionOptions> options, DelegatingHandler handler = null, bool addCaching = false)
        {
            return CreateServer(options, handler, addCaching).CreateClient();
        }

        public static HttpMessageHandler CreateHandler(Action<OAuth2IntrospectionOptions> options, DelegatingHandler handler = null, bool addCaching = false)
        {
            return CreateServer(options, handler, addCaching).CreateHandler();
        }
    }
}
