// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Threading.Tasks;

namespace Tests.Util
{
    class PipelineFactory
    {
        public static TestServer CreateServer(OAuth2IntrospectionOptions options)
        {
            IWebHostBuilder whb = new WebHostBuilder()
                .ConfigureServices((services) => 
                {
                    services.AddAuthentication();
                    services.AddSingleton<OAuth2IntrospectionOptions>(options);
                });

            return new TestServer(new WebHostBuilder().UseStartup<TestStartup>());
        }

        public static HttpClient CreateClient(OAuth2IntrospectionOptions options)
        {
            return CreateServer(options).CreateClient();
        }

        public static HttpMessageHandler CreateHandler(OAuth2IntrospectionOptions options)
        {
            return CreateServer(options).CreateHandler();
        }
    }
    public class TestStartup
    {
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, OAuth2IntrospectionOptions options)
        {
            app.UseOAuth2IntrospectionAuthentication(options);

            app.Use((context, next) =>
            {
                var user = context.User;

                if (user.Identity.IsAuthenticated)
                {
                    context.Response.StatusCode = 200;
                }
                else
                {
                    context.Response.StatusCode = 401;
                }

                return Task.FromResult(0);
            });
        }
    }
}