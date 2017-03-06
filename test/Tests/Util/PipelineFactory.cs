// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Hosting;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Tests.Util
{
    class PipelineFactory
    {
        public static TestServer CreateServer(OAuth2IntrospectionOptions options, bool addCaching = false)
        {
            return new TestServer(new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseOAuth2IntrospectionAuthentication(options);

                    app.Use(async (context, next) =>
                    {
                        var user = context.User;

                        if (user.Identity.IsAuthenticated)
                        {
                            var responseObject = new Dictionary<string, string>
                            {
                                {"token", await context.Authentication.GetTokenAsync("access_token") }
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
                }) 
                .ConfigureServices(services =>
                {
                    if (addCaching)
                    {
                        services.AddDistributedMemoryCache();
                    }

                    services.AddAuthentication();
                }));
        }

        public static HttpClient CreateClient(OAuth2IntrospectionOptions options, bool addCaching = false)
        {
            return CreateServer(options, addCaching).CreateClient();
        }

        public static HttpMessageHandler CreateHandler(OAuth2IntrospectionOptions options, bool addCaching = false)
        {
            return CreateServer(options, addCaching).CreateHandler();
        }
    }
}