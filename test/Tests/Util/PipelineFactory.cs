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
using IdentityModel.AspNetCore.OAuth2Introspection;
using Microsoft.Extensions.Options;
using System;

namespace Tests.Util
{
    class PipelineFactory
    {
        public static TestServer CreateServer(Action<OAuth2IntrospectionOptions> options, bool addCaching = false)
        {
            return new TestServer(new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseAuthentication();

                    app.Use(async (context, next) =>
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
                })
                .ConfigureServices(services =>
                {
                    if (addCaching)
                    {
                        services.AddDistributedMemoryCache();
                    }


                    // services.AddSingleton<IOptions<OAuth2IntrospectionOptions>>(new OptionsWrapper<OAuth2IntrospectionOptions>(options));

                    //services.AddAuthentication(o =>
                    //{
                    //    o.DefaultAuthenticateScheme = OAuth2IntrospectionDefaults.AuthenticationScheme;
                    //    o.DefaultChallengeScheme = OAuth2IntrospectionDefaults.AuthenticationScheme;
                    //    o.DefaultSignInScheme = OAuth2IntrospectionDefaults.AuthenticationScheme;
                    //});

                    services.AddOAuth2IntrospectionAuthentication(options);

                }));
        }

        public static HttpClient CreateClient(Action<OAuth2IntrospectionOptions> options, bool addCaching = false)
        {
            return CreateServer(options, addCaching).CreateClient();
        }

        public static HttpMessageHandler CreateHandler(Action<OAuth2IntrospectionOptions> options, bool addCaching = false)
        {
            return CreateServer(options, addCaching).CreateHandler();
        }
    }
}