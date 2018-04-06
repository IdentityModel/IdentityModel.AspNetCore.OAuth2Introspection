// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Tests.Util
{
    class DiscoveryEndpointHandler : HttpMessageHandler
    {
        public string Endpoint { get; set; }

        public bool IsFailureTest { get; set; } = false;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            if (IsFailureTest)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            if (request.RequestUri.AbsoluteUri.ToString() == "https://authority.com/.well-known/openid-configuration")
            {
                Endpoint = request.RequestUri.AbsoluteUri;

                var data = new Dictionary<string, object>
                {
                    { "issuer", "https://authority.com" },
                    { "introspection_endpoint", "https://authority.com/introspection_endpoint" }
                };

                var json = SimpleJson.SimpleJson.SerializeObject(data);

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent(json, Encoding.UTF8, "application/json");

                return Task.FromResult(response);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}