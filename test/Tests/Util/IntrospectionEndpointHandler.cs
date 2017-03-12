// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tests.Util
{
    class IntrospectionEndpointHandler : HttpMessageHandler
    {
        private readonly Behavior _behavior;

        public enum Behavior
        {
            Active,
            Inactive,
            Unauthorized
        }

        public Dictionary<string, object> AdditionalValues { get; set; } = new Dictionary<string, object>();
        public string Endpoint { get; set; }

        public IntrospectionEndpointHandler(Behavior behavior, TimeSpan? ttl = null)
        {
            _behavior = behavior;

            if (ttl.HasValue)
            {
                AdditionalValues.Add("exp", DateTimeOffset.UtcNow.Add(ttl.Value).ToEpochTime());
            }
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Endpoint = request.RequestUri.AbsoluteUri;

            if (_behavior == Behavior.Unauthorized)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Active)
            {
                var responseObject = new Dictionary<string, object>
                {
                    { "active", true }
                };

                foreach (var item in AdditionalValues)
                {
                    responseObject.Add(item.Key, item.Value);
                }

                var json = SimpleJson.SimpleJson.SerializeObject(responseObject);

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent(json, Encoding.UTF8, "application/json");

                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Inactive)
            {
                var responseObject = new Dictionary<string, object>
                {
                    { "active", false }
                };

                var json = SimpleJson.SimpleJson.SerializeObject(responseObject);

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent(json, Encoding.UTF8, "application/json");

                return Task.FromResult(response);
            }

            throw new NotImplementedException();
        }
    }
}