// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Encodings.Web;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    public class OAuth2IntrospectionMiddleware : AuthenticationMiddleware<OAuth2IntrospectionOptions>
    {
        Lazy<IntrospectionClient> _client;

        public OAuth2IntrospectionMiddleware(RequestDelegate next, IOptions<OAuth2IntrospectionOptions> options, UrlEncoder urlEncoder, ILoggerFactory loggerFactory)
            : base(next, options, loggerFactory, urlEncoder)
        {
            if (Options.Authority.IsMissing() && Options.IntrospectionEndpoint.IsMissing())
            {
                throw new InvalidOperationException("You must either set Authority or IntrospectionEndpoint");
            }

            if (Options.ScopeName.IsMissing() && Options.IntrospectionHttpHandler == null)
            {
                throw new InvalidOperationException("You must either set a ScopeName or set an introspection HTTP handler");
            }

            if (Options.TokenRetriever == null)
            {
                throw new ArgumentException("TokenRetriever must be set", nameof(Options.TokenRetriever));
            }

            _client = new Lazy<IntrospectionClient>(InitializeIntrospectionClient);
            if (Options.DelayLoadDiscoveryDocument == false)
            {
                var temp = _client.Value;
            }
        }

        private IntrospectionClient InitializeIntrospectionClient()
        {
            string endpoint;

            if (Options.IntrospectionEndpoint.IsPresent())
            {
                endpoint = Options.IntrospectionEndpoint;
            }
            else
            {
                endpoint = GetIntrospectionEndpointFromDiscoveryDocument();
                Options.IntrospectionEndpoint = endpoint;
            }

            IntrospectionClient client;
            if (Options.IntrospectionHttpHandler != null)
            {
                client = new IntrospectionClient(
                    endpoint,
                    innerHttpMessageHandler: Options.IntrospectionHttpHandler);
            }
            else
            {
                client = new IntrospectionClient(endpoint);
            }

            client.Timeout = Options.DiscoveryTimeout;
            return client;
        }

        private string GetIntrospectionEndpointFromDiscoveryDocument()
        {
            HttpClient client;

            if (Options.DiscoveryHttpHandler != null)
            {
                client = new HttpClient(Options.DiscoveryHttpHandler);
            }
            else
            {
                client = new HttpClient();
            }

            client.Timeout = Options.DiscoveryTimeout;

            var discoEndpoint = Options.Authority.EnsureTrailingSlash() + ".well-known/openid-configuration";
            var response = AsyncHelper.RunSync<string>(() => client.GetStringAsync(discoEndpoint));

            var json = (IDictionary<string, object>)SimpleJson.SimpleJson.DeserializeObject(response);
            return (string)json["introspection_endpoint"];
        }

        protected override AuthenticationHandler<OAuth2IntrospectionOptions> CreateHandler()
        {
            return new OAuth2IntrospectionHandler(_client.Value);
        }
    }
}