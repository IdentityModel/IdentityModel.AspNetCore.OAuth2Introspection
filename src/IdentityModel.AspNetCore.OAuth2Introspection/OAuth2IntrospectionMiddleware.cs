// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    public class OAuth2IntrospectionMiddleware : AuthenticationMiddleware<OAuth2IntrospectionOptions>
    {
        AsyncLazy<IntrospectionClient> _client;
        private readonly IDistributedCache _cache;
        private readonly ILoggerFactory _loggerFactory;
        private readonly ConcurrentDictionary<string, AsyncLazy<IntrospectionResponse>> _lazyTokenIntrospections;

        public OAuth2IntrospectionMiddleware(
            RequestDelegate next,
            IOptions<OAuth2IntrospectionOptions> options,
            UrlEncoder urlEncoder,
            ILoggerFactory loggerFactory,
            IDistributedCache cache = null)
            : base(next, options, loggerFactory, urlEncoder)
        {
            _loggerFactory = loggerFactory;

            if (options.Value.Authority.IsMissing() && options.Value.IntrospectionEndpoint.IsMissing())
            {
                throw new InvalidOperationException("You must either set Authority or IntrospectionEndpoint");
            }

            if (options.Value.ClientId.IsMissing() && options.Value.IntrospectionHttpHandler == null)
            {
                throw new InvalidOperationException("You must either set a ClientId or set an introspection HTTP handler");
            }

            if (options.Value.TokenRetriever == null)
            {
                throw new ArgumentException("TokenRetriever must be set", nameof(options.Value.TokenRetriever));
            }

            if (options.Value.EnableCaching == true && cache == null)
            {
                throw new ArgumentException("Caching is enabled, but no cache is found in the services collection", nameof(cache));
            }

            _cache = cache;
            _client = new AsyncLazy<IntrospectionClient>(InitializeIntrospectionClient);
            _lazyTokenIntrospections = new ConcurrentDictionary<string, AsyncLazy<IntrospectionResponse>>();
        }

        private async Task<IntrospectionClient> InitializeIntrospectionClient()
        {
            string endpoint;

            if (Options.IntrospectionEndpoint.IsPresent())
            {
                endpoint = Options.IntrospectionEndpoint;
            }
            else
            {
                endpoint = await GetIntrospectionEndpointFromDiscoveryDocument().ConfigureAwait(false);
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

        private async Task<string> GetIntrospectionEndpointFromDiscoveryDocument()
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

            string response;
            try
            {
                response = await client.GetStringAsync(discoEndpoint).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Discovery endpoint {discoEndpoint} is unavailable: {ex.ToString()}");
            }

            try
            {
                var json = JObject.Parse(response);
                return json["introspection_endpoint"].ToString();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error parsing discovery document from {discoEndpoint}: {ex.ToString()}");
            }
        }

        protected override AuthenticationHandler<OAuth2IntrospectionOptions> CreateHandler()
        {
            return new OAuth2IntrospectionHandler(_client, _loggerFactory, _cache, _lazyTokenIntrospections);
        }
    }
}