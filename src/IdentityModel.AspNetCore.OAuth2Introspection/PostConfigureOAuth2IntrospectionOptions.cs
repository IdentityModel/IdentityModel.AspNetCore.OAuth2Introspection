// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure;
using IdentityModel.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    internal class PostConfigureOAuth2IntrospectionOptions : IPostConfigureOptions<OAuth2IntrospectionOptions>
    {
        private readonly IDistributedCache _cache;

        public PostConfigureOAuth2IntrospectionOptions(IDistributedCache cache = null)
        {
            _cache = cache;
        }

        public void PostConfigure(string name, OAuth2IntrospectionOptions options)
        {
            options.Validate();

            if (options.EnableCaching && _cache == null)
            {
                throw new ArgumentException("Caching is enabled, but no IDistributedCache is found in the services collection", nameof(_cache));
            }

            options.IntrospectionClient = new AsyncLazy<IntrospectionClient>(() => InitializeIntrospectionClient(options));
            options.LazyIntrospections = new ConcurrentDictionary<string, AsyncLazy<IntrospectionResponse>>();
        }

        private async Task<string> GetIntrospectionEndpointFromDiscoveryDocument(OAuth2IntrospectionOptions Options)
        {
            DiscoveryClient client;

            if (Options.DiscoveryHttpHandler != null)
            {
                client = new DiscoveryClient(Options.Authority, Options.DiscoveryHttpHandler);
            }
            else
            {
                client = new DiscoveryClient(Options.Authority);
            }

            client.Timeout = Options.DiscoveryTimeout;
            client.Policy = Options?.DiscoveryPolicy ?? new DiscoveryPolicy();
            
            var disco = await client.GetAsync().ConfigureAwait(false);
            if (disco.IsError)
            {
                if (disco.ErrorType == ResponseErrorType.Http)
                {
                    throw new InvalidOperationException($"Discovery endpoint {client.Url} is unavailable: {disco.Error}");
                }
                if (disco.ErrorType == ResponseErrorType.PolicyViolation)
                {
                    throw new InvalidOperationException($"Policy error while contacting the discovery endpoint {client.Url}: {disco.Error}");
                }
                if (disco.ErrorType == ResponseErrorType.Exception)
                {
                    throw new InvalidOperationException($"Error parsing discovery document from {client.Url}: {disco.Error}");
                }
            }

            return disco.IntrospectionEndpoint;
        }

        private async Task<IntrospectionClient> InitializeIntrospectionClient(OAuth2IntrospectionOptions Options)
        {
            string endpoint;

            if (Options.IntrospectionEndpoint.IsPresent())
            {
                endpoint = Options.IntrospectionEndpoint;
            }
            else
            {
                endpoint = await GetIntrospectionEndpointFromDiscoveryDocument(Options).ConfigureAwait(false);
                Options.IntrospectionEndpoint = endpoint;
            }

            IntrospectionClient client;
            if (Options.IntrospectionHttpHandler != null)
            {
                client = new IntrospectionClient(
                    endpoint,
                    headerStyle: Options.BasicAuthenticationHeaderStyle,
                    innerHttpMessageHandler: Options.IntrospectionHttpHandler);
            }
            else
            {
                client = new IntrospectionClient(endpoint);
            }

            client.Timeout = Options.DiscoveryTimeout;
            return client;
        }
    }
}