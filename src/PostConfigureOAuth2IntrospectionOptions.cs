// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading.Tasks;
using IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure;
using IdentityModel.Client;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    internal class PostConfigureOAuth2IntrospectionOptions : IPostConfigureOptions<OAuth2IntrospectionOptions>
    {
        private readonly IDistributedCache _cache;
        private readonly IHttpClientFactory _httpClientFactory;

        public PostConfigureOAuth2IntrospectionOptions(IHttpClientFactory httpClientFactory, IDistributedCache cache = null)
        {
            _cache = cache;
            _httpClientFactory = httpClientFactory;
        }

        public void PostConfigure(string name, OAuth2IntrospectionOptions options)
        {
            options.Validate();

            if (options.EnableCaching && _cache == null)
            {
                throw new ArgumentException("Caching is enabled, but no IDistributedCache is found in the services collection", nameof(_cache));
            }
            
            options.IntrospectionClient = new AsyncLazy<IntrospectionClient>(() => InitializeIntrospectionClient(options));
        }

        private async Task<IntrospectionClient> InitializeIntrospectionClient(OAuth2IntrospectionOptions options)
        {
            string endpoint;

            if (options.IntrospectionEndpoint.IsPresent())
            {
                endpoint = options.IntrospectionEndpoint;
            }
            else
            {
                endpoint = await GetIntrospectionEndpointFromDiscoveryDocument(options).ConfigureAwait(false);
                options.IntrospectionEndpoint = endpoint;
            }

            HttpMessageInvoker clientFunc() => _httpClientFactory.CreateClient(OAuth2IntrospectionDefaults.BackChannelHttpClientName);

            return new IntrospectionClient(clientFunc, new IntrospectionClientOptions
            {
                Address = endpoint,
                ClientId = options.ClientId,
                ClientSecret = options.ClientSecret,
                ClientAssertion = options.ClientAssertion ?? new ClientAssertion(),
                ClientCredentialStyle = options.ClientCredentialStyle,
                AuthorizationHeaderStyle = options.AuthorizationHeaderStyle
            });
        }

        private async Task<string> GetIntrospectionEndpointFromDiscoveryDocument(OAuth2IntrospectionOptions options)
        {
            var client = _httpClientFactory.CreateClient(OAuth2IntrospectionDefaults.BackChannelHttpClientName);

            var disco = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = options.Authority,
                Policy = options?.DiscoveryPolicy ?? new DiscoveryPolicy()
            }).ConfigureAwait(false);
            
            if (disco.IsError)
            {
                if (disco.ErrorType == ResponseErrorType.Http)
                {
                    throw new InvalidOperationException($"Discovery endpoint {options.Authority} is unavailable: {disco.Error}");
                }
                if (disco.ErrorType == ResponseErrorType.PolicyViolation)
                {
                    throw new InvalidOperationException($"Policy error while contacting the discovery endpoint {options.Authority}: {disco.Error}");
                }
                if (disco.ErrorType == ResponseErrorType.Exception)
                {
                    throw new InvalidOperationException($"Error parsing discovery document from {options.Authority}: {disco.Error}");
                }
            }

            return disco.IntrospectionEndpoint;
        }
    }
}