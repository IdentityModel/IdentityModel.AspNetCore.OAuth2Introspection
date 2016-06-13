// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Tests.Util;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class Introspection
    {
        OAuth2IntrospectionOptions _options = new OAuth2IntrospectionOptions
        {
            AutomaticAuthenticate = true,

            Authority = "http://server",
            DiscoveryHttpHandler = new DiscoveryEndpointHandler(),

            ScopeName = "scope",
            ScopeSecret = "secret"
        };

        [Fact]
        public async Task Unauthorized_Client()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Unauthorized);

            var client = PipelineFactory.CreateClient(_options);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task ActiveToken()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            var client = PipelineFactory.CreateClient(_options);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task InactiveToken()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Inactive);

            var client = PipelineFactory.CreateClient(_options);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
    }
}