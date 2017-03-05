// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using FluentAssertions;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
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

            Authority = "http://authority.com",
            DiscoveryHttpHandler = new DiscoveryEndpointHandler(),

            ClientId = "scope",
            ClientSecret = "secret"
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
        public async Task ActiveToken_With_Caching_Ttl_Longer_Than_Duration()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active, TimeSpan.FromHours(1));
            _options.EnableCaching = true;
            _options.CacheDuration = TimeSpan.FromMinutes(10);

            var client = PipelineFactory.CreateClient(_options, addCaching: true);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);

            result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task ActiveToken_With_Caching_Ttl_Shorter_Than_Duration()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active, TimeSpan.FromMinutes(5));
            _options.EnableCaching = true;
            _options.CacheDuration = TimeSpan.FromMinutes(10);

            var client = PipelineFactory.CreateClient(_options, addCaching: true);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);

            result = await client.GetAsync("http://test");
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

        [Fact]
        public async Task ActiveToken_With_SavedToken()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);
            _options.SaveToken = true;

            var expectedToken = "expected_token";

            var client = PipelineFactory.CreateClient(_options);
            client.SetBearerToken(expectedToken);

            var response = await client.GetAsync("http://test");
            response.StatusCode.Should().Be(HttpStatusCode.OK);

            var responseDataStr = await response.Content.ReadAsStringAsync();
            var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseDataStr);

            responseData.Should().Contain("token", expectedToken);
        }

        [Fact]
        public async Task ActiveToken_With_SavedToken_And_Caching()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active, TimeSpan.FromHours(1));
            _options.SaveToken = true;
            _options.EnableCaching = true;
            _options.CacheDuration = TimeSpan.FromMinutes(10);

            var expectedToken = "expected_token";

            var client = PipelineFactory.CreateClient(_options, true);
            client.SetBearerToken(expectedToken);

            var firstResponse = await client.GetAsync("http://test");
            firstResponse.StatusCode.Should().Be(HttpStatusCode.OK);

            var secondResponse = await client.GetAsync("http://test");
            secondResponse.StatusCode.Should().Be(HttpStatusCode.OK);

            var responseDataStr = await secondResponse.Content.ReadAsStringAsync();
            var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseDataStr);

            responseData.Should().Contain("token", expectedToken);
        }
    }
}