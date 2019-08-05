// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using FluentAssertions;
using IdentityModel.AspNetCore.OAuth2Introspection;
using IdentityModel.Client;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Tests.Util;
using Xunit;

namespace Tests
{
    public class Introspection
    {
        readonly Action<OAuth2IntrospectionOptions> _options = (o) =>
        {
            o.Authority = "https://authority.com";
            o.DiscoveryPolicy.RequireKeySet = false;

            o.ClientId = "scope";
            o.ClientSecret = "secret";
        };

        [Fact]
        public async Task Unauthorized_Client()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Unauthorized);

            var client = PipelineFactory.CreateClient((o) => _options(o), handler);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task ActiveToken()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            var client = PipelineFactory.CreateClient((o) => _options(o), handler);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task Active_token_with_inline_event_events_should_be_called()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);
            bool? validatedCalled = null;
            bool? failureCalled = null;

            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);

                o.Events.OnTokenValidated = e =>
                {
                    validatedCalled = true;

                    return Task.CompletedTask;
                };

                o.Events.OnAuthenticationFailed = e =>
                {
                    failureCalled = true;

                    return Task.CompletedTask;
                };

            }, handler);

            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");

            result.StatusCode.Should().Be(HttpStatusCode.OK);
            validatedCalled.Should().BeTrue();
            failureCalled.Should().BeNull();
        }

        [Fact]
        public async Task ActiveToken_With_Caching_Ttl_Longer_Than_Duration()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active, TimeSpan.FromHours(1));
            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);

                o.EnableCaching = true;
                o.CacheDuration = TimeSpan.FromMinutes(10);

            }, handler, true);

            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);

            result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task ActiveToken_With_Caching_Ttl_Shorter_Than_Duration()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active, TimeSpan.FromMinutes(5));

            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);

                o.EnableCaching = true;
                o.CacheDuration = TimeSpan.FromMinutes(10);
            }, handler, true);

            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);

            result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task InactiveToken()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Inactive);

            var client = PipelineFactory.CreateClient((o) => _options(o), handler);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task InActive_token_with_inline_event_events_should_be_called()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Inactive);
            bool? validatedCalled = null;
            bool? failureCalled = null;

            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);

                o.Events.OnTokenValidated = e =>
                {
                    validatedCalled = true;

                    return Task.CompletedTask;
                };

                o.Events.OnAuthenticationFailed = e =>
                {
                    failureCalled = true;

                    return Task.CompletedTask;
                };

            }, handler);

            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");

            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            validatedCalled.Should().BeNull();
            failureCalled.Should().BeTrue();
        }

        [Fact]
        public async Task ActiveToken_With_SavedToken()
        {
            var expectedToken = "expected_token";
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);

                o.SaveToken = true;
            }, handler);

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
            var expectedToken = "expected_token";
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active, TimeSpan.FromHours(1));

            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);

                o.SaveToken = true;
                o.EnableCaching = true;
                o.CacheDuration = TimeSpan.FromMinutes(10);
            }, handler, true);

            client.SetBearerToken(expectedToken);

            var firstResponse = await client.GetAsync("http://test");
            firstResponse.StatusCode.Should().Be(HttpStatusCode.OK);

            var secondResponse = await client.GetAsync("http://test");
            secondResponse.StatusCode.Should().Be(HttpStatusCode.OK);

            var responseDataStr = await secondResponse.Content.ReadAsStringAsync();
            var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseDataStr);

            responseData.Should().Contain("token", expectedToken);
        }

        [Fact]
        public async Task Repeated_active_token_with_caching_enabled_should_hit_cache()
        {
            var expectedToken = "expected_token";
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active, TimeSpan.FromHours(1));

            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);
                
                o.SaveToken = true;
                o.EnableCaching = true;
                o.CacheDuration = TimeSpan.FromMinutes(10);
            }, handler, true);

            client.SetBearerToken(expectedToken);

            var firstResponse = await client.GetAsync("http://test");

            firstResponse.StatusCode.Should().Be(HttpStatusCode.OK);
            handler.SentIntrospectionRequest.Should().BeTrue();

            handler.SentIntrospectionRequest = false;
            var secondResponse = await client.GetAsync("http://test");
            handler.SentIntrospectionRequest.Should().BeFalse();
        }

        [Fact]
        public async Task Repeated_inactive_token_with_caching_enabled_should_hit_cache()
        {
            var expectedToken = "expected_token";
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Inactive);

            var client = PipelineFactory.CreateClient((o) =>
            {
                _options(o);

                o.SaveToken = true;
                o.EnableCaching = true;
                o.CacheDuration = TimeSpan.FromMinutes(10);
            }, handler, true);

            client.SetBearerToken(expectedToken);

            var firstResponse = await client.GetAsync("http://test");

            firstResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            handler.SentIntrospectionRequest.Should().BeTrue();

            handler.SentIntrospectionRequest = false;
            var secondResponse = await client.GetAsync("http://test");
            secondResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            handler.SentIntrospectionRequest.Should().BeFalse();
        }

        [Fact]
        public async Task ActiveToken_With_Discovery_Unavailable_On_First_Request()
        {
            var handler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            var client = PipelineFactory.CreateClient((o) => _options(o), handler);
            client.SetBearerToken("sometoken");

            handler.IsDiscoveryFailureTest = true;
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await client.GetAsync("http://test"));

            handler.IsDiscoveryFailureTest = false;
            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}