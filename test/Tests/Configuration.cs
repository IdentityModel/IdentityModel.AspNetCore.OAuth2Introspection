// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using Tests.Util;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class Configuration
    {
        OAuth2IntrospectionOptions _options = new OAuth2IntrospectionOptions();

        [Fact]
        public void Empty_Options()
        {
            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldThrow<InvalidOperationException>()
                .WithMessage("You must either set Authority or IntrospectionEndpoint");
        }

        [Fact]
        public void Authority_No_Scope_Details()
        {
            _options.Authority = "http://foo";

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldThrow<InvalidOperationException>()
                .WithMessage("You must either set a ClientId or set an introspection HTTP handler");
        }

        [Fact]
        public void No_Token_Retriever()
        {
            _options.Authority = "http://foo";
            _options.ClientId = "scope";
            _options.TokenRetriever = null;

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldThrow<ArgumentException>()
                .Where(e => e.Message.StartsWith("TokenRetriever must be set"));
        }

        [Fact]
        public void Endpoint_But_No_Authority()
        {
            _options.IntrospectionEndpoint = "http://endpoint";
            _options.ClientId = "scope";

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
        }

        [Fact]
        public void Caching_With_Caching_Service()
        {
            _options.IntrospectionEndpoint = "http://endpoint";
            _options.ClientId = "scope";
            _options.EnableCaching = true;

            Action act = () => PipelineFactory.CreateClient(_options, addCaching: true);

            act.ShouldNotThrow();
        }

        [Fact]
        public void Caching_Without_Caching_Service()
        {
            _options.IntrospectionEndpoint = "http://endpoint";
            _options.ClientId = "scope";
            _options.EnableCaching = true;

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldThrow<ArgumentException>()
                .Where(e => e.Message.StartsWith("Caching is enabled, but no cache is found in the services collection"));
        }

        [Fact]
        public void No_ClientName_But_Introspection_Handler()
        {
            _options.IntrospectionEndpoint = "http://endpoint";
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
        }

        [Fact]
        public void Authority_No_Network_Delay_Load()
        {
            _options.Authority = "http://localhost:6666";
            _options.ClientId = "scope";

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
        }

        [Fact]
        public async Task Authority_No_Trailing_Slash()
        {
            _options.Authority = "http://authority.com";
            _options.ClientId = "scope";

            var handler = new DiscoveryEndpointHandler();
            _options.DiscoveryHttpHandler = handler;

            var client = PipelineFactory.CreateClient(_options);
            client.SetBearerToken("token");
            var response = await client.GetAsync("http://server/api");

            handler.Endpoint.Should().Be("http://authority.com/.well-known/openid-configuration");
        }

        [Fact]
        public async Task Authority_Trailing_Slash()
        {
            _options.Authority = "http://authority.com/";
            _options.ClientId = "scope";

            var handler = new DiscoveryEndpointHandler();
            _options.DiscoveryHttpHandler = handler;

            var client  = PipelineFactory.CreateClient(_options);
            client.SetBearerToken("token");
            var response = await client.GetAsync("http://server/api");

            handler.Endpoint.Should().Be("http://authority.com/.well-known/openid-configuration");
        }

        [Fact]
        public async Task Authority_Get_Introspection_Endpoint()
        {
            _options.Authority = "http://authority.com/";
            _options.ClientId = "scope";

            var handler = new DiscoveryEndpointHandler();
            _options.DiscoveryHttpHandler = handler;

            var client = PipelineFactory.CreateClient(_options);
            client.SetBearerToken("token");
            var response = await client.GetAsync("http://server/api");

            _options.IntrospectionEndpoint.Should().Be("http://introspection_endpoint");
        }
    }
}