// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using Microsoft.AspNetCore.Builder;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using Tests.Util;
using Xunit;

namespace Tests
{
    public class Configuration
    {
        [Fact]
        public void Empty_Options()
        {
            Action act = () => PipelineFactory.CreateClient((o) => { })
            .GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldThrow<InvalidOperationException>()
                .WithMessage("You must either set Authority or IntrospectionEndpoint");
        }

        [Fact]
        public void Authority_No_Scope_Details()
        {
            Action act = () => PipelineFactory.CreateClient((o) =>
            {
                o.Authority = "http://foo";
            }).GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldThrow<InvalidOperationException>()
                .WithMessage("You must either set a ClientId or set an introspection HTTP handler");
        }

        [Fact]
        public void No_Token_Retriever()
        {
            Action act = () => PipelineFactory.CreateClient(_options =>
            {
                _options.Authority = "http://foo";
                _options.ClientId = "scope";
                _options.TokenRetriever = null;
            }).GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldThrow<ArgumentException>()
                .Where(e => e.Message.StartsWith("TokenRetriever must be set"));
        }

        [Fact]
        public void Endpoint_But_No_Authority()
        {
            Action act = () => PipelineFactory.CreateClient(_options =>
            {
                _options.IntrospectionEndpoint = "http://endpoint";
                _options.ClientId = "scope";

            }).GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldNotThrow();
        }

        [Fact]
        public void Caching_With_Caching_Service()
        {
            Action act = () => PipelineFactory.CreateClient(_options =>
            {
                _options.IntrospectionEndpoint = "http://endpoint";
                _options.ClientId = "scope";
                _options.EnableCaching = true;

            }, addCaching: true).GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldNotThrow();
        }

        [Fact]
        public void Caching_Without_Caching_Service()
        {
            Action act = () => PipelineFactory.CreateClient(_options =>
            {
                _options.IntrospectionEndpoint = "http://endpoint";
                _options.ClientId = "scope";
                _options.EnableCaching = true;

            }).GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldThrow<ArgumentException>()
                .Where(e => e.Message.StartsWith("Caching is enabled, but no cache is found in the services collection"));
        }

        [Fact]
        public void No_ClientName_But_Introspection_Handler()
        {
            Action act = () => PipelineFactory.CreateClient(_options =>
            {
                _options.IntrospectionEndpoint = "http://endpoint";
                _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            }).GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldNotThrow();
        }

        [Fact]
        public void Authority_No_Network_Delay_Load()
        {
            Action act = () => PipelineFactory.CreateClient(_options =>
            {
                _options.Authority = "http://localhost:6666";
                _options.ClientId = "scope";
            }).GetAsync("http://test").GetAwaiter().GetResult();

            act.ShouldNotThrow();
        }

        [Fact]
        public async Task Authority_Get_Introspection_Endpoint()
        {
            var handler = new DiscoveryEndpointHandler();
            OAuth2IntrospectionOptions ops = null;

            var client = PipelineFactory.CreateClient(_options =>
            {
                _options.Authority = "https://authority.com/";
                _options.ClientId = "scope";

                _options.DiscoveryHttpHandler = handler;
                _options.DiscoveryPolicy.RequireKeySet = false;

                ops = _options;
            });

            client.SetBearerToken("token");
            var response = await client.GetAsync("http://server/api");

            ops.IntrospectionEndpoint.Should().Be("https://authority.com/introspection_endpoint");
        }
    }
}