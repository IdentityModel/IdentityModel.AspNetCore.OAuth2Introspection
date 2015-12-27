using FluentAssertions;
using IdentityModel.AspNet.OAuth2Introspection;
using System;
using System.Net.Http;
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
                .WithMessage("You must either set a ScopeName or set an introspection HTTP handler");
        }

        [Fact]
        public void No_Token_Retriever()
        {
            _options.Authority = "http://foo";
            _options.ScopeName = "scope";
            _options.TokenRetriever = null;

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldThrow<ArgumentException>()
                .Where(e => e.Message.StartsWith("TokenRetriever must be set"));
        }

        [Fact]
        public void Endpoint_But_No_Authority()
        {
            _options.IntrospectionEndpoint = "http://endpoint";
            _options.ScopeName = "scope";

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
        }

        [Fact]
        public void No_ScopeName_But_Introspection_Handler()
        {
            _options.IntrospectionEndpoint = "http://endpoint";
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
        }

        [Fact]
        public void Authority_No_Network()
        {
            _options.Authority = "http://localhost:6666";
            _options.ScopeName = "scope";

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldThrow<HttpRequestException>();
        }

        [Fact]
        public void Authority_No_Network_Delay_Load()
        {
            _options.Authority = "http://localhost:6666";
            _options.ScopeName = "scope";
            _options.DelayLoadDiscoveryDocument = true;

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
        }

        [Fact]
        public void Authority_No_Trailing_Slash()
        {
            _options.Authority = "http://authority.com";
            _options.ScopeName = "scope";

            var handler = new DiscoveryEndpointHandler();
            _options.DiscoveryHttpHandler = handler;

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
            handler.Endpoint.Should().Be("http://authority.com/.well-known/openid-configuration");
        }

        [Fact]
        public void Authority_Trailing_Slash()
        {
            _options.Authority = "http://authority.com/";
            _options.ScopeName = "scope";

            var handler = new DiscoveryEndpointHandler();
            _options.DiscoveryHttpHandler = handler;

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
            handler.Endpoint.Should().Be("http://authority.com/.well-known/openid-configuration");
        }

        [Fact]
        public void Authority_Get_Introspection_Endpoint()
        {
            _options.Authority = "http://authority.com/";
            _options.ScopeName = "scope";

            var handler = new DiscoveryEndpointHandler();
            _options.DiscoveryHttpHandler = handler;

            Action act = () => PipelineFactory.CreateClient(_options);

            act.ShouldNotThrow();
            _options.IntrospectionEndpoint.Should().Be("http://introspection_endpoint");
        }
    }
}