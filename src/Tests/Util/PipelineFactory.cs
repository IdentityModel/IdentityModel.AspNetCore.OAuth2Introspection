using IdentityModel.AspNet.OAuth2Introspection;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.TestHost;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http;
using System.Threading.Tasks;

namespace Tests.Util
{
    class PipelineFactory
    {
        public static TestServer CreateServer(OAuth2IntrospectionOptions options)
        {
            return new TestServer(TestServer.CreateBuilder().UseStartup(
                app =>
                {
                    app.UseOAuth2IntrospectionAuthentication(options);

                    app.Use((context, next) =>
                    {
                        var user = context.User;

                        if (user.Identity.IsAuthenticated)
                        {
                            context.Response.StatusCode = 200;
                        }
                        else
                        {
                            context.Response.StatusCode = 401;
                        }

                        return Task.FromResult(0);
                    });
                }, 
                services =>
                {
                    services.AddAuthentication();
                }));
        }

        public static HttpClient CreateClient(OAuth2IntrospectionOptions options)
        {
            return CreateServer(options).CreateClient();
        }

        public static HttpMessageHandler CreateHandler(OAuth2IntrospectionOptions options)
        {
            return CreateServer(options).CreateHandler();
        }
    }
}