using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Tests.Util
{
    class IntrospectionEndpointHandler : HttpMessageHandler
    {
        private readonly Behavior _behavior;

        public enum Behavior
        {
            Active,
            Inactive,
            Unauthorized
        }

        public string Endpoint { get; set; }

        public IntrospectionEndpointHandler(Behavior behavior)
        {
            _behavior = behavior;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Endpoint = request.RequestUri.AbsoluteUri;

            if (_behavior == Behavior.Unauthorized)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Active)
            {
                var responseObject = new Dictionary<string, object>
                {
                    { "active", true }
                };

                var json = SimpleJson.SimpleJson.SerializeObject(responseObject);

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent(json, Encoding.UTF8, "application/json");

                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Inactive)
            {
                var responseObject = new Dictionary<string, object>
                {
                    { "active", false }
                };

                var json = SimpleJson.SimpleJson.SerializeObject(responseObject);

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new StringContent(json, Encoding.UTF8, "application/json");

                return Task.FromResult(response);
            }

            throw new NotImplementedException();
        }
    }
}