using Microsoft.AspNet.Http;
using System;
using System.Linq;

namespace IdentityModel.AspNet.OAuth2Introspection
{
    public static class TokenRetrieval
    {
        public static Func<HttpRequest, string> FromAuthorizationHeader(string scheme = "Bearer")
        {
            return (request) =>
            {
                string authorization = request.Headers["Authorization"];

                if (string.IsNullOrEmpty(authorization))
                {
                    return null;
                }

                if (authorization.StartsWith(scheme + " ", StringComparison.OrdinalIgnoreCase))
                {
                    return authorization.Substring(scheme.Length + 1).Trim();
                }

                return null;
            };
        }

        public static Func<HttpRequest, string> FromQueryString(string name = "access_token")
        {
            return (request) =>
            {
                return request.Query[name].FirstOrDefault();
            };
        }
    }
}