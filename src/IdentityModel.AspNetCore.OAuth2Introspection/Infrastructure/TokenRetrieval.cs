// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.AspNetCore.Http;
using System;
using System.Linq;

namespace IdentityModel.AspNetCore.OAuth2Introspection
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