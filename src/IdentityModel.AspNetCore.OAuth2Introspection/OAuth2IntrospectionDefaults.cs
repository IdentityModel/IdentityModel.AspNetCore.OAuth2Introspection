// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    /// <summary>
    /// Defaults for OAuth 2.0 introspection authentication
    /// </summary>
    public class OAuth2IntrospectionDefaults
    {
        /// <summary>
        /// Gets the default authentication scheme.
        /// </summary>
        /// <value>
        /// The authentication scheme.
        /// </value>
        public static string AuthenticationScheme => "Bearer";
    }
}