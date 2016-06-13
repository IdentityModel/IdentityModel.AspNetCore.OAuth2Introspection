// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    internal static class TupleExtensions
    {
        public static List<Claim> ToClaims(this IEnumerable<Tuple<string, string>> claims)
        {
            return new List<Claim>(claims
                   .Where(c => c.Item1 != "active")
                   .Select(c => new Claim(c.Item1, c.Item2)));
        }

        public static IEnumerable<Tuple<string, string>> ToTuples(this List<Claim> claims)
        {
            return new List<Tuple<string, string>>(claims.Select(c => Tuple.Create(c.Type, c.Value)));
        }
    }
}