// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    internal static class CacheExtensions
    {
        public static async Task<List<Claim>> GetClaimsAsync(this IDistributedCache cache, string token)
        {
            var bytes = await cache.GetAsync(token);

            if (bytes == null)
            {
                return null;
            }

            var json = Encoding.UTF8.GetString(bytes);
            var tuples = JsonConvert.DeserializeObject<IEnumerable<Tuple<string, string>>>(json);
            return tuples.ToClaims();
        }

        public static async Task SetTuplesAsync(this IDistributedCache cache, string token, IEnumerable<Tuple<string, string>> claims, TimeSpan duration, ILogger logger)
        {
            var expClaim = claims.FirstOrDefault(c => c.Item1 == JwtClaimTypes.Expiration);
            if (expClaim == null)
            {
                logger.LogInformation("No exp claim found on introspection response, can't cache.");
                return;
            }

            var expiration = long.Parse(expClaim.Item2).ToDateTimeOffsetFromEpoch();
            var now = DateTimeOffset.UtcNow;

            if (expiration <= now)
            {
                return;
            }

            DateTimeOffset absoluteLifetime;
            if (expiration <= now.Add(duration))
            {
                absoluteLifetime = expiration;
            }
            else
            {
                absoluteLifetime = now.Add(duration);
            }

            var json = JsonConvert.SerializeObject(claims);
            var bytes = Encoding.UTF8.GetBytes(json);

            await cache.SetAsync(token, bytes, new DistributedCacheEntryOptions { AbsoluteExpiration = absoluteLifetime });
        }
    }
}