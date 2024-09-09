// Copyright (c) Duende Software. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

#pragma warning disable 1591

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    public class ClaimConverter : JsonConverter<Claim>
    {
        public override Claim Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var source = JsonSerializer.Deserialize<ClaimLite>(ref reader, options);
            var target = new Claim(source.Type, source.Value);
            
            return target;
        }

        public override void Write(Utf8JsonWriter writer, Claim value, JsonSerializerOptions options)
        {
            var target = new ClaimLite
            {
                Type = value.Type,
                Value = value.Value
            };

            JsonSerializer.Serialize(writer, target, options);
        }
    }
}