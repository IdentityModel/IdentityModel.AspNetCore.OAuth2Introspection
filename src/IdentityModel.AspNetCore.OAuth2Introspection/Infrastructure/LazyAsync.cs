// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure
{
    public class LazyAsync<T>
    {
        private readonly Func<Task<T>> _valueFactory;
        private T _value;
        private readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1);

        public LazyAsync(Func<Task<T>> valueFactory)
        {
            _valueFactory = valueFactory;
        }

        public async Task<T> GetValue()
        {
            if (_value != null)
            {
                return _value;
            }

            // Only one thread will be allowed through here at a time
            await _semaphoreSlim.WaitAsync().ConfigureAwait(false);

            try
            {
                if (_value != null)
                {
                    return _value;
                }

                _value = await _valueFactory().ConfigureAwait(false);
                return _value;
            }
            finally
            {
                // Let the next thread through
                _semaphoreSlim.Release();
            }
        }
    }
}
