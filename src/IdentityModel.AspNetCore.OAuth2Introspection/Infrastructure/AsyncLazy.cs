// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure
{
    internal sealed class AsyncLazy<T>
    {
        private Lazy<Task<T>> _lazyFactory;
        private readonly Func<Task<T>> _taskFactory;

        public AsyncLazy(Func<Task<T>> taskFactory)
        {
            _taskFactory = taskFactory;
            _lazyFactory = InitLazy(_taskFactory);
        }
 
        public Task<T> GetAsync()
        {
            lock (_taskFactory)
            {
                if (_lazyFactory.IsValueCreated && _lazyFactory.Value.IsFaulted)
                {
                    _lazyFactory = InitLazy(_taskFactory);
                }

                return _lazyFactory.Value;
            }
        }

        private static Lazy<Task<T>> InitLazy(Func<Task<T>> taskFactory)
        {
            return new Lazy<Task<T>>(() => Task.Factory.StartNew(taskFactory).Unwrap(), LazyThreadSafetyMode.ExecutionAndPublication);
        }
    }
}