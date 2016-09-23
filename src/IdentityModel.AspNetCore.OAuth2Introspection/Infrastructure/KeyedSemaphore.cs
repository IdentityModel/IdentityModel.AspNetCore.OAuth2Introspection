using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure
{
    /// <summary>
    /// Provides access to a keyed resource to one thread at a time.
    /// </summary>
    public class KeyedSemaphore
    {
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _keySemaphores = new ConcurrentDictionary<string, SemaphoreSlim>();

        /// <summary>
        /// Attempt to gain access to the resource and wait until this thread is designated the single thread allowed to access it
        /// </summary>
        /// <param name="key">A key representing the resource</param>
        /// <returns>An object which can be used to relinquish control of the keyed resource</returns>
        public async Task<KeyedSemaphoreRelease> WaitForKey(string key)
        {
            SemaphoreSlim keySemaphore = _keySemaphores.GetOrAdd(key, theKey => new SemaphoreSlim(1));
            await keySemaphore.WaitAsync().ConfigureAwait(false);
            return new KeyedSemaphoreRelease(this, key, keySemaphore);
        }

        /// <summary>
        /// Relinquishes control of the resource sepcified by the key
        /// </summary>
        private void Release(string key, SemaphoreSlim keySemaphore)
        {
            keySemaphore.Release();
            _keySemaphores.TryRemove(key, out keySemaphore);
        }

        /// <summary>
        /// Allows a thread to reliquish control of a scoped resource
        /// </summary>
        public class KeyedSemaphoreRelease
        {
            private readonly KeyedSemaphore _keyedSemaphore;
            private readonly string _key;
            private readonly SemaphoreSlim _keySemaphore;

            public KeyedSemaphoreRelease(KeyedSemaphore keyedSemaphore, string key, SemaphoreSlim keySemaphore)
            {
                _keyedSemaphore = keyedSemaphore;
                _key = key;
                _keySemaphore = keySemaphore;
            }

            public void Release()
            {
                _keyedSemaphore.Release(_key, _keySemaphore);
            }
        }
    }
}
