namespace Pentagon.Extensions.Security {
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Exceptions;
    using JetBrains.Annotations;

    /// <summary> An <see cref="IHasher" /> implementation with SHA512 hashing algorithm. </summary>
    public sealed class Sha512Hasher : IHasher
    {
        readonly int? _saltSizeBytes;

        [NotNull]
        readonly Encoding _textEncoding;

        /// <summary>
        /// Initializes a new instance of the <see cref="Sha512Hasher" /> class.
        /// </summary>
        /// <param name="saltSizeBytes">The salt size in bytes. If <c>null</c> then salting will be disabled.</param>
        /// <param name="textEncoding">The text encoding.</param>
        public Sha512Hasher(int? saltSizeBytes = 16, Encoding textEncoding=null)
        {
            _saltSizeBytes = saltSizeBytes;
            _textEncoding = textEncoding ?? Encoding.UTF8;
        }

        /// <inheritdoc />
        /// <exception cref="StringArgumentException"> When <paramref name="password" /> is null or empty. </exception>
        public string HashPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password is empty or null.");

            if (_saltSizeBytes.HasValue)
            {
                var salt = RandomHelper.GenerateRandom(_saltSizeBytes.Value);

                var hashBytes = GenerateSaltedHash(password, salt);
                return Convert.ToBase64String(hashBytes);
            }
            else
            {
                var hashBytes = GenerateSaltlessHash(password);
                return Convert.ToBase64String(hashBytes);
            }
        }
        
        /// <inheritdoc />
        /// <exception cref="StringArgumentException"> When <paramref name="hashedPassword" /> or <paramref name="providedPassword" /> are null or empty. </exception>
        public bool VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            if (string.IsNullOrWhiteSpace(hashedPassword))
                throw new ArgumentException("Hashed password is empty or null.");
            
            if (string.IsNullOrWhiteSpace(providedPassword))
                throw new ArgumentException("Provided password is empty or null.");

            var hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            byte[] providedPasswordHashBuffer;

            if (_saltSizeBytes.HasValue)
            {
                var salt = hashedPasswordBytes.Take(_saltSizeBytes.Value).ToArray();

                providedPasswordHashBuffer = GenerateSaltedHash(providedPassword, salt);
            }
            else
            {
                providedPasswordHashBuffer = GenerateSaltlessHash(providedPassword);
            }

            var providedPasswordHash = Convert.ToBase64String(providedPasswordHashBuffer);

            return string.CompareOrdinal(hashedPassword, providedPasswordHash) == 0;
        }

        /// <summary> Generates the hash with give password and salt. </summary>
        /// <param name="password"> The password. </param>
        /// <param name="salt"> The salt. </param>
        /// <returns>The hash buffer.</returns>
        byte[] GenerateSaltedHash(string password, byte[] salt)
        {
            var text = _textEncoding.GetBytes(password);

            var managed = SHA512.Create();

            var textWithSalt = salt.Concat(text).ToArray();

            var hash = managed.ComputeHash(textWithSalt);

            return salt.Concat(hash).ToArray();
        }

        /// <summary> Generates the hash with give password. </summary>
        /// <param name="password">The password.</param>
        /// <returns>The hash buffer.</returns>
        byte[] GenerateSaltlessHash(string password)
        {
            var text = _textEncoding.GetBytes(password);

            var managed = SHA512.Create();

            var hash = managed.ComputeHash(text);

            return hash;
        }
    }
}