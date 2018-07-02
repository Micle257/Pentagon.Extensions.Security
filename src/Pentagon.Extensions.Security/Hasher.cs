// -----------------------------------------------------------------------
//  <copyright file="Hasher.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Exceptions;

    /// <summary> An <see cref="IHasher" /> implementation with SHA512 hashing algorithm. </summary>
    public sealed class Hasher : IHasher
    {
        /// <summary> The salt. </summary>
        const string Salt = "QcCWi5geGEm2MrqWi17FxqiOIHddbVeZDtErHem5L7Y=";

        /// <inheritdoc />
        /// <exception cref="StringArgumentException"> When <paramref name="password" /> is null or empty. </exception>
        public string HashPassword(string password)
        {
            Require.StringNotNullNorEmpty(() => password);
            var hashBytes = GenerateSaltedHash(password, Convert.FromBase64String(Salt));
            return Convert.ToBase64String(hashBytes);
        }

        /// <inheritdoc />
        /// <exception cref="StringArgumentException"> When <paramref name="password" /> or <paramref name="salt" /> is null or empty. </exception>
        public string HashPassword(string password, string salt)
        {
            Require.StringNotNullNorEmpty(() => password);
            Require.StringNotNullNorEmpty(() => salt);

            Require.Condition(() => salt.Length > 0, message: "The salt length must be grater than zero");

            var saltBytes = Convert.FromBase64String(salt);
            var hashBytes = GenerateSaltedHash(password, saltBytes);
            return Convert.ToBase64String(hashBytes);
        }

        /// <inheritdoc />
        /// <exception cref="StringArgumentException"> When <paramref name="hashedPassword" /> or <paramref name="providedPassword" /> are null or empty. </exception>
        public bool VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            Require.StringNotNullNorEmpty(() => hashedPassword);
            Require.StringNotNullNorEmpty(() => providedPassword);

            var providedPasswordHash = HashPassword(providedPassword, Salt);
            return string.CompareOrdinal(hashedPassword, providedPasswordHash) == 0;
        }

        /// <summary> Generates the hash with give password and salt. </summary>
        /// <param name="password"> The password. </param>
        /// <param name="salt"> The salt. </param>
        /// <returns> </returns>
        byte[] GenerateSaltedHash(string password, byte[] salt)
        {
            var text = Encoding.UTF8?.GetBytes(password);
            var managed = SHA512.Create();
            var textWithSalt = text.Concat(salt).ToArray();
            return managed.ComputeHash(textWithSalt);
        }
    }
}