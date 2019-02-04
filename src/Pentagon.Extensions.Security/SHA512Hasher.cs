namespace Pentagon.Extensions.Security {
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Exceptions;

    /// <summary> An <see cref="IHasher" /> implementation with SHA512 hashing algorithm. </summary>
    public sealed class SHA512Hasher : IHasher
    {
        public const int SaltSize = 128 / 8;

        /// <inheritdoc />
        /// <exception cref="StringArgumentException"> When <paramref name="password" /> is null or empty. </exception>
        public string HashPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password is empty or null.");

            var salt = RandomHelper.GenerateRandom(SaltSize);
            
            var hashBytes = GenerateSaltedHash(password, salt);
            return Convert.ToBase64String(hashBytes);
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

            var salt = hashedPasswordBytes.Take(SaltSize).ToArray();

            var providedPasswordHashBuffer = GenerateSaltedHash(providedPassword, salt);

            var providedPasswordHash = Convert.ToBase64String(providedPasswordHashBuffer);

            return string.CompareOrdinal(hashedPassword, providedPasswordHash) == 0;
        }

        /// <summary> Generates the hash with give password and salt. </summary>
        /// <param name="password"> The password. </param>
        /// <param name="salt"> The salt. </param>
        /// <returns> </returns>
        byte[] GenerateSaltedHash(string password, byte[] salt)
        {
            var text = Encoding.UTF8.GetBytes(password);

            var managed = SHA512.Create();

            var textWithSalt = salt.Concat(text).ToArray();

            var hash = managed.ComputeHash(textWithSalt);

            return salt.Concat(hash).ToArray();
        }
    }
}