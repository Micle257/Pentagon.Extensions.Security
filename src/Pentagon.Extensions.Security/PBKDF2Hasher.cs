// -----------------------------------------------------------------------
//  <copyright file="Hasher.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    using System;

    public class PBKDF2Hasher : IHasher
    {
        /// <inheritdoc />
        public string HashPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password is empty or null.");

            return PBKDF2.HashPassword(password);
        }
        
        /// <inheritdoc />
        public bool VerifyHashedPassword(string hashedPassword, string providedPassword)
        {
            if (PBKDF2.VerifyHashedPassword(hashedPassword, providedPassword))
                return true;

            return false;
        }
    }
}