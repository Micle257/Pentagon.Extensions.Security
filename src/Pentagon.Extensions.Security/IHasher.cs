// -----------------------------------------------------------------------
//  <copyright file="IHasher.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    using JetBrains.Annotations;

    /// <summary> Provides a hasher algorithm. </summary>
    public interface IHasher
    {
        /// <summary> Computes hash string from a password. </summary>
        /// <param name="password"> The password. </param>
        /// <returns> A <see cref="string" /> containing the hash. </returns>
        [NotNull]
        string HashPassword([NotNull] string password);
        
        /// <summary> Verifies if the hash string of a provided password matches the hashed password. </summary>
        /// <param name="hashedPassword"> The hashed password. </param>
        /// <param name="providedPassword"> The provided password. </param>
        /// <returns> <c> true </c> if the hashes are equal; otherwise, <c> false </c>. </returns>
        bool VerifyHashedPassword([NotNull] string hashedPassword, [NotNull] string providedPassword);
    }
}