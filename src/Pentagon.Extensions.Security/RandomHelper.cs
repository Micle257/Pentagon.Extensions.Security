// -----------------------------------------------------------------------
//  <copyright file="RandomHelper.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    using System;
    using JetBrains.Annotations;

    /// <summary> Represents a helper for random generation. </summary>
    public class RandomHelper
    {
        /// <summary> Generates a random byte array of certain length. </summary>
        /// <param name="length"> The length. </param>
        /// <returns> A byte array with random data. </returns>
        [Pure]
        [PublicAPI]
        public static byte[] GenerateRandom(int length)
        {
            var buffer = new byte[length];
            var r = new Random();
            r.NextBytes(buffer);
            return buffer;
        }
    }
}