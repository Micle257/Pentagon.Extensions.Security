// -----------------------------------------------------------------------
//  <copyright file="SecureStringExtensions.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security;
    using JetBrains.Annotations;

    /// <summary> Contains extension methods for <see cref="SecureString" />. </summary>
    public static class SecureStringExtensions
    {
        /// <summary> Converts the secure string to normal string using unmanaged convertion. </summary>
        /// <param name="secureString"> The secure string. </param>
        /// <returns> A <see cref="string" />. </returns>
        [Pure]
        public static string ConvertToString([NotNull] this SecureString secureString)
        {
            if (secureString == null)
                throw new ArgumentNullException(nameof(secureString));

            var unmanaged = IntPtr.Zero;

            try
            {
                unmanaged = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(unmanaged);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanaged);
            }
        }
    }
}