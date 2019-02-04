// -----------------------------------------------------------------------
//  <copyright file="HasherType.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    public enum HasherType
    {
        Unspecified = 0,
        Default = PBKDF2,
        PBKDF2 = 1,
        SHA512 = 2
    }
}