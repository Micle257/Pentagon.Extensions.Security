// -----------------------------------------------------------------------
//  <copyright file="ServiceCollectionExtensions.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    using System;
    using Microsoft.Extensions.DependencyInjection;

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddHasher(this IServiceCollection services, HasherType type = HasherType.Default, bool useSalt = true)
        {
            switch (type)
            {
                case HasherType.SHA512:
                    services.AddTransient<IHasher>(c => new Sha512Hasher(useSalt ? 16 : (int?) null));
                    break;
                    
                case HasherType.Unspecified:
                case HasherType.PBKDF2:
                    services.AddTransient<IHasher, PBKDF2Hasher>();
                    break;
            }
            
            return services;
        }
    }
}