// -----------------------------------------------------------------------
//  <copyright file="ServiceCollectionExtensions.cs">
//   Copyright (c) Michal Pokorný. All Rights Reserved.
//  </copyright>
// -----------------------------------------------------------------------

namespace Pentagon.Extensions.Security
{
    using Microsoft.Extensions.DependencyInjection;

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddDefaultSecurityServices(this IServiceCollection services)
        {
            services.AddTransient<IHasher, Hasher>();

            return services;
        }
    }
}