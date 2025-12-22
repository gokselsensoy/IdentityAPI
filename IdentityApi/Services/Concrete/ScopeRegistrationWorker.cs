using OpenIddict.Abstractions;

namespace IdentityApi.Services.Concrete
{
    public class ScopeRegistrationWorker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public ScopeRegistrationWorker(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            // 1. logistics_api Scope'u
            if (await manager.FindByNameAsync("logistics_api") is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "logistics_api",
                    DisplayName = "Logistics API Access",
                    Resources =
                {
                    "logistics_resource_server" // Audience (Hangi API için geçerli?)
                }
                });
            }

            // 2. offline_access Scope'u (Standarttır ama eklemekte fayda var)
            if (await manager.FindByNameAsync("offline_access") is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "offline_access",
                    DisplayName = "Offline Access (Refresh Token)",
                    Description = "Kullanıcı çevrimdışıyken işlem yapabilme yetkisi."
                });
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
