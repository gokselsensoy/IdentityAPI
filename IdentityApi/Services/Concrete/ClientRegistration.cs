using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityApi.Services.Concrete
{
    public class ClientRegistrationWorker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IConfiguration _configuration;

        public ClientRegistrationWorker(
            IServiceProvider serviceProvider,
            IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _configuration = configuration;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            // === 1. Güvenli (Confidential) İstemci: LogisticsAPI ===
            var confidentialClientId = "logistics_api_service";
            if (await manager.FindByClientIdAsync(confidentialClientId, cancellationToken) is null)
            {
                // Gizli şifreyi appsettings'den oku (3. sorunun cevabı)
                var clientSecret = _configuration["Secrets:ClientSecret"];
                if (string.IsNullOrEmpty(clientSecret))
                {
                    throw new InvalidOperationException("Secrets:ClientSecret is not set in appsettings.json");
                }

                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = confidentialClientId,
                    ClientSecret = clientSecret, // ŞİFRESİ VAR
                    DisplayName = "Logistics API Service",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.ClientCredentials // Sadece S2S izni var
                    }
                }, cancellationToken);
            }

            // === 2. Halka Açık (Public) İstemci: Mobil Uygulama ===
            var mobileClientId = "multillo_mobile";
            if (await manager.FindByClientIdAsync(mobileClientId, cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = mobileClientId,
                    // ClientSecret YOK!
                    DisplayName = "Multillo Mobile App",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Revocation,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken
                       
                    }
                }, cancellationToken);
            }

            var webClientId = "multillo_web";
            if (await manager.FindByClientIdAsync(webClientId, cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = webClientId,
                    DisplayName = "Multillo Web App",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Revocation,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken
                    }
                }, cancellationToken);
            }
        }
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
