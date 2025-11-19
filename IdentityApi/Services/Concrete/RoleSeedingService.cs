using IdentityApi.Domain;
using Microsoft.AspNetCore.Identity;

namespace IdentityApi.Services.Concrete
{
    public class RoleSeedingService : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<RoleSeedingService> _logger;

        public RoleSeedingService(
            IServiceProvider serviceProvider,
            ILogger<RoleSeedingService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();

            // Projende kullanacağın tüm rolleri buraya listele
            var roles = new[] { "Multillo.Admin", "Multillo.Customer", "Multillo.Supplier", "Multillo.Transporter", "Multillo.Worker", "Multillo.Freelancer" };

            foreach (var roleName in roles)
            {
                // Rol var mı diye kontrol et
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    _logger.LogInformation("Rol oluşturuluyor: {RoleName}", roleName);

                    // Yoksa oluştur
                    var result = await roleManager.CreateAsync(new ApplicationRole
                    {
                        Name = roleName,
                        NormalizedName = roleName.ToUpperInvariant()
                        // Id Guid olduğu için otomatik oluşur
                    });

                    if (!result.Succeeded)
                    {
                        var error = string.Join(", ", result.Errors.Select(e => e.Description));
                        _logger.LogError("Rol oluşturulamadı ({RoleName}): {Error}", roleName, error);
                    }
                }
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
