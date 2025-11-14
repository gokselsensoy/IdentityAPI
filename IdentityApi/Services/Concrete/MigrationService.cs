using IdentityApi.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace IdentityApi.Services.Concrete
{
    public class MigrationService : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<MigrationService> _logger;

        public MigrationService(
            IServiceProvider serviceProvider,
            ILogger<MigrationService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Veritabanı migration kontrolü başlıyor...");

            using var scope = _serviceProvider.CreateScope();

            try
            {
                var dbContext = scope.ServiceProvider
                                     .GetRequiredService<IdentityDbContext>();

                // Bekleyen migration'ları uygula
                await dbContext.Database.MigrateAsync(cancellationToken);

                _logger.LogInformation("Veritabanı başarıyla güncellendi.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Veritabanı migration sırasında bir hata oluştu.");
                // Hata olursa uygulamayı durdurabilir veya loglayıp devam edebilirsiniz.
                // Şimdilik loglayıp durduruyoruz.
                throw;
            }
        }

        // Bu servisin durdurulduğunda yapması gereken bir şey yok.
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
