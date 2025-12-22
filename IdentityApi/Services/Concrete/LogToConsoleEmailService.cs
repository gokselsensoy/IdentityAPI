using IdentityApi.Services.Abstracts;

namespace IdentityApi.Services.Concrete
{
    public class LogToConsoleEmailService : IEmailService
    {
        private readonly ILogger<LogToConsoleEmailService> _logger;
        public LogToConsoleEmailService(ILogger<LogToConsoleEmailService> logger)
        {
            _logger = logger;
        }

        public Task SendEmailAsync(string toEmail, string subject, string body)
        {
            _logger.LogWarning($"=== EMAIL GÖNDERİLİYOR (TEST) ===");
            _logger.LogInformation($"To: {toEmail}");
            _logger.LogInformation($"Subject: {subject}");
            _logger.LogInformation($"Body: {body}");
            _logger.LogWarning($"==================================");
            return Task.CompletedTask;
        }
    }
}
