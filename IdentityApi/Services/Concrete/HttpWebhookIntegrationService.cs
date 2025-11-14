using IdentityApi.Services.Abstracts;
using System.Text;
using System.Text.Json;

namespace IdentityApi.Services.Concrete
{
    public class HttpWebhookIntegrationService : IIntegrationService
    {
        private readonly HttpClient _httpClient;
        public HttpWebhookIntegrationService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task NotifyUserUpdatedAsync(Guid identityId, string email)
        {
            // LogisticsAPI'deki internal endpoint'i çağıracağız
            var payload = new { identityId, email };
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            try
            {
                // Bu endpoint'i Bölüm 3'te LogisticsAPI'de oluşturacağız
                await _httpClient.PostAsync("/api/integration/user-sync", content);
            }
            catch (Exception ex)
            {
                // API erişilemezse logla, ama ana işlemi (register) durdurma
                // TODO: Burası için bir retry mekanizması (Polly) veya Outbox Pattern düşünülebilir
            }
        }
    }
}
