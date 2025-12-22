namespace IdentityApi.Services.Abstracts
{
    public interface IIntegrationService
    {
        Task NotifyUserUpdatedAsync(Guid identityId, string email);
    }
}
