namespace IdentityApi.Models.ResponseDTOs
{
    public record RegisterResponse(Guid UserId, string Email, bool RequiresConfirmation);
}
