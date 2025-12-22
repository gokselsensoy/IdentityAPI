namespace IdentityApi.Models.ResponseDTOs
{
    public record LoginResponse(
            string AccessToken,
            string RefreshToken,
            DateTime ExpiresAt,
            Guid UserId,
            string Email);
}
