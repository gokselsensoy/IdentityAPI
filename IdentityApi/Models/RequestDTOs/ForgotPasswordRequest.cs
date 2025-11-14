using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record ForgotPasswordRequest([Required, EmailAddress] string Email);
}
