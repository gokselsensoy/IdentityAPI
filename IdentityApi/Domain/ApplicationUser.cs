using Microsoft.AspNetCore.Identity;

namespace IdentityApi.Domain
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string? DeviceId { get; set; }
    }
}
