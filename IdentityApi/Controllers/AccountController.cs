using IdentityApi.Domain;
using IdentityApi.Models.RequestDTOs;
using IdentityApi.Services.Abstracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IIntegrationService _integrationService;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            IEmailService emailService,
            IIntegrationService integrationService)
        {
            _userManager = userManager;
            _emailService = emailService;
            _integrationService = integrationService;
        }

        // Helper metot: Token'dan mevcut kullanıcıyı bulur
        private async Task<ApplicationUser?> GetCurrentUserAsync()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return null;

            return await _userManager.FindByIdAsync(userId);
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            var user = await GetCurrentUserAsync();
            if (user == null) return Unauthorized();

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok("Password changed successfully.");
        }

        [HttpPost("request-email-change")]
        public async Task<IActionResult> RequestEmailChange([FromBody] RequestEmailChangeRequest request)
        {
            var user = await GetCurrentUserAsync();
            if (user == null) return Unauthorized();

            if (user.Email.Equals(request.NewEmail, StringComparison.OrdinalIgnoreCase))
                return BadRequest("This is already your email.");

            // YENİ email adresi için bir onay token'ı oluştur
            var token = await _userManager.GenerateChangeEmailTokenAsync(user, request.NewEmail);
            await _emailService.SendEmailAsync(request.NewEmail, "Confirm Your New Email", $"Token: {token}");

            return Ok("Verification email sent to new address. Please confirm.");
        }

        [AllowAnonymous]
        [HttpGet("confirm-email-change")]
        public async Task<IActionResult> ConfirmEmailChange([FromQuery] Guid userId, [FromQuery] string token, [FromQuery] string newEmail)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null) return BadRequest("Invalid request.");

            // Token'ı doğrula
            var result = await _userManager.ChangeEmailAsync(user, newEmail, token);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Email değişti, şimdi UserName'i de güncellemeliyiz
            await _userManager.SetUserNameAsync(user, newEmail);

            // === Entegrasyon: LogisticsAPI'ye haber ver ===
            await _integrationService.NotifyUserUpdatedAsync(user.Id, user.Email);

            return Ok("Email changed successfully.");
        }

        [HttpPost("update-device-id")]
        public async Task<IActionResult> UpdateDeviceId([FromBody] string deviceId)
        {
            var user = await GetCurrentUserAsync();
            if (user == null) return Unauthorized();

            user.DeviceId = deviceId;
            await _userManager.UpdateAsync(user);

            return Ok();
        }
    }
}
