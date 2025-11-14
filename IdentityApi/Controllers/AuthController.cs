using IdentityApi.Domain;
using IdentityApi.Models.RequestDTOs;
using IdentityApi.Models.ResponseDTOs;
using IdentityApi.Services.Abstracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly IIntegrationService _integrationService;

        // OpenIddict'in token üretebilmesi için SignInManager'a ihtiyacı var
        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailService emailService,
            IIntegrationService integrationService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _integrationService = integrationService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var userExists = await _userManager.FindByEmailAsync(request.Email);
            if (userExists != null)
                return BadRequest("User with this email already exists.");

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                Email = request.Email,
                UserName = request.Email
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Email onay token'ı oluştur ve email gönder
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            // TODO: 'token'ı bir URL içine yerleştir (örn: 'https://myfrontend.com/confirm?token=...')
            await _emailService.SendEmailAsync(user.Email, "Confirm your email", $"Token: {token} | UserId: {user.Id}");

            // === Entegrasyon: LogisticsAPI'ye haber ver ===
            await _integrationService.NotifyUserUpdatedAsync(user.Id, user.Email);

            return Ok(new RegisterResponse(user.Id, user.Email, true));
        }

        // === LOGIN ===
        // Bu endpoint OpenIddict'e özeldir: '/connect/token'
        // Bizim bir Login endpoint'imiz OLMAYACAK. 
        // İstemciler (Mobil/Web) doğrudan OpenIddict'in /connect/token adresine 
        // "grant_type=password", "username=...", "password=..." ile istek atacak.

        // OpenIddict, token vermeden ÖNCE bizim Identity ayarlarımızı kontrol edecek.
        // `options.SignIn.RequireConfirmedEmail = true;` dediğimiz için,
        // email'i onaysız kullanıcıya token VERMEYECEK ve "invalid_grant" hatası dönecek.

        // Bizim yapmamız gereken, eğer `DeviceId` gelirse onu kaydetmek.
        // Bu yüzden, `/connect/token` isteğini *yakalayıp* (intercept) araya gireceğiz.
        // Bu, OpenIddict'in gelişmiş bir özelliğidir ve 'IOpenIddictServerHandler' ile yapılır.
        // ŞİMDİLİK daha basit bir yol izleyelim: 
        // Login *başarılı* olduktan sonra mobil uygulama `/api/account/update-device` 
        // diye (bizim yazacağımız) bir endpoint'i çağırsın.

        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
        {
            var user = await _userManager.FindByIdAsync(request.UserId.ToString());
            if (user == null)
                return NotFound("User not found.");

            var result = await _userManager.ConfirmEmailAsync(user, request.Token);
            if (!result.Succeeded)
            {
                // Token süresi dolmuş olabilir (15 dk)
                return BadRequest(result.Errors);
            }

            return Ok("Email confirmed successfully.");
        }

        [HttpPost("resend-confirmation")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return NotFound("User not found.");

            if (await _userManager.IsEmailConfirmedAsync(user))
                return BadRequest("Email is already confirmed.");

            // Yeni token oluştur (eskiyi geçersiz kılar)
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            await _emailService.SendEmailAsync(user.Email, "Confirm your email (New)", $"Token: {token} | UserId: {user.Id}");

            return Ok("Confirmation email sent. Please check your inbox.");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return Ok("If an account exists, a reset link has been sent."); // Güvenlik için

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            // TODO: 'token'ı bir URL içine yerleştir (örn: 'https://myfrontend.com/reset-password?token=...')
            await _emailService.SendEmailAsync(user.Email, "Reset Your Password", $"Token: {token} | Email: {user.Email}");

            return Ok("If an account exists, a reset link has been sent.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
                return BadRequest("Invalid request.");

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
            if (!result.Succeeded)
            {
                // Token süresi dolmuş olabilir (30 dk)
                return BadRequest(result.Errors);
            }

            return Ok("Password has been reset successfully.");
        }

        [Authorize(Policy = "InternalApiAccess")]
        [HttpPost("internal-register")]
        public async Task<IActionResult> RegisterInternal([FromBody] CreateInternalUserRequest request)
        {
            var userExists = await _userManager.FindByEmailAsync(request.Email);
            if (userExists != null)
                return BadRequest("User with this email already exists.");

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                Email = request.Email,
                UserName = request.Email
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // === ÖNEMLİ FARKLAR ===
            // 1. Email'i otomatik onayla, çünkü admin oluşturuyor
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            await _userManager.ConfirmEmailAsync(user, token);

            // 2. İstenen rolü ata
            // (Önce rolün DB'de var olduğundan emin olmalıyız, şimdilik var sayıyoruz)
            await _userManager.AddToRoleAsync(user, request.Role);

            // 3. LogisticsAPI'ye webhook ile haber ver (Sync için)
            await _integrationService.NotifyUserUpdatedAsync(user.Id, user.Email);

            return Ok(new CreateInternalUserResponse(user.Id, user.Email));
        }
    }
}
