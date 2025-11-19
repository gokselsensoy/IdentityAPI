using IdentityApi.Domain;
using IdentityApi.Models.RequestDTOs;
using IdentityApi.Models.ResponseDTOs;
using IdentityApi.Services.Abstracts;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

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
        private readonly IOpenIddictApplicationManager _applicationManager;

        // OpenIddict'in token üretebilmesi için SignInManager'a ihtiyacı var
        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailService emailService,
            IIntegrationService integrationService,
            IOpenIddictApplicationManager applicationManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _integrationService = integrationService;
            _applicationManager = applicationManager;
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
            //await _integrationService.NotifyUserUpdatedAsync(user.Id, user.Email);

            return Ok(new CreateInternalUserResponse(user.Id, user.Email));
        }


        #region connect/token
        [HttpPost("~/connect/token")]
        [Consumes("application/x-www-form-urlencoded")] // Swagger'a Form tipi olduğunu söyle
        [Produces("application/json")]
        public async Task<IActionResult> Exchange([FromForm] TokenRequest request)
        {
            // Gelen OIDC isteğini al
            var openIddictRequest = HttpContext.GetOpenIddictServerRequest();
            if (openIddictRequest == null) throw new InvalidOperationException("İstek okunamadı.");

            // 1. SENARYO: S2S (LogisticsAPI gibi servisler için)
            if (openIddictRequest.IsClientCredentialsGrantType())
            {
                // Client ID'yi al (ClientRegistrationWorker'da kaydettiğimiz)
                var applicationId = openIddictRequest.ClientId;

                // Client'ın varlığını doğrula (OpenIddict bunu zaten yapmış olabilir ama güvenli taraf)
                var application = await _applicationManager.FindByClientIdAsync(applicationId);
                if (application == null)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "İstemci bulunamadı."
                        }));
                }

                // Yeni bir kimlik (ClaimsPrincipal) oluştur
                // Bu bir "insan" değil, bir "servis" olduğu için User tablosuna bakmıyoruz.
                var identity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Kimliğe gerekli claim'leri ekle
                identity.AddClaim(Claims.Subject, applicationId); // ID olarak ClientID kullan
                identity.AddClaim(Claims.Name, await _applicationManager.GetDisplayNameAsync(application));

                // *** KRİTİK NOKTA ***
                // LogisticsAPI'nin [Authorize(Policy = "InternalApiAccess")] politikasını
                // geçebilmesi için 'client_id' claim'ini ekliyoruz.
                // OpenIddict bunu genelde otomatik yapar ama biz garantiye alalım.
                identity.AddClaim("client_id", applicationId);

                // Token'a eklenecek hakları (Scopes) belirle
                identity.SetScopes(openIddictRequest.GetScopes());
                identity.SetDestinations(GetDestinations);

                // Token'ı üret ve dön
                return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 2. SENARYO: KULLANICI (Mobil/Web - Password Grant)
            if (openIddictRequest.IsPasswordGrantType())
            {
                var user = await _userManager.FindByNameAsync(openIddictRequest.Username);
                if (user == null)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Kullanıcı adı veya şifre hatalı."
                        }));
                }

                // Şifreyi kontrol et
                var result = await _signInManager.CheckPasswordSignInAsync(user, openIddictRequest.Password, lockoutOnFailure: true);
                if (!result.Succeeded)
                {
                    return Forbid(
                        authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                        properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Kullanıcı adı veya şifre hatalı."
                        }));
                }

                // Email onayı kontrolü (Program.cs'te zorunlu kıldıysak)
                if (_userManager.Options.SignIn.RequireConfirmedEmail && !await _userManager.IsEmailConfirmedAsync(user))
                {
                    return Forbid(
                       authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                       properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties(new Dictionary<string, string>
                       {
                           [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                           [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Lütfen önce email adresinizi onaylayın."
                       }));
                }

                // Kullanıcı için Principal oluştur
                var principal = await _signInManager.CreateUserPrincipalAsync(user);

                // Scope ve Destination ayarlarını yap
                principal.SetScopes(openIddictRequest.GetScopes());
                foreach (var claim in principal.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim, principal));
                }

                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            // 3. SENARYO: Refresh Token
            if (openIddictRequest.IsRefreshTokenGrantType())
            {
                // Refresh token ile gelen identity'yi al
                var info = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                var user = await _userManager.GetUserAsync(info.Principal);

                if (user == null)
                {
                    return Forbid(
                       authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                       properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties(new Dictionary<string, string>
                       {
                           [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                           [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Refresh token artık geçerli değil."
                       }));
                }

                // Kullanıcının hala giriş yapabilir durumda olduğunu kontrol et (banlanmış mı vb.)
                if (!await _signInManager.CanSignInAsync(user))
                {
                    return Forbid(
                       authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                       properties: new Microsoft.AspNetCore.Authentication.AuthenticationProperties(new Dictionary<string, string>
                       {
                           [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                           [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Kullanıcı artık giriş yapamaz."
                       }));
                }

                var principal = await _signInManager.CreateUserPrincipalAsync(user);
                foreach (var claim in principal.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim, principal));
                }

                return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            throw new NotImplementedException("Bu grant type henüz desteklenmiyor.");
        }

        // Yardımcı Metot: Claim'lerin Access Token'a mı yoksa Identity Token'a mı gideceğini belirler
        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // Basit versiyon: Her şeyi Access Token'a koy
            yield return Destinations.AccessToken;
        }

        private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        {
            // User için detaylı versiyon
            yield return Destinations.AccessToken;

            if (claim.Type == Claims.Name || claim.Type == Claims.Email)
                yield return Destinations.IdentityToken;
        }
        #endregion
    }
}
