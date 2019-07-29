using IdentityServer4.Services;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;
using Moneteer.Identity.ViewModels;
using Moneteer.Identity.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using IdentityServer4.Events;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Moneteer.Identity.Helpers;

namespace Moneteer.Identity.Controllers
{
    public class AccountController : Controller
    {
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly IClientStore _clientStore;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEventService _eventService;
        private readonly IPersistedGrantService _persistedGrantService;
        private readonly ILogger<AccountController> _logger;
        private readonly IConfigurationHelper _configurationHelper;

        public AccountController(
            IIdentityServerInteractionService interactionService,
            IAuthenticationSchemeProvider authenticationSchemeProvider,
            IPersistedGrantService persistedGrantService,
            IClientStore clientStore,
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IEventService eventService,
            ILogger<AccountController> logger,
            IConfigurationHelper configurationHelper)
        {
            _interactionService = interactionService;
            _authenticationSchemeProvider = authenticationSchemeProvider;
            _clientStore = clientStore;
            _userManager = userManager;
            _signInManager = signInManager;
            _eventService = eventService;
            _persistedGrantService = persistedGrantService;
            _logger = logger;
            _configurationHelper = configurationHelper;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var vm = await BuildLoginViewModelAsync(returnUrl);

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            var returnUrl = model.ReturnUrl;

            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, isPersistent: true, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByEmailAsync(model.Email);

                    await _eventService.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName));

                    if (_interactionService.IsValidReturnUrl(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }

                    return Redirect(_configurationHelper.LandingUri);
                }
                else if (result.IsLockedOut)
                {
                    ModelState.AddModelError("", "Account locked. Please contact support.");
                }
                else if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(LoginWith2FA), new { returnUrl, RememberMe = true });
                }
                else
                {
                    var user = await _userManager.FindByEmailAsync(model.Email);

                    if (user != null && !await _userManager.IsEmailConfirmedAsync(user))
                    {
                        await _eventService.RaiseAsync(new UserLoginFailureEvent(model.Email, "must confirm email"));
                        ModelState.AddModelError("", "You must confirm your email before logging in. Click on the link in the email sent when you signed up.");
                    }
                    else
                    {
                        await _eventService.RaiseAsync(new UserLoginFailureEvent(model.Email, "invalid credentials"));
                        ModelState.AddModelError("", "Invalid username or password");
                    }
                }
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);

            return View(vm);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2FA(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync().ConfigureAwait(false);

            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var model = new LoginWith2FAViewModel { RememberMe = rememberMe };
            ViewData["ReturnUrl"] = returnUrl;

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2FA(LoginWith2FAViewModel model, bool rememberMe, string returnUrl = null)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync().ConfigureAwait(false);
            if (user == null || model.TwoFactorCode == null)
            {
                // This can happen if the user stays on the LoginWith2FA for a while and then tries to submit
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return View();
            }

            var authenticatorCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, model.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID {UserId} logged in with 2fa.", user.Id);
                return RedirectToLocal(returnUrl);
            }
            else if (result.IsLockedOut)
            {
                _logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return RedirectToAction(nameof(Lockout));
            }
            else
            {
                _logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return View();
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        public Task<IActionResult> Logout(string logoutId)
        {
            return Logout(new LogoutViewModel { LogoutId = logoutId });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutViewModel model)
        {
            var logout = await _interactionService.GetLogoutContextAsync(model.LogoutId);

            var vm = new LoggedOutViewModel
            {
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = model.LogoutId
            };
            
            if (User?.Identity.IsAuthenticated == true)
            {
                await _signInManager.SignOutAsync();

                await _eventService.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            if (vm.PostLogoutRedirectUri != null)
            {
                return Redirect(vm.PostLogoutRedirectUri);
            }
            else
            {
                return View("LoggedOut", vm);
            }
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginViewModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Email = model.Email;
            vm.ShouldConfirmEmail = model.ShouldConfirmEmail;
            return vm;
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interactionService.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    Email = context?.LoginHint,
                    ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
                };
            }

            var schemes = await _authenticationSchemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                EnableLocalLogin = true,
                ReturnUrl = returnUrl,
                Email = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(AccountController.Login), "Home");
            }
        }
    }
}
