using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UserIdentity.Entities;
using UserIdentity.Models;

namespace UserIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountApiController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<AccountController> _logger;
        public AccountApiController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }
        string errormsg="";
        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            model.ReturnUrl ??= Url.Content("~/");
            model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User created a new account with password.");

                await _signInManager.SignInAsync(user, isPersistent: false);
                return Ok();
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
                errormsg = error.Description;
            }
            // If we got this far, something failed, redisplay form
            return BadRequest(errormsg);
        }
        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult> Login(LoginModel model)
        {
            string returnUrl = null;
            returnUrl ??= Url.Content("~/");

            model.ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return Ok(model);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return BadRequest();
            }
        }
    }
}
