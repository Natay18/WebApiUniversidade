using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using apiUniversidade.Model;
using apiUniversidade.Context;
using Microsoft.AspNetCore.Identity;
using apiUniversidade.DTO;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

namespace apiUniversidade.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AutorizaController : Controller
    {
        private UsuarioToken GeraToken(UsuarioDTO userInfo){
                var claims = new[]{
                    new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.UniqueName, userInfo.Email),
                    new Claim("IFRN", "TecInfo"),
                    new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                };

                var key = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_configuration["Jwt:key"]));
                
                var credentials = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

                var expiracao = _configuration["TokenConfiguration:ExpireHours"];
                var expiration = DateTime.UtcNow.AddHours(double.Parse(expiracao));

                JwtSecurityToken token = new JwtSecurityToken(
                    issuer: _configuration ["TokenConfiguration:Issuer"],
                    audience: _configuration ["TokenConfiguration:Audience"],
                    claims: claims,
                    expires: expiration,
                    signingCredentials: credentials
                );

                return new UsuarioToken(){
                    Autenticado = true,
                    Expiracao = expiration,
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    Mensagem = "JWT Ok."

                };
        }


        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AutorizaController(UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpGet]
        public ActionResult<string> Get(){
             return "AutorizaController :: Acessado em : "
                 + DateTime.Now.ToLongDateString();
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody]UsuarioDTO model){
            var user = new IdentityUser{
                UserName = model.Email,
                Email = model.Email,
                EmailConfirmed = true 
            };
                
            var result = await _userManager.CreateAsync(user, model.Senha);
            if (!result.Succeeded)
                return BadRequest(result.Errors);
                
            await _signInManager.SignInAsync(user, false);
            return Ok(GeraToken(model));    
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UsuarioDTO UserInfo){

            var result = await _signInManager.PasswordSignInAsync(UserInfo.Email, UserInfo.Senha, 
                isPersistent: false, lockoutOnFailure: false);

            if (!result.Succeeded)
                return Ok(GeraToken(UserInfo));
            else{
                ModelState.AddModelError(string.Empty, "Login Inválido...");
                return BadRequest(ModelState);
            }
        }
    }
}