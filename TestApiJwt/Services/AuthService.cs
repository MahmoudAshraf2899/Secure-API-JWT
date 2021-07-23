using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TestApiJwt.Helpers;
using TestApiJwt.Models;

namespace TestApiJwt.Services
{
    //This Class To Implement The IAuth Service InterFace
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager ,IOptions<JWT> jwt)
        {
           _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }
        //Method For Registeration
        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message="Email is already registered"};

            if (await _userManager.FindByNameAsync(model.FirstName) is not null)
                return new AuthModel { Message = "UserName is already registered" };

            var user = new ApplicationUser
            {
                UserName= model.UserName,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };
            
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += error.Description;
                }
                return new AuthModel { Message = errors };

            }
            await _userManager.AddToRoleAsync(user, "User");

            var jwtSecurityToken = await CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                UserName = user.UserName
            };
        }

        //Method For Login
        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(model.Email);


            if(user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email Or Password is Incorrect !";
                return authModel;
            }
            var jwtSecurityToken = await CreateJwtToken(user);
            var rolesList = await _userManager.GetRolesAsync(user);
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.UserName = user.UserName;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();           

            return authModel;
        }

        //Assign User To Role    
        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }
        
        //Method to Create JWT Token and use it In Auth Model Method
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            //user claims Var to get Claims of User
            var userClaims = await _userManager.GetClaimsAsync(user);

            //Roles variable to get Roles of user
            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);
            
            //Variable to make Symmetric Security Key with key that we add in app setting .Json
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));

            //Variable to make Signing Credentials by using Symmetrickey and Security Algorithms
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            //Values that we use when JWT Token is Generated
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
