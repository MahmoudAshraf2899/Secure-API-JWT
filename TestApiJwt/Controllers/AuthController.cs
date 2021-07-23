using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TestApiJwt.Models;
using TestApiJwt.Services;

namespace TestApiJwt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }
        
        //Register and Post Token
        [HttpPost("register")]
        public async Task <IActionResult> RegisterAsync([FromBody]RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);

            }
            var result = await _authService.RegisterAsync(model);
            if (result.IsAuthenticated == false)
            {
                return BadRequest(result.Message);
            }
            //To Return Specific objects
            //return ok(new{token = result.Token , expiresOn = result.ExpiresOn });

            return Ok(result);
           
        }

        //Login and Get Token
        [HttpPost("Login")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);

            }
            var result = await _authService.GetTokenAsync(model);
            if (result.IsAuthenticated == false)
            {
                return BadRequest(result.Message);
            }
            //To Return Specific objects
            //return ok(new{token = result.Token , expiresOn = result.ExpiresOn });

            return Ok(result);

        }

        //Assign User To Role
        [HttpPost("addrole")]
        public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var result = await _authService.AddRoleAsync(model);

            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(model);
        }

    }
}
