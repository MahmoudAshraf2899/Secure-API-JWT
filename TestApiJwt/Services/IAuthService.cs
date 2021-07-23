﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TestApiJwt.Models;

namespace TestApiJwt.Services
{
   public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterModel model);
        Task<AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);

    }
}
