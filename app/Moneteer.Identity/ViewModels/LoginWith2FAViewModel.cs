﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Moneteer.Identity.ViewModels
{
    public class LoginWith2FAViewModel
    {
        public string TwoFactorCode { get; set; }
        public bool RememberMachine { get; set; }
        public string ReturnUrl { get; set; }
        public bool RememberMe { get; set; }
    }
}
