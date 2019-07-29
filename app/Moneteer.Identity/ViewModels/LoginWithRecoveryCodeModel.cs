using System.ComponentModel.DataAnnotations;

namespace Moneteer.Identity.ViewModels
{
    public class LoginWithRecoveryCodeModel
    {
        [Required]
        [DataType(DataType.Text)]
        [Display(Name = "Recovery Code")]
        public string RecoveryCode { get; set; }
        public bool RememberMe { get; set; }
    }
}

