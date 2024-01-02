using SampleWebApi.Common;

namespace SampleWebApi.Domain
{
    public class User : BaseEntity
    {
        

        public string Fullname { get; set; }
        public string Username { get; set; }

        public string Password { get; set; }
        public bool IsActive { get; set; } = true;
    }
}
