using SampleWebApi.Common;

namespace SampleWebApi.Features
{
    public class AutheticationError
    {

        public static Error IncorrectUsernameOrPassword() =>
       new Error("Authentication.IncorrectUsernameOrPassword", "Username or password is incorrect!");

    }
}
