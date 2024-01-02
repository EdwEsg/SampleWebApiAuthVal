using SampleWebApi.Common;
using MediatR;
using Microsoft.IdentityModel.Tokens;
using SampleWebApi.Data;
using SampleWebApi.Domain;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SampleWebApi.Features
{
    public class AuthenticationUser
    {

        public class AuthenticationUserResult
        {
            public int Id { get; set; }

            public string FullName { get; set; }

            public string UserName { get; set; }

            public string Password { get; set; }

            public string Token { get; set; }

            public AuthenticationUserResult(User user, string token)
            {
                
                Id = user.Id;
                FullName = user.Fullname;
                UserName = user.Username; 
                Password = user.Password;
                Token = token;

            }
        }

        public class AuthenticationUserCommand : IRequest<Result>
        {
            [Required]
            public string Username { get; set; }
            [Required]
            public string Password { get; set; }
        }



        public class Handler : IRequestHandler<AuthenticationUserCommand, Result>
        {

            private readonly IConfiguration _configuration;
            private readonly SampleWebApiDbContext _context;

            public Handler(SampleWebApiDbContext context , IConfiguration configuration)
            {
                _context = context;
                _configuration = configuration;
            }

            public async Task<Result> Handle(AuthenticationUserCommand command, CancellationToken cancellationToken)
            {

                var user =  _context.Users.Where(x => x.Username == command.Username && x.Password == command.Password && x.IsActive == true)
                    .SingleOrDefault();

                if(user == null)
                {
                    return Result.Failure(AutheticationError.IncorrectUsernameOrPassword());
                }


                await _context.SaveChangesAsync(cancellationToken);

                var token = GenerateJwtToken(user);

                var result = user.ToGetAuthenticatedUserResult(token);

                return Result.Success(result);


            }

            public string GenerateJwtToken(User user)
            {
                var key = _configuration.GetValue<string>("JwtConfig:Key");
                var KeyBytes = Encoding.ASCII.GetBytes(key);
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim("id", user.Id.ToString()),
                        new Claim(ClaimTypes.Name , user.Fullname),
                    }),
                    Expires = DateTime.UtcNow.AddDays(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(KeyBytes),
                        SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }


        }


    }

    public static class AuthenticateMappingExtension
    {
        public static AuthenticationUser.AuthenticationUserResult ToGetAuthenticatedUserResult(this User user, string token)
        {
            return new AuthenticationUser.AuthenticationUserResult(user, token);
        }

    }
}
