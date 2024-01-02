using MediatR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SampleWebApi.Common;
using SampleWebApi.Data;
using SampleWebApi.Domain;

namespace SampleWebApi.Features
{
    [Route("api/User"), ApiController]
    public class GetUsers : ControllerBase
    {
        private readonly IMediator _mediator;

        public GetUsers(IMediator mediator)
        {
            _mediator = mediator;
        }
        [HttpGet("GetUsers")]

        public async Task<IActionResult> Get([FromQuery]GetUsersQuery query)
        {
            try
            {
                var result = await _mediator.Send(query);
                if (result.IsFailure)
                {
                    return BadRequest(result);
                }
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        public class GetUsersResult
        {
            public int Id { get; set; }
            public string Fullname { get; set; }

            public string Username { get; set; }
            public string Password { get; set; }
            public bool IsActive { get; set; }
        }

        public class GetUsersQuery : IRequest<Result>
        {
            public bool? IsActive { get; set; }

            public string Search { get; set; }
        }


        public class Handler : IRequestHandler<GetUsersQuery, Result>
        {
            private readonly SampleWebApiDbContext _context;

            public Handler(SampleWebApiDbContext context)
            {
                _context = context;
            }

            public async Task<Result> Handle(GetUsersQuery request, CancellationToken cancellationToken)
            {
                IQueryable<User> usersQuery = _context.Users;


                if(!string.IsNullOrEmpty(request.Search))
                {
                    usersQuery = usersQuery.Where(x => x.Fullname.Contains(request.Search) || x.Username.Contains(request.Search));             
                }

                if(request.IsActive != null)
                {
                    usersQuery = usersQuery.Where(x => x.IsActive == request.IsActive);
                }
                   
                if (usersQuery is null)
                {
                    return Result.Failure(UserErrors.NoDataFound());
                }

                var result = await usersQuery.Select(x => new GetUsersResult
                {
                    Id = x.Id,
                    Fullname = x.Fullname,
                    Username = x.Username,
                    Password = x.Password,
                    IsActive = x.IsActive,
                }).ToListAsync();

                return Result.Success(result);
            }
        }
    }
}
