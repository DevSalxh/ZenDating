using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

    public class MembersController(AppDbContext context) : BaseApiController
    {
        [HttpGet]
        public async Task<ActionResult<IReadOnlyList<AppUser>>> getMembers()
        {
            var members = await context.Users.ToListAsync();

            return members;
        }
        
        [Authorize]
        [HttpGet("{id}")]
        public async Task<ActionResult<AppUser>> getMembers(int id)
        {
            var member = await context.Users.FindAsync(id);

            if (member == null) return NotFound();

            return member;
        }
    }
}
