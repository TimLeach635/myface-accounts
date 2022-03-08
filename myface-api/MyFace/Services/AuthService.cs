using MyFace.Repositories;
using MyFace.Models.Database;
using System;
using MyFace.Helpers;

namespace MyFace.Services
{
    public interface IAuthService
    {
        bool IsValidUsernameAndPassword(string username, string password);
    }

    public class AuthService : IAuthService
    {
        private readonly IUsersRepo _users;

        public AuthService(IUsersRepo users)
        {
            _users = users;
        }

        public bool IsValidUsernameAndPassword(string username, string password)
        {
            User user;
            try
            {
                user = _users.GetByUsername(username);
            }
            catch (InvalidOperationException)
            {
                return false;
            }

            // hash user's password and check it
            string hashed = AuthHelper.HashPassword(
                password,
                user.Salt
            );

            if (hashed != user.HashedPassword)
            {
                return false;
            }

            return true;
        }
    }
}
