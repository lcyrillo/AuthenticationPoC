using AuthenticationPOC.Interfaces;
using AuthenticationPOC.Models;
using Dapper;
using System.Data.SqlClient;

namespace AuthenticationPOC.Data;

public class UserDao : IUserDao
{
    private readonly IConfiguration _config;

    public UserDao(IConfiguration config)
    {
        _config = config;
    }

    public async void Add(User user)
    {
        using var connection = new SqlConnection(_config.GetConnectionString("SqlServer"));
        await connection.ExecuteAsync("INSERT INTO USERS (USERNAME, PASSWORDHASH, PASSWORDSALT) VALUES (@Username, @PasswordHash, @PasswordSalt)", user);
    }

    public User GetUser(UserDto userDto)
    {
        using var connection = new SqlConnection(_config.GetConnectionString("SqlServer"));
        var user = connection.QueryFirstOrDefault<User>("SELECT USERNAME, PASSWORDHASH, PASSWORDSALT FROM USERS WHERE USERNAME = @Username", new { Username = userDto.UserName });

        return user;
    }
}

