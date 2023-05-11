using AuthenticationPOC.Models;

namespace AuthenticationPOC.Interfaces;

public interface IUserDao
{
    public void Add(User user);
    User GetUser(UserDto userDto);
}

