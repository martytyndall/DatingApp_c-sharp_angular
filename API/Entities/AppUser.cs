namespace API.Entities
{
    public class AppUser
    {
        // gets and sets the Id property for the app user
        public int Id { get; set; }

        // gets and sets the username for the app user
        public string UserName { get; set; }

        // gets and sets the password hash for the app user
        public byte[] PasswordHash { get; set; }

        // gets and sets the password salt for the app user
        public byte[] PasswordSalt { get; set; }
    }
}