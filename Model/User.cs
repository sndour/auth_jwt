namespace apiTuto
{

    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[]? PasswordHash { get; set; }

        public byte[]? PassswordSalt { get; set; }
    }
}