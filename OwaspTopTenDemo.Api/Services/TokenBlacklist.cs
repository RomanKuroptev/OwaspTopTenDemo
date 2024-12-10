namespace OwaspTopTenDemo.Api
{
    public static class TokenBlacklist
    {
        private static readonly List<string> _blacklist = new List<string>();

        public static void Add(string token)
        {
            _blacklist.Add(token);
        }

        public static bool Contains(string token)
        {
            return _blacklist.Contains(token);
        }
    }
}
