using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace OwaspTopTenDemo.Blazor.Services
{
    public class TokenService
    {
        private readonly ProtectedLocalStorage _localStorage;

        public TokenService(ProtectedLocalStorage localStorage)
        {
            _localStorage = localStorage;
        }

        public async Task SetToken(string token)
        {
            await _localStorage.SetAsync("authToken", token);
        }

        public async Task<string> GetToken()
        {
            var result = await _localStorage.GetAsync<string>("authToken");
            return result.Success ? result.Value : null;
        }

        public async Task RemoveToken()
        {
            await _localStorage.DeleteAsync("authToken");
        }
    }
}
