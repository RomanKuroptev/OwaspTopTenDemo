using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using OwaspTopTenDemo.Blazor.Services;

public class AuthenticatedHttpClientHandler : DelegatingHandler
{
    private readonly TokenService _tokenService;

    public AuthenticatedHttpClientHandler(TokenService tokenService)
    {
        _tokenService = tokenService;
        InnerHandler = new HttpClientHandler(); // Set the inner handler
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var token = await _tokenService.GetToken();
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}