using System.Net.Http.Headers;
using InteractiveBrokers.Helpers;

namespace InteractiveBrokers;

public sealed class IBRestClient
{
    private readonly HttpClient _httpClient;

    public IBRestClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    /// <summary>
    /// See more: https://www.interactivebrokers.com/webtradingapi/doc.html#tag/OAuth/paths/~1oauth~1request_token/post
    /// https://oauth.net/core/1.0a/#auth_step1
    /// </summary>
    /// <param name="consumerKey"></param>
    /// <returns></returns>
    public async ValueTask<string> RequestTokenAsync(string consumerKey)
    {
        const string requestUri = "oauth/request_token";

        var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

        var baseUrl = _httpClient.BaseAddress!.AbsoluteUri;
        var authorizationHeader = OAuthHelper.GetAuthorizationHeader($"{baseUrl}{requestUri}", "POST", consumerKey);

        var authSplit = authorizationHeader.Split(' ');
        request.Headers.Authorization = new AuthenticationHeaderValue(authSplit[0], authSplit[1]);

        var response = await _httpClient.SendAsync(request);
        return await response.Content.ReadAsStringAsync();
    }
}
