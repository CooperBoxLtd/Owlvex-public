using System.Net.Http;

public class AvatarFetcherSafe
{
    public async Task<string> Fetch()
    {
        return await httpClient.GetStringAsync("https://example.com/avatar.png");
    }
}
