using System.Net.Http;

public class AvatarFetcherUnsafe
{
    public async Task<string> Fetch()
    {
        string url = Request.Query["url"];
        return await httpClient.GetStringAsync(url);
    }
}
