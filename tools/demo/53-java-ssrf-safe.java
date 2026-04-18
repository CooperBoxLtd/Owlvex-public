import java.net.URL;

public class AvatarFetcherSafe {
    public void fetch() throws Exception {
        URL target = new URL("https://example.com/avatar.png");
        target.openStream();
    }
}
