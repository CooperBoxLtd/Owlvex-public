import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileDownloadSafe {
    public String read() throws Exception {
        Path target = Paths.get("/srv/files", "logo.png");
        return Files.readString(target);
    }
}
