import jakarta.servlet.http.HttpServletRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileDownloadUnsafe {
    public String read(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("file");
        Path target = Paths.get("/srv/files", filename);
        return Files.readString(target);
    }
}
