using System.IO;

public class FileDownloadSafe
{
    public string Read()
    {
        var target = Path.Combine("/srv/files", "logo.png");
        return File.ReadAllText(target);
    }
}
