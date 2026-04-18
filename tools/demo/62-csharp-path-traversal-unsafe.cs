using System.IO;

public class FileDownloadUnsafe
{
    public string Read()
    {
        string filename = Request.Query["file"];
        var target = Path.Combine("/srv/files", filename);
        return File.ReadAllText(target);
    }
}
