package xades4j.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public final class FileUtils
{
    private FileUtils()
    {
    }

    public static String writeTempFile(String contents) throws IOException
    {
        File file = File.createTempFile("xades4j", null);
        file.deleteOnExit();
        Files.writeString(file.toPath(), contents);
        return file.getAbsolutePath();
    }
}
