package net.ripe.rpki.ta.util;

import com.google.common.io.Files;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class FileUtilTest {
    @Test
    public void testNamingStrategy(@TempDir Path tempDir) throws IOException {
        Path baseName = tempDir.resolve("important.txt");
        Instant now = Instant.parse("2007-12-03T10:15:30.51Z");

        // Find first file and write to it, so it will conflict
        File firstCopy = FileUtil.findAvailableBackupFile(baseName, now);
        Files.asCharSink(firstCopy, Charset.defaultCharset()).write(firstCopy.getName());

        assertThat(firstCopy).hasFileName("important.txt.2007-12-03T10:15:30Z");

        // Second file has -1 appended
        File secondFile = FileUtil.findAvailableBackupFile(baseName, now);
        Files.asCharSink(secondFile, Charset.defaultCharset()).write(secondFile.getName());

        assertThat(secondFile).hasFileName("important.txt.2007-12-03T10:15:30Z-1");

        // Afterwards, counter increments
        assertThat(FileUtil.findAvailableBackupFile(baseName, now)).hasFileName("important.txt.2007-12-03T10:15:30Z-2");
    }
}
