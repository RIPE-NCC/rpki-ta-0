package net.ripe.rpki.ta.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

public class FileUtilTest {
    @Test
    public void testFilesAreCreatedAlready(@TempDir Path tempDir) throws IOException {
        // Beforehand, the temp dir is empty
        assertThat(Files.list(tempDir)).isEmpty();

        // File exists and is a file, not dir
        assertThat(FileUtil.findAvailableBackupFile(tempDir.resolve("name.txt"), Instant.now()))
                .exists()
                .isFile();

        // And that file is created in the directory.
        assertThat(Files.list(tempDir)).isNotEmpty();
    }

    @Test
    public void testNamingStrategy(@TempDir Path tempDir) throws IOException {
        Path baseName = tempDir.resolve("important.txt");
        Instant now = Instant.parse("2007-12-03T10:15:30.51Z");

        // Find first file and write to it, so it will conflict
        assertThat(FileUtil.findAvailableBackupFile(baseName, now)).hasFileName("important.txt.2007-12-03T10:15:30Z");

        // Second file has -1 appended
        assertThat(FileUtil.findAvailableBackupFile(baseName, now)).hasFileName("important.txt.2007-12-03T10:15:30Z-1");

        // Afterwards, counter increments
        assertThat(FileUtil.findAvailableBackupFile(baseName, now)).hasFileName("important.txt.2007-12-03T10:15:30Z-2");
    }
}
