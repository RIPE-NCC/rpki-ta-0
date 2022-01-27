package net.ripe.rpki.ta.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class FileUtil {
    /**
     * Generate backup filenames following this pattern:
     *   * if it does not exist, use [basename].[ISO date time]
     *   * alternatively, try [basename].[ISO date time]-[index] with increasing indexes.
     *
     *  From <pre>Files.createFile</pre> documentation:
     *  <quote>The check for the existence of the file and the creation of the new file if it does not exist are a single operation that is atomic with respect to all other filesystem activities that might affect the directory.</quote>
     *  This should prevent TOCTOU issues.
     *
     * In practice multiple files being created in a second should not be encountered - the only known situation where
     * multiple files are encountered is during unit tests.
     *
     * @return a timestamp-formatted file in the same directory that was just created.
     */
    public static File findAvailableBackupFile(final Path basePath, final Instant now) throws IOException {
        final String baseName = basePath.getFileName().toString();
        final String dateFragment = DateTimeFormatter.ISO_INSTANT.format(now.truncatedTo(ChronoUnit.SECONDS));

        int fileIndex = 0;
        while (true) {
            final String relName = fileIndex == 0 ? String.format("%s.%s", baseName, dateFragment) : String.format("%s.%s-%d", baseName, dateFragment, fileIndex);
            final Path cur = basePath.resolveSibling(relName);
            // abundance of caution: do not rely on FileAlreadyExistsException when a file is known to exist. Skipping
            // a potential name (TOC, file exists, TOU, file was deleted) does not matter.
            if (!cur.toFile().exists()) {
                try {
                    return Files.createFile(
                            cur,
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
                    ).toFile();
                } catch (FileAlreadyExistsException e) {
                    // expected.
                }
            }

            fileIndex++;
        }
    }
}
