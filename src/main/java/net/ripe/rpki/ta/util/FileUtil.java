package net.ripe.rpki.ta.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class FileUtil {
    /**
     * Generate backup filenames following this pattern:
     *   * if it does not exist, use [basename].[ISO date time]
     *   * alternatively, try [basename].[ISO date time]-[index] with increasing indexes.
     * @return a timestamp-formatted file in the same directory that does not exist yet.
     */
    public static File findAvailableBackupFile(final Path basePath, final Instant now) {
        final String baseName = basePath.getFileName().toString();
        final String dateFragment = DateTimeFormatter.ISO_INSTANT.format(now.truncatedTo(ChronoUnit.SECONDS));

        int fileIndex = 0;
        while (true) {
            final String relName = fileIndex == 0 ? String.format("%s.%s", baseName, dateFragment) : String.format("%s.%s-%d", baseName, dateFragment, fileIndex);
            final File cur = basePath.resolveSibling(relName).toFile();
            if (!cur.exists()) {
                return cur;
            }

            fileIndex++;
        }
    }
}
