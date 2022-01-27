package net.ripe.rpki.ta.persistence;


import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;
import lombok.extern.slf4j.Slf4j;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.util.FileUtil;

import java.io.File;
import java.io.IOException;
import java.time.Instant;

@Slf4j(topic = "TAPersistence")
public class TAPersistence {

    private static final String TRUST_ANCHOR_FILENAME = "ta";
    private static final String TRUST_ANCHOR_FILE_EXT = "xml";

    private final File persistenceDirectory;
    private final File trustAnchorFile;

    public TAPersistence(final Config config) {
        this.persistenceDirectory = new File(config.getPersistentStorageDir());
        if (!this.persistenceDirectory.exists()) this.persistenceDirectory.mkdirs();
        Preconditions.checkArgument(this.persistenceDirectory.isDirectory(), "Can't create directory: " + persistenceDirectory);
        this.trustAnchorFile = new File(this.persistenceDirectory, TRUST_ANCHOR_FILENAME + "." + TRUST_ANCHOR_FILE_EXT);
    }

    public void save(String xml) throws IOException {
        final File tempFile = File.createTempFile(
                Strings.padStart(TRUST_ANCHOR_FILENAME, 3, '_'),
                TRUST_ANCHOR_FILE_EXT, persistenceDirectory);
        try {
            // write a backup of the trust anchor state
            if (trustAnchorFile.exists()) {
                final File backupFile = FileUtil.findAvailableBackupFile(trustAnchorFile.toPath(), Instant.now());
                Files.copy(trustAnchorFile, backupFile);
               log.info("Stored a backup of the previous trust anchor state in '{}' (sha256={})", backupFile, getTrustAnchorSha256());
           } else {
               log.info("Initial save of trust anchor state.");
           }

            Files.asCharSink(tempFile, Charsets.UTF_8).write(xml);
            Files.move(tempFile, trustAnchorFile);
            log.info("Trust Anchor written to: '{}' (sha256={})", trustAnchorFile, getTrustAnchorSha256());
        } finally {
            if (tempFile.exists()) tempFile.delete();
        }
    }

    private HashCode getTrustAnchorSha256() throws IOException {
        return Hashing.sha256().hashBytes(Files.asByteSource(trustAnchorFile).read());
    }

    public String load() throws IOException {
        byte[] content = Files.asByteSource(trustAnchorFile).read();

        log.info("Loaded trust anchor state (sha256={})", Hashing.sha256().hashBytes(content));
        return new String(content, Charsets.UTF_8);
    }

    public boolean taStateExists() {
        return trustAnchorFile.exists();
    }

}
