package net.ripe.rpki.ta.persistence;


import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.io.Files;
import lombok.extern.slf4j.Slf4j;
import net.ripe.rpki.ta.config.Config;

import java.io.File;
import java.io.IOException;

@Slf4j
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

    // TODO Add backing up the existing file
    public void save(String xml) throws IOException {
        final File tempFile = File.createTempFile(
                Strings.padStart(TRUST_ANCHOR_FILENAME, 3, '_'),
                TRUST_ANCHOR_FILE_EXT, persistenceDirectory);
        try {
            Files.write(xml, tempFile, Charsets.UTF_8);
            Files.move(tempFile, trustAnchorFile);
            log.info("Trust Anchor written to: " + trustAnchorFile);
        } finally {
            if (tempFile.exists()) tempFile.delete();
        }
    }

    public String load() throws IOException {
        return Files.toString(trustAnchorFile, Charsets.UTF_8);
    }

    public String load(String fileName) throws IOException {
        return Files.toString(new File(fileName), Charsets.UTF_8);
    }

    public boolean taStateExists() {
        return trustAnchorFile.exists();
    }

}
