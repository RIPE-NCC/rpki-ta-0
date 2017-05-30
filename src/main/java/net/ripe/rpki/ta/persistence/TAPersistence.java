package net.ripe.rpki.ta.persistence;

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.util.KeyPairFactory;
import net.ripe.rpki.ta.cas.TrustAnchor;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

public class TrustAnchorPersistenceHandler implements PersistenceHandler<TrustAnchor> {

    private static final Logger LOG = Logger.getLogger(TrustAnchorPersistenceHandler.class);

    static final String TRUST_ANCHOR_FILENAME = "ta";
    static final String TRUST_ANCHOR_FILE_EXT = "xml";
    static final Charset IO_CHARSET = Charsets.UTF_8;

    private TrustAnchorSerializer serializer = new TrustAnchorSerializer();

    private final File persistenceDirectory;
    private final File trustAnchorFile;

    private final KeyPairFactory keyPairFactory;

    public TrustAnchorPersistenceHandler(String persistenceDirectory, KeyPairFactory keyPairFactory) {
        this.persistenceDirectory = new File(persistenceDirectory);
        if (! this.persistenceDirectory.exists()) this.persistenceDirectory.mkdirs();
        Preconditions.checkArgument(this.persistenceDirectory.isDirectory(), "Can't create directory: " + persistenceDirectory);
        this.trustAnchorFile = new File(this.persistenceDirectory, TRUST_ANCHOR_FILENAME + "." + TRUST_ANCHOR_FILE_EXT);
        this.keyPairFactory = keyPairFactory;
    }

    @Override
    public void save(TrustAnchor trustAnchor) throws IOException {
        final File tempFile = File.createTempFile(Strings.padStart(TRUST_ANCHOR_FILENAME, 3, '_'), TRUST_ANCHOR_FILE_EXT, persistenceDirectory);
        try {
            String serializedXml = serializer.serialize(trustAnchor);
            Files.write(serializedXml, tempFile, IO_CHARSET);
            backupOldFileIfItExists();
            Files.move(tempFile, trustAnchorFile);
            LOG.info("Trust Anchor written to: " + trustAnchorFile);
        } finally {
            if (tempFile.exists()) tempFile.delete();
        }
    }

    private void backupOldFileIfItExists() throws IOException {
        if (trustAnchorFile.exists()) {
            File destTaFile = new File(persistenceDirectory, TRUST_ANCHOR_FILENAME + "-" + System.currentTimeMillis() + "." + TRUST_ANCHOR_FILE_EXT);
            Files.move(trustAnchorFile, destTaFile);
        }
    }

    @Override
    public TrustAnchor load() throws IOException {
        TrustAnchor trustAnchor = serializer.deserialize(Files.toString(trustAnchorFile, IO_CHARSET));
        trustAnchor.open(keyPairFactory);
        LOG.info("Trust Anchor read from: " + trustAnchorFile);
        return trustAnchor;
    }
}
