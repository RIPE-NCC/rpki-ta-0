package net.ripe.rpki.ta.persistence;

/*-
 * ========================LICENSE_START=================================
 * RIPE NCC Trust Anchor
 * -
 * Copyright (C) 2017 RIPE NCC
 * -
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the RIPE NCC nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * =========================LICENSE_END==================================
 */

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.io.Files;
import net.ripe.rpki.ta.config.Config;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class TAPersistence {

    private static final Logger LOG = Logger.getLogger(TAPersistence.class);

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
        final File tempFile = File.createTempFile(Strings.padStart(TRUST_ANCHOR_FILENAME, 3, '_'), TRUST_ANCHOR_FILE_EXT, persistenceDirectory);
        try {
            Files.write(xml, tempFile, Charsets.UTF_8);
            Files.move(tempFile, trustAnchorFile);
            LOG.info("Trust Anchor written to: " + trustAnchorFile);
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

    public boolean exists() {
        return trustAnchorFile.exists();
    }

}
