package net.ripe.rpki.ta.integration;

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

import net.ripe.rpki.ta.Main;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import com.google.common.io.Files;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

@Ignore
public abstract class AbstractIntegrationTest {

    private static final String DEFAULT_USER_DIR = System.getProperty("user.dir");

    @BeforeClass
    public static void setWorkingDirectory() throws IOException {
        final File tempDirectory = Files.createTempDir();
        tempDirectory.deleteOnExit();
        System.setProperty("user.dir", tempDirectory.getAbsolutePath());
    }

    @AfterClass
    public static void resetWorkingDirectory() {
        System.setProperty("user.dir", DEFAULT_USER_DIR);
    }

    protected int run(final String args) {
        return run(args.split(" "));
    }

    protected int run(final String[] args) {
        return new Main().run(args);
    }

    protected void deleteFile(final String pathToFile) {
        new File(pathToFile).delete();
    }

    protected String readFile(final String pathToFile) {
        try {
            return Files.toString(new File(pathToFile), Charset.defaultCharset());
        } catch (IOException e) {
            throw new AssertionError(e.getClass().getName() + ": " + e.getMessage());
        }
    }

}
