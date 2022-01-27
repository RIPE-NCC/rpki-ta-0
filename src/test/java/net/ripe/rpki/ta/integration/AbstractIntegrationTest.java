package net.ripe.rpki.ta.integration;


import com.google.common.io.Files;
import lombok.SneakyThrows;
import net.ripe.rpki.ta.Main;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

@Ignore
public abstract class AbstractIntegrationTest {

    private static final String DEFAULT_USER_DIR = System.getProperty("user.dir");

    @BeforeClass
    public static void setWorkingDirectory() throws IOException {
        final File tempDirectory = java.nio.file.Files.createTempDirectory("abstractIntegrationtest").toFile();
        tempDirectory.deleteOnExit();
        System.setProperty("user.dir", tempDirectory.getAbsolutePath());
    }

    @AfterClass
    public static void resetWorkingDirectory() {
        System.setProperty("user.dir", DEFAULT_USER_DIR);
    }

    protected Main.Exit run(final String args) {
        return run(args.split(" "));
    }

    protected Main.Exit run(final String[] args) {
        return Main.run(args);
    }

    protected static void deleteFile(final String pathToFile) {
        new File(pathToFile).delete();
    }

    @SneakyThrows
    protected String readFile(final String pathToFile) {
        return Files.asCharSource(new File(pathToFile), Charset.defaultCharset()).read();
    }

}
