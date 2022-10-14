package net.ripe.rpki.ta;


import lombok.extern.slf4j.Slf4j;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.config.ProgramOptions;
import net.ripe.rpki.ta.exception.BadOptionsException;
import net.ripe.rpki.ta.exception.OperationAbortedException;
import org.apache.commons.lang3.StringUtils;

import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

@Slf4j
public class Main {
    public static final int EXIT_OK = 0;
    public static final int EXIT_ERROR_2 = 2;

    public static void main(String[] args) {
        final Exit run = run(args);
        if (StringUtils.isNotEmpty(run.stderr)) {
            System.err.println(run.stderr);
        }
        System.exit(run.exitCode);
    }

    public static Exit run(final String... args) {
        try {
            final ProgramOptions options = new ProgramOptions(args);
            return run(Env.config(options), options);
        } catch (BadOptionsException e) {
            return new Exit(EXIT_ERROR_2, e.getMessage() + "\n" + ProgramOptions.getUsageString());
        } catch (Exception e) {
            log.error("Exiting due to uncaught exception", e);
            return Exit.of(e);
        }
    }

    private static Exit run(final Config cliConfig, final ProgramOptions options) throws Exception {
        options.validateOptions();

        if (options.hasInitialiseOption() && TA.hasState(cliConfig)) {
            throw new OperationAbortedException("TA state is already serialised to " + cliConfig.getPersistentStorageDir() + ".");
        }

        TA ta = options.hasInitialiseOption() ? TA.initialise(cliConfig) : TA.load(cliConfig);
        if (options.hasGenerateTACertificateOption()) {
            ta.generateTACertificate();
        }

        if (options.hasExportCertificateOption()) {
            try (final FileOutputStream out = new FileOutputStream(options.getPrintCertificateFileName())) {
                out.write(ta.getCertificateDER());
            }
        }

        if (options.hasRequestOption() && options.hasResponseOption()) {
            ta.processRequestXml(options);
        }

        if (options.hasPrintTALOption()) {
            try (final FileOutputStream out = new FileOutputStream(options.getTalFilePath())) {
                out.write(ta.getCurrentTrustAnchorLocator().getBytes());
            }
        }

        ta.persist();
        return new Exit(EXIT_OK);
    }

    public static class Exit {
        public final int exitCode;
        public final String stderr;

        public Exit(int exitCode) {
            this(exitCode, "");
        }

        public Exit(int exitCode, String stderr) {
            this.exitCode = exitCode;
            this.stderr = stderr;
        }

        static Exit of(Exception e) {
            final StringWriter sw = new StringWriter();
            sw.append("The following problem occurred: ").append(e.getMessage()).append("\n");
            e.printStackTrace(new PrintWriter(sw));
            return new Exit(EXIT_ERROR_2, sw.toString());
        }
    }
}
