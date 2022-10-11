package net.ripe.rpki.ta;


import lombok.extern.slf4j.Slf4j;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.config.ProgramOptions;
import net.ripe.rpki.ta.exception.BadOptionsException;
import org.apache.commons.lang3.StringUtils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
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
            return run(Env.config(options), options, args);
        } catch (BadOptionsException e) {
            return new Exit(EXIT_ERROR_2, e.getMessage() + "\n" + ProgramOptions.getUsageString());
        } catch (Exception e) {
            log.error("Exiting due to uncaught exception", e);
            return Exit.of(e);
        }
    }

    public static Exit run(final Config config, final String... args) {
        try {
            return run(config, new ProgramOptions(args), args);
        } catch (BadOptionsException e) {
            return new Exit(EXIT_ERROR_2, e.getMessage() + "\n" + ProgramOptions.getUsageString());
        } catch (Exception e) {
            log.error("Exiting due to uncaught exception", e);
            return Exit.of(e);
        }
    }

    private static Exit run(final Config config, final ProgramOptions options, final String... args) throws Exception {
        options.validateOptions();

        final TA ta = new TA(config);

        if (options.hasExportCertificateOption()) {
            try (final FileOutputStream out = new FileOutputStream(options.getPrintCertificateFileName())) {
                out.write(ta.getCertificateDER());
            }
            return new Exit(EXIT_OK);
        }

        if (options.hasRequestOption() && options.hasResponseOption()) {
            ta.processRequestXml(options);
            return new Exit(EXIT_OK);
        }

        if (options.hasPrintTALOption()) {
            try (PrintStream out = getOutput(options.getTalFilePath())) {
                String tal = new String(ta.getCurrentTrustAnchorLocator().getBytes(), "UTF-8");
                out.print(tal);
            }
            return new Exit(EXIT_OK);
        }

        if (options.hasInitialiseOption() || options.hasGenerateTACertificateOption()) {
            ta.persist(ta.createNewTAState(options));
            return new Exit(EXIT_OK);
        }

        return new Exit(EXIT_ERROR_2, ProgramOptions.getUsageString());
    }

    private static PrintStream getOutput(String filename) throws IOException {
        if (filename.equals("-")) {
            return System.out;
        } else {
            return new PrintStream(new FileOutputStream(filename));
        }
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
