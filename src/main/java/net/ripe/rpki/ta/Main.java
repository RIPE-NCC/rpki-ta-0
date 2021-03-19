/**
 * Copyright © 2017, RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.ta;


import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.config.ProgramOptions;
import org.apache.commons.lang3.StringUtils;

import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

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
        } catch (BadOptions e) {
            return new Exit(EXIT_ERROR_2, e.getMessage() + "\n" + ProgramOptions.getUsageString());
        } catch (Exception e) {
            return Exit.of(e);
        }
    }

    public static Exit run(final Config config, final String... args) {
        try {
            return run(config, new ProgramOptions(args), args);
        } catch (BadOptions e) {
            return new Exit(EXIT_ERROR_2, e.getMessage() + "\n" + ProgramOptions.getUsageString());
        } catch (Exception e) {
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
            try (final FileOutputStream out = new FileOutputStream(options.getTalFilePath())) {
                out.write(ta.getCurrentTrustAnchorLocator().getBytes());
            }
            return new Exit(EXIT_OK);
        }

        if (options.hasInitialiseOption() || options.hasInitialiseFromOldOption() || options.hasGenerateTACertificateOption()) {
            ta.persist(ta.createNewTAState(options));
            return new Exit(EXIT_OK);
        }

        return new Exit(EXIT_ERROR_2, ProgramOptions.getUsageString());
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
