package net.ripe.rpki.ta;

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

import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.config.ProgramOptions;

import java.io.FileOutputStream;

public class Main {

    private static int EXIT_OK = 0;
    private static int EXIT_ERROR_1 = 1;
    private static int EXIT_ERROR_2 = 2;

    public static void main(String[] args) {
        System.exit(run(args));
    }

    public static int run(final String[] args) {
        try {
            final ProgramOptions options = new ProgramOptions(args);
            final String errorMessage = options.checkValidOptionSet();
            if (errorMessage != null) {
                System.err.println(errorMessage);
                System.err.println(options.getUsageString());
                return EXIT_ERROR_1;
            }

            final Config config = Env.config(options.getEnv());
            final TA ta = new TA(config);

            if (options.hasPrintCertificateOption()) {
                new FileOutputStream(options.getPrintCertificateFileName()).write(ta.getCertificateDER());
                return EXIT_OK;
            }

            ta.persist(ta.createNewTAState(options));

            return EXIT_OK;

        } catch (Exception e) {
            System.err.println("The following problem occurred: " +
                    e.getMessage() +
                    "\n");
            e.printStackTrace(System.err);

            return EXIT_ERROR_2;
        }
    }

}
