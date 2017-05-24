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

import net.ripe.rpki.ta.config.ProgramOptions;
import org.apache.commons.cli.ParseException;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class App {
    public static void main(String[] args) {
        try {
            final ProgramOptions clOptions = new ProgramOptions(args);
            if (clOptions.hasAnyMeaningfulOption()) {
                System.err.println(clOptions.getUsageString());
                System.exit(1);
            }
            if (clOptions.hasInitialise()) {
                initialiseTa(clOptions);
            }
            // TODO Implement other options
        } catch (ParseException e) {
            System.err.println("The following problem occurred: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }

        System.out.println("I am the TA application");
    }

    private static void initialiseTa(ProgramOptions clOptions) {
//        KeyHandlingDetails keyHandlingDetails = new KeyHandlingDetails(options.getKeyPairGeneratorProvider(), keyStoreProvider, keyStoreType, signatureProvider);
//        TrustAnchorDetails trustAnchorDetails = new TrustAnchorDetails(new X500Principal("CN=" + trustAnchorName), URI.create(trustAnchorCertificatePublicationUri), URI.create(trustAnchorProductsPublicationUri));
//
//        createAndStoreTrustAnchor(keyHandlingDetails, trustAnchorDetails);
    }
}
