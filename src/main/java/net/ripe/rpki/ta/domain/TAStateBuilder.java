package net.ripe.rpki.ta.domain;


import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.ta.config.Config;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public class TAStateBuilder {

    private final TAState taState;

    public TAStateBuilder(Config config) {
        taState = new TAState();
        taState.setConfig(config);
    }

    public TAStateBuilder withEncoded(byte[] encoded) {
        taState.setEncoded(encoded);
        return this;
    }

    public TAStateBuilder withKeyStoreKeyAlias(String keyStoreKeyAlias) {
        taState.setKeyStoreKeyAlias(keyStoreKeyAlias);
        return this;
    }

    public TAStateBuilder withKeyStorePassphrase(String keyStorePassphrase) {
        taState.setKeyStorePassphrase(keyStorePassphrase);
        return this;
    }

    public TAStateBuilder withLastIssuedCertificateSerial(BigInteger lastIssuedCertificateSerial) {
        taState.setLastIssuedCertificateSerial(lastIssuedCertificateSerial);
        return this;
    }

    public TAStateBuilder withCrl(X509Crl crl) {
        taState.setCrl(crl);
        return this;
    }

    public TAStateBuilder withLastCrlSerial(BigInteger lastCrlSerial) {
        taState.setLastCrlSerial(lastCrlSerial);
        return this;
    }

    public TAStateBuilder withLastMftSerial(BigInteger lastMftSerial) {
        taState.setLastMftSerial(lastMftSerial);
        return this;
    }

    public TAState build() {
        return taState;
    }
}
