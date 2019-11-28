package net.ripe.rpki.ta.serializers.legacy;


import java.math.BigInteger;

public class TrustAnchorKeyStore {
    private byte[] encoded;

    private String keyStorePassphrase;
    private String keyStoreKeyAlias;


    public byte[] getEncoded() {
        return encoded;
    }

    public String getKeyStorePassphrase() {
        return keyStorePassphrase;
    }

    public String getKeyStoreKeyAlias() {
        return keyStoreKeyAlias;
    }
}
