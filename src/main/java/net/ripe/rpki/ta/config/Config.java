package net.ripe.rpki.ta.config;

import javax.security.auth.x500.X500Principal;

public class Config {
    public final String signatureProvider;
    public X500Principal trustAnchorName;

    public Config(String signatureProvider) {
        this.signatureProvider = signatureProvider;
    }
}
