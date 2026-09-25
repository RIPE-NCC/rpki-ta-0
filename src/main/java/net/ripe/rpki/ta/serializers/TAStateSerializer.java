package net.ripe.rpki.ta.serializers;



import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.domain.Revocation;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.serializers.legacy.SignedObjectTracker;

import javax.security.auth.x500.X500Principal;

public class TAStateSerializer extends Serializer<TAState> {

    public TAStateSerializer() {
        super(TAState.class, builder -> builder
                .withAliasType("TA", TAState.class)
                .withAliasType("revocation", Revocation.class)
                .withAllowedType(Config.class)
                .withAllowedType(X500Principal.class)
                .withAllowedType(X509Crl.class)
                .withAllowedTypeHierarchy(SignedObjectTracker.class));
    }
}
