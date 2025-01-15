package br.com.navas.domain.service;

import lombok.Builder;
import lombok.Data;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;

@Data
@Builder
public class PkObject {

    private JcaPGPObjectFactory jcaPGPObjectFactory;
    private PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData;
}
