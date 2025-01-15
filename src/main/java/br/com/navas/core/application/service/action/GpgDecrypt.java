package br.com.navas.core.application.service.action;

import br.com.navas.core.application.service.exception.DecryptException;
import br.com.navas.domain.service.PkObject;
import lombok.SneakyThrows;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Base64;

import static br.com.navas.shared.ConstantsStr.PROVIDER;

@Component
public class GpgDecrypt {

    @SneakyThrows
    public byte[] decrypt(InputStream in, String privateKey, String password){


        in = PGPUtil.getDecoderStream(in);

        var pkObject = extractPrivateKey(privateKey, in, password);

        return  decrypt(pkObject);
    }

    @SneakyThrows
    private byte[] decrypt(PkObject pkObject){

        var plainFact = pkObject.getJcaPGPObjectFactory();
        var pbe = pkObject.getPgpPublicKeyEncryptedData();
        var message = plainFact.nextObject();
        if (message instanceof PGPCompressedData cData) {

            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
            message = pgpFact.nextObject();
        }

        try(var fOut = new ByteArrayOutputStream();){
            if (message instanceof PGPLiteralData ld) {
                try(InputStream unc = ld.getInputStream();){
                    Streams.pipeAll(unc, fOut);
                }
            }
            if (pbe.isIntegrityProtected() && pbe.verify()) {
                return fOut.toByteArray();
            }
            throw new DecryptException("Erro ao decryptorgrafar o conteudo");
        }
    }

    @SneakyThrows
    public PkObject extractPrivateKey(String privateKey, InputStream in, String password)  {
        var keyIn = new ByteArrayInputStream(Base64.getDecoder().decode(privateKey.getBytes()));

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;

        if (pgpF.nextObject() instanceof PGPEncryptedDataList o) {
            enc = o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        var it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        var pgpSec =
                new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            var pgpSecKey = pgpSec.getSecretKey(pbe.getKeyID());
            if(pgpSecKey == null) {
                sKey = null;
            } else {
                sKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(PROVIDER)
                        .build(password.toCharArray()));
            }
        }

        if (pbe != null) {
            try(var clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(PROVIDER).build(sKey));) {

                return PkObject.builder()
                        .pgpPublicKeyEncryptedData(pbe)
                        .jcaPGPObjectFactory(new JcaPGPObjectFactory(clear))
                        .build();
            }

        }
        throw new DecryptException("Chave privada invalida");
    }
}
