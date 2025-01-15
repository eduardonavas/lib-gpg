package br.com.navas.core.application.service.action;

import br.com.navas.core.application.service.exception.EncryptException;
import br.com.navas.shared.Util;
import lombok.SneakyThrows;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Base64;

import static br.com.navas.shared.ConstantsStr.PROVIDER;

@Component
public class GpgEncrypt {

    @SneakyThrows
    public byte[] encrypt(String data, String pubKey, boolean armor, boolean withIntegrityCheck) {

        PGPPublicKey pgpPublicKey = extractPublicKey(pubKey);

        byte[] bytes = generateContentBytes(data);

        var bout = new ByteArrayOutputStream();
        var out = new ArmoredOutputStream(bout);

        encryptData((armor ? out : bout), bytes, pgpPublicKey, withIntegrityCheck);

        out.close();
        bout.close();

        return bout.toByteArray();
    }

    @SneakyThrows
    private void encryptData(OutputStream out, byte [] bytes, PGPPublicKey pgpPublicKey, boolean withIntegrityCheck){
        PGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(9).setProvider(PROVIDER)
                .setSecureRandom(new SecureRandom())
                .setWithIntegrityPacket(withIntegrityCheck);
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider(PROVIDER));
        try(OutputStream cOut = encGen.open(out, bytes.length)) {
            cOut.write(bytes);
        }
    }


    @SneakyThrows
    private byte[] generateContentBytes(String data){
        try(ByteArrayOutputStream bOut = new ByteArrayOutputStream()){
            var fileMemory = Util.generateFileInMemory(data.getBytes());
            PGPUtil.writeFileToLiteralData(bOut, PGPLiteralData.BINARY, fileMemory);
            return bOut.toByteArray();
        }
    }

    @SneakyThrows
    private PGPPublicKey extractPublicKey(String publicKeyFile) {
        var publicKeyInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(publicKeyFile.getBytes()));
        var pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyInputStream), new JcaKeyFingerprintCalculator());
        var keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            var keyRing = keyRingIter.next();
            var keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                var key = keyIter.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new EncryptException("Can't find encryption key in key ring.");
    }
}
