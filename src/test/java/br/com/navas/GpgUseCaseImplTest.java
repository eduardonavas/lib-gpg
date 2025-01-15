package br.com.navas;

import br.com.navas.core.application.service.GpgUseCaseImpl;
import br.com.navas.core.application.service.action.GpgDecrypt;
import br.com.navas.core.application.service.action.GpgEncrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class GpgUseCaseImplTest {

    private GpgUseCaseImpl gpgUseCaseImpl = new GpgUseCaseImpl(new GpgDecrypt(), new GpgEncrypt());

    @BeforeEach
    void setUp() {

        Security.addProvider(new BouncyCastleProvider());
    }


    @Test
    void encryptReturnsEncryptedData() {
        String data = "test data";
        String pubKey = Mocks.PUBLIC_KEY;
        boolean armor = true;
        boolean withIntegrityCheck = true;

        var result = new String(gpgUseCaseImpl.encrypt(data, pubKey, armor, withIntegrityCheck));
        assertTrue( result.startsWith("-----BEGIN PGP MESSAGE-----"));
        assertTrue(result.contains("-----END PGP MESSAGE-----"));
    }

    @Test
    void decryptReturnsDecryptedData() {
        InputStream in = new ByteArrayInputStream(Mocks.ENCRYPTED.getBytes());
        String privateKey = Mocks.PRIVATE_KEY;
        String password = "testando";
        byte[] expected = "test data".getBytes();
        byte[] result = gpgUseCaseImpl.decrypt(in, privateKey, password);

        assertArrayEquals(expected, result);
        assertArrayEquals(expected, gpgUseCaseImpl.decrypt(Mocks.ENCRYPTED, privateKey, password));
        String nula = null;
        assertThrows(Exception.class, () -> gpgUseCaseImpl.decrypt(nula, privateKey, password));
    }
}