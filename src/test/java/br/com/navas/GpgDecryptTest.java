package br.com.navas;

import br.com.navas.core.application.service.action.GpgDecrypt;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

class GpgDecryptTest {


    private GpgDecrypt gpgDecrypt = new GpgDecrypt();

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());

    }

    @Test
    void decryptReturnsDecryptedData() throws IOException, PGPException {
        InputStream in = new ByteArrayInputStream(Mocks.ENCRYPTED.getBytes());
        String privateKey = Mocks.PRIVATE_KEY;
        String password = "testando";
        byte[] expected = "test data".getBytes();


        byte[] result = gpgDecrypt.decrypt(in, privateKey, password);

        assertArrayEquals(expected, result);
    }

    @Test
    void decryptThrowsExceptionForInvalidPrivateKey() {
        InputStream in = new ByteArrayInputStream("encrypted data".getBytes());
        String privateKey = "invalid private key";
        String password = "password";

        assertThrows(RuntimeException.class, () -> gpgDecrypt.decrypt(in, privateKey, password));
    }

    @Test
    void decryptThrowsExceptionForEmptyInputStream() {
        InputStream in = new ByteArrayInputStream(new byte[0]);
        String privateKey = Mocks.PRIVATE_KEY;
        String password = "testando";

        assertThrows(NullPointerException.class, () -> gpgDecrypt.decrypt(in, privateKey, password));
    }

    @Test
    @SneakyThrows
    void extractPrivateKeyReturnsPkObject() {
        String privateKey = Mocks.PRIVATE_KEY;
        InputStream input = new ByteArrayInputStream(Mocks.ENCRYPTED.getBytes());
        final InputStream in = PGPUtil.getDecoderStream(input);
        String password = "testando";

        assertDoesNotThrow(() -> gpgDecrypt.extractPrivateKey(privateKey, in, password));


    }

    @Test
    void extractPrivateKeyThrowsExceptionForInvalidPrivateKey() {
        String privateKey = "invalid private key";
        InputStream in = new ByteArrayInputStream("encrypted data".getBytes());
        String password = "password";

        assertThrows(IllegalArgumentException.class, () -> gpgDecrypt.extractPrivateKey(privateKey, in, password));
    }
}