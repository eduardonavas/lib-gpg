package br.com.navas;

import br.com.navas.core.application.service.action.GpgEncrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GpgEncryptTest {

    @InjectMocks
    private GpgEncrypt gpgEncrypt;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void encryptReturnsEncryptedData() throws IOException, PGPException, NoSuchProviderException {
        String data = "test data";
        String pubKey = Mocks.PUBLIC_KEY;
        boolean armor = true;
        boolean withIntegrityCheck = true;
        assertDoesNotThrow(() -> gpgEncrypt.encrypt(data, pubKey, armor, withIntegrityCheck));

        assertDoesNotThrow(() -> gpgEncrypt.encrypt(data, pubKey, false, withIntegrityCheck));
    }

    @Test
    void encryptThrowsExceptionForInvalidPublicKey() {
        String data = "test data";
        String pubKey = "invalid public key";
        boolean armor = true;
        boolean withIntegrityCheck = true;

        assertThrows(RuntimeException.class, () -> gpgEncrypt.encrypt(data, pubKey, armor, withIntegrityCheck));
    }

    @Test
    void encryptThrowsExceptionForEmptyData() {
        String data = "";
        String pubKey = "public key";
        boolean armor = true;
        boolean withIntegrityCheck = true;

        assertThrows(IllegalArgumentException.class, () -> gpgEncrypt.encrypt(data, pubKey, armor, withIntegrityCheck));
    }
}