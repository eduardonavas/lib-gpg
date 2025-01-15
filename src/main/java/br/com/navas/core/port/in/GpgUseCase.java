package br.com.navas.core.port.in;

import java.io.InputStream;

public interface GpgUseCase {

    byte[] encrypt(String data, String pubKey, boolean armor, boolean withIntegrityCheck);
    byte[] decrypt(InputStream in, String privateKey, String password);

    byte[] decrypt(String in, String privateKey, String password);
}
