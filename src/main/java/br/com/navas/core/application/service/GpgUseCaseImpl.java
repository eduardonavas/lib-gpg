package br.com.navas.core.application.service;

import br.com.navas.core.application.service.action.GpgDecrypt;
import br.com.navas.core.application.service.action.GpgEncrypt;
import br.com.navas.core.port.in.GpgUseCase;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

@Service
@RequiredArgsConstructor
public class GpgUseCaseImpl implements GpgUseCase {

    private final GpgDecrypt gpgDecrypt;
    private final GpgEncrypt gpgEncrypt;

    @Override
    public byte[] encrypt(String data, String pubKey, boolean armor, boolean withIntegrityCheck) {
        return gpgEncrypt.encrypt(data, pubKey, armor, withIntegrityCheck);
    }

    @Override
    public byte[] decrypt(InputStream in, String privateKey, String password) {
        return gpgDecrypt.decrypt(in, privateKey, password);
    }

    @Override
    @SneakyThrows
    public byte[] decrypt(String data, String privateKey, String password) {
        var in = new ByteArrayInputStream(data.getBytes());

        return gpgDecrypt.decrypt(in, privateKey, password);
    }
}
