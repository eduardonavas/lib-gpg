package br.com.navas.shared;

import lombok.SneakyThrows;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.UUID;

public class Util {

    private Util() {
    }

    @SneakyThrows
    public static File generateFileInMemory(byte[] content) throws IOException {
        File file = new File(UUID.randomUUID() + ".asc");
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content);
        }
        return file;
    }
}
