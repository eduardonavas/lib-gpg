package br.com.navas;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Configuration
@ComponentScan("br.com.navas.*")
public class Config {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {

    }
}
