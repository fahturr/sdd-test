package com.sdd.fitness.security;

import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.FileCopyUtils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

@Component
public class SecurityKey {

    private final ResourceLoader resourceLoader;

    private final ClassLoader classLoader = SecurityKey.class.getClassLoader();

    public SecurityKey(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean("key")
    public KeyPair key() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PKCS8EncodedKeySpec keyPrivate = new PKCS8EncodedKeySpec(getPrivateKey());
            PrivateKey privateKey = keyFactory.generatePrivate(keyPrivate);

            X509EncodedKeySpec keyPublic = new X509EncodedKeySpec(getPublicKey());
            PublicKey publicKey = keyFactory.generatePublic(keyPublic);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            return null;
        }
    }

    private byte[] getPrivateKey() throws IOException {
        try {
            String filenamePrivate = "key_private";
            String filenamePublic = "key_public.pub";

            String pathPrivateKeyFile = "key/" + filenamePrivate;
            String pathPublicKeyFile = "key/" + filenamePublic;

            if (!resourceLoader.getResource("classpath:" + pathPrivateKeyFile).exists()) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);

                KeyPair key = generator.generateKeyPair();

                try (FileOutputStream fos = new FileOutputStream("src/main/resources/" + pathPrivateKeyFile)) {
                    byte[] encoded = formatAsPEM(key.getPrivate().getEncoded(), "PRIVATE KEY");

                    fos.write(encoded);
                }

                try (FileOutputStream fos = new FileOutputStream("src/main/resources/" + pathPublicKeyFile)) {
                    byte[] encoded = formatAsPEM(key.getPublic().getEncoded(), "PUBLIC KEY");

                    fos.write(encoded);
                }
            }

            InputStream fileKeyPrivate = classLoader.getResourceAsStream(pathPrivateKeyFile);
            InputStreamReader keyReader = new InputStreamReader(Objects.requireNonNull(fileKeyPrivate));

            String key = FileCopyUtils.copyToString(keyReader);
            key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            return Base64.getDecoder().decode(key);
        } catch (NoSuchAlgorithmException e) {
            return new byte[1];
        }
    }

    private byte[] getPublicKey() throws IOException {
        InputStreamReader keyReader = getResourceFileAsInputStream("key/key_public.pub");

        String key = FileCopyUtils.copyToString(keyReader);
        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        return Base64.getDecoder().decode(key);
    }

    private InputStreamReader getResourceFileAsInputStream(String fileName) {
        ClassLoader classLoader = SecurityKey.class.getClassLoader();
        InputStream is = classLoader.getResourceAsStream(fileName);

        return new InputStreamReader(Objects.requireNonNull(is));
    }

    private byte[] formatAsPEM(byte[] keyBytes, String type) {
        String encoded = "-----BEGIN " + type + "-----\n" +
                Base64.getEncoder().encodeToString(keyBytes) +
                "\n-----END " + type + "-----\n";

        return encoded.getBytes();
    }
}
