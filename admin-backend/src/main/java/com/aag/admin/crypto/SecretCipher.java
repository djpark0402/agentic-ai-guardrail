package com.aag.admin.crypto;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

@Component
public class SecretCipher {

    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;          // bytes
    private static final int TAG_LENGTH_BITS = 128;

    private final ResourceLoader resourceLoader;
    private final String keystorePath;
    private final String keystorePassword;
    private final String keyAlias;
    private final SecureRandom random = new SecureRandom();

    private SecretKey masterKey;

    public SecretCipher(ResourceLoader resourceLoader,
                        @Value("${aag.crypto.keystore-path}") String keystorePath,
                        @Value("${aag.crypto.keystore-password}") String keystorePassword,
                        @Value("${aag.crypto.key-alias}") String keyAlias) {
        this.resourceLoader = resourceLoader;
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.keyAlias = keyAlias;
    }

    @PostConstruct
    void loadKeyStore() {
        if (keystorePassword == null || keystorePassword.isEmpty()) {
            throw new IllegalStateException(
                    "AAG_KEYSTORE_PASSWORD is required (set via env or aag.crypto.keystore-password)");
        }
        try {
            Resource resource = resolveResource(keystorePath);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = resource.getInputStream()) {
                ks.load(in, keystorePassword.toCharArray());
            }
            this.masterKey = (SecretKey) ks.getKey(keyAlias, keystorePassword.toCharArray());
            if (this.masterKey == null) {
                throw new IllegalStateException(
                        "Key alias '" + keyAlias + "' not found in keystore " + keystorePath);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load AES master key from keystore: " + keystorePath, ex);
        }
    }

    private Resource resolveResource(String path) {
        if (path.startsWith("classpath:") || path.startsWith("file:")) {
            return resourceLoader.getResource(path);
        }
        return resourceLoader.getResource("file:" + path);
    }

    public byte[] encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[IV_LENGTH + ct.length];
            System.arraycopy(iv, 0, out, 0, IV_LENGTH);
            System.arraycopy(ct, 0, out, IV_LENGTH, ct.length);
            return out;
        } catch (Exception ex) {
            throw new IllegalStateException("AES-GCM encryption failed", ex);
        }
    }

    public String decrypt(byte[] combined) {
        if (combined == null || combined.length <= IV_LENGTH) {
            throw new IllegalArgumentException("encrypted payload too short");
        }
        try {
            byte[] iv = Arrays.copyOfRange(combined, 0, IV_LENGTH);
            byte[] ct = Arrays.copyOfRange(combined, IV_LENGTH, combined.length);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalStateException("AES-GCM decryption failed", ex);
        }
    }
}
