package com.aag.admin.crypto;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import javax.crypto.AEADBadTagException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class SecretCipherTest {

    @Autowired
    SecretCipher cipher;

    @Test
    void encrypt_decrypt_roundTrip_returnsOriginalPlaintext() {
        String plaintext = "ak_supersecret_secret_value_43chars_xxxx";
        byte[] encrypted = cipher.encrypt(plaintext);
        String decrypted = cipher.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void encrypt_samePlaintext_producesDifferentCiphertext() {
        String plaintext = "same-input";
        byte[] first = cipher.encrypt(plaintext);
        byte[] second = cipher.encrypt(plaintext);
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void encrypt_outputContainsIvPlusCiphertextPlusTag() {
        // IV(12) + tag(16) = 28 minimum overhead. 평문 1자 → 최소 29 bytes
        byte[] encrypted = cipher.encrypt("a");
        assertThat(encrypted.length).isGreaterThanOrEqualTo(29);
    }

    @Test
    void decrypt_tamperedTag_throwsAeadBadTagException() {
        byte[] encrypted = cipher.encrypt("payload");
        encrypted[encrypted.length - 1] ^= 0x01; // 마지막 바이트(태그 일부) flip
        assertThatThrownBy(() -> cipher.decrypt(encrypted))
                .hasCauseInstanceOf(AEADBadTagException.class);
    }

    @Test
    void encrypt_decrypt_emptyString_roundTrips() {
        byte[] encrypted = cipher.encrypt("");
        assertThat(cipher.decrypt(encrypted)).isEmpty();
    }

    @Test
    void encrypt_decrypt_unicodeKorean_roundTrips() {
        String plaintext = "비밀-한글-입니다-🔒";
        byte[] encrypted = cipher.encrypt(plaintext);
        assertThat(cipher.decrypt(encrypted)).isEqualTo(plaintext);
    }
}
