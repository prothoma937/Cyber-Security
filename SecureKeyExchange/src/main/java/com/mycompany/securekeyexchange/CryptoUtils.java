/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.securekeyexchange;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


public class CryptoUtils {
    private static final SecureRandom RNG = new SecureRandom();

    // RFC 3526 2048-bit MODP Group (Group 14), generator g = 2
    private static final String P_HEX_2048 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
            "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
            "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
            "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
            "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
            "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

    /** Standard DH params: 2048-bit safe prime p and g=2 */
    public static DHParameterSpec getStandardDHParams() {
        BigInteger p = new BigInteger(P_HEX_2048, 16);
        BigInteger g = BigInteger.valueOf(2);
        return new DHParameterSpec(p, g);
    }

    /** Generate an ephemeral DH key pair */
    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(getStandardDHParams());
        return kpg.generateKeyPair();
    }

    /** Perform DH key agreement to get the shared secret bytes */
    public static byte[] agreeSharedSecret(PrivateKey myPrivate, PublicKey peerPublic) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(myPrivate);
        ka.doPhase(peerPublic, true);
        return ka.generateSecret(); // raw KDF not applied yet
    }

    /**
     * Derive an AES-128 key from the raw shared secret using SHA-256
     * (first 16 bytes). Simple and sufficient for demo; consider HKDF in prod.
     */
    public static SecretKey deriveAESKey(byte[] sharedSecret) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest(sharedSecret);
        byte[] key16 = Arrays.copyOf(digest, 16); // 128-bit
        return new SecretKeySpec(key16, "AES");
    }

    /** AES-GCM encrypt: returns Base64(iv) + ":" + Base64(ciphertext||tag) */
    public static String encryptAESGCM(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; // 96-bit IV recommended for GCM
        RNG.nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ct);
    }

    /** AES-GCM decrypt for "iv:ciphertext" (both Base64) */
    public static String decryptAESGCM(String ivAndCiphertext, SecretKey key) throws Exception {
        String[] parts = ivAndCiphertext.split(":", 2);
        if (parts.length != 2) throw new IllegalArgumentException("Bad payload");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ct = Base64.getDecoder().decode(parts[1]);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
    }

    /** Encode DH public key (X.509 SubjectPublicKeyInfo) */
    public static byte[] encodePublicKey(PublicKey pub) {
        return pub.getEncoded();
    }

    /** Decode DH public key from X.509-encoded bytes */
    public static PublicKey decodeDHPublicKey(byte[] enc) throws Exception {
        X509EncodedKeySpec x = new X509EncodedKeySpec(enc);
        KeyFactory kf = KeyFactory.getInstance("DH");
        return kf.generatePublic(x);
    }

    /** Short fingerprint (first 8 bytes of SHA-256(key)) for display */
    public static String shortKeyFingerprint(SecretKey key) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] fp = md.digest(key.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8 && i < fp.length; i++) sb.append(String.format("%02x", fp[i]));
        return sb.toString();
    }
}
