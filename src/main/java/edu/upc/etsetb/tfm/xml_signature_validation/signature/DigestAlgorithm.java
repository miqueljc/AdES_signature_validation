/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.security.PublicKey;

/**
 *
 * @author mique
 */
public class DigestAlgorithm {
    private static DigestAlgorithm digestAlgorithm;
    private PublicKeyContent publicKey;
    
    protected DigestAlgorithm (PublicKeyContent publicKey) {
        this.publicKey = publicKey;
    }
    
    public static DigestAlgorithm getInstance(PublicKeyContent publicKey) {
        digestAlgorithm = new DigestAlgorithm(publicKey);
        return digestAlgorithm;
    }
    
    public byte[] getValue() {
        return this.publicKey.getEncoded();
    }
    public String getAlgorithm() {
        return this.publicKey.getAlgorithm();
    }
    public PublicKey getPublicKey() {
        return this.publicKey;
    }
    
    public void setValue(byte[] value) {
        this.publicKey.setEncoded(value);
    }
    
    public void setAlgorithm(String algorithm) {
        this.publicKey.setAlgorithm(algorithm);
    }
    
    public void setPublicKey(PublicKeyContent publicKey) {
        this.publicKey = publicKey;
    }
    
    public static byte[] StringToByte(String str) {
        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(str.substring(index, index + 2), 16);
            bytes[i] = (byte) j;
        }
        return bytes;
    }
}
