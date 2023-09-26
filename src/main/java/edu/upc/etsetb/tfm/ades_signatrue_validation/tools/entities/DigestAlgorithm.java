/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signatrue_validation.tools.entities;

/**
 *
 * @author mique
 */
public abstract class DigestAlgorithm {
    
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
