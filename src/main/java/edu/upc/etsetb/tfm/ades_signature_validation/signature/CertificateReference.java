/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature;

import java.math.BigInteger;

/**
 *
 * @author mique
 */
public interface CertificateReference {
    
    public String getSerial();
    public boolean[] getIssuer();
    public String getAlgorithm();
    public byte[] getDigest(); // Compare with certificate returned digest
    
}
