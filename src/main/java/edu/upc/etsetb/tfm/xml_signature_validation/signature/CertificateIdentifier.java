/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.math.BigInteger;

/**
 *
 * @author mique
 */
public interface CertificateIdentifier {
    
    public boolean[] getIssuer();
    public BigInteger getSerial();
    public DigestAlgorithm getDigestAlgorithm();
    public void setIssuer(boolean[] issuer);
    public void setSerial(BigInteger serial);
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm);
}
