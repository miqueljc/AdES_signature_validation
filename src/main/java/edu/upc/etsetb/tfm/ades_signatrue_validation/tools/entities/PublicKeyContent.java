/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signatrue_validation.tools.entities;

import edu.upc.etsetb.tfm.ades_signatrue_validation.tools.entities.DigestAlgorithm;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCERSAPublicKey;

/**
 *
 * @author mique
 */
public class PublicKeyContent implements PublicKey {
    
    private static PublicKeyContent publicKeyContent;
    private String algorithm;
    private byte[] encoded;
    
    protected PublicKeyContent(String algorithm, byte[] encoded) {
        this.algorithm = algorithm;
        this.encoded = encoded;
    }
    
    public static PublicKeyContent getInstance(String algorithm, byte[] encoded) {
        publicKeyContent = new PublicKeyContent(algorithm, encoded);
        return publicKeyContent;
    }
    
    public PublicKeyContent(String publicKeyData) {
        stringToPublicKeyContent(publicKeyData);
    }
    
    public static PublicKeyContent stringToPublicKeyContent(String publicKeyData) {
        PublicKey pk = null;
        try {
            byte[] publicKeyDataBytes = DigestAlgorithm.StringToByte(publicKeyData);
            String oid = SubjectPublicKeyInfo.getInstance(publicKeyDataBytes).getAlgorithmId().getAlgorithm().toString();
            pk = KeyFactory.getInstance(oid, new BouncyCastleProvider()).generatePublic(new X509EncodedKeySpec(publicKeyDataBytes));
            publicKeyContent = new PublicKeyContent(pk.getAlgorithm(), ((JCERSAPublicKey)pk).getModulus().toByteArray());
            
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(PublicKeyContent.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(PublicKeyContent.class.getName()).log(Level.SEVERE, null, ex);
        }
        return publicKeyContent;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] getEncoded() {
        return this.encoded;
    }
    
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
    
    public void setFormat(String format) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    public void setEncoded(byte[] encoded) {
        this.encoded = encoded;
    }
    
}
