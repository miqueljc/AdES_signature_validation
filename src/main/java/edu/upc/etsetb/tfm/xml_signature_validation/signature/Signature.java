/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.util.Date;
import java.util.List;

/**
 *
 * @author mique
 */
public interface Signature {
    public SignedProperties getSignedProperties();
    public UnsignedProperties getUnsignedProperties();
    public String getTarget();
    public String getId();
    public String getSignatureValue();
    public String getSignatureAlgorithm();
    public List<TimeStamp> getAllSignatureTimeStamps();
    public List<SignedDataObject> getAllSignedDataObjects();
    public List<String> getAllDeprecatedAlgorithms();
    public String getFormat();
    public List<EncapsulatedPKIData> getAllObjectsAsReferences();
    
    public void setSignedProperties(SignedProperties signedProperties);
    public void setUnsignedProperties(UnsignedProperties unsignedProperties);
    public void setTarget(String target);
    public void setId(String id);
    public void setSignatureValue(byte[] value);
    public void setSignatureAlgorithm(String signatureAlgorithm);
    public void setFormat(String format);
    public void addDeprectedAlgorithm(String algorithm);
    
    public boolean checkSignatureValue(String signatureValue, String signatureAlgorithm, byte[] publicKeyValue);
    public ProofOfExistence createPOE(Object object, Date date);
    
    
}
