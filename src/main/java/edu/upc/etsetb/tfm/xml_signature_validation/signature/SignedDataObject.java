/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

/**
 *
 * @author mique
 */
public interface SignedDataObject {
    ObjectIdentifier getObjectIdentifier();
    String getDescription();
    String getEncoding();
    String getMimeType();
    void setObjectIdentifier(ObjectIdentifier objectIdentifier);
    void setDescription(String description);
    void setEncoding(String encoding);
    void setMimeType(String mimeType);
    void setReference(String reference);
    
    boolean checkIntegrity();
}
