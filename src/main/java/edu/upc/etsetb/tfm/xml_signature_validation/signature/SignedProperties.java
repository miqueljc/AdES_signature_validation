/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.util.List;

/**
 *
 * @author mique
 */
public interface SignedProperties {
    public Signature getSigningSignature();
    public SignedSignatureProperties getSignedSignatureProperties();
    public SignedDataObjectProperties getSignedDataObjectProperties();
    
    public void setSignedSignatureProperties(SignedSignatureProperties signedSignatureProperties);
    public void getSignedDataObject(SignedDataObjectProperties signedDataObjectProperties);
    
}
