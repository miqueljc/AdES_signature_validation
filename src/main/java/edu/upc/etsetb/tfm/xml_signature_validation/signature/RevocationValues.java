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
public interface RevocationValues {
    public String getId();
    public List<EncapsulatedPKIData> getCRLValues();
    public List<EncapsulatedPKIData> getOCSPValues();
    public List<Object> getOtherCertificateStatusValues();
    
    public void setId(String id);
    public void addCRLValue(EncapsulatedPKIData crlValue);
    public void addOCSPValue(EncapsulatedPKIData ocspValue);
    public void addOtherCertificateStatusValue(Object certificateStatusValue);
}
