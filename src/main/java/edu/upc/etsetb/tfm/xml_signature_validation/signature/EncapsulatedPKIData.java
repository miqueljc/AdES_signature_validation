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
public interface EncapsulatedPKIData {
    public String getId();
    public SignatureCertificate getCertificate();
    public void setId(String id);
    public void setCertificate(SignatureCertificate certificate);
}
