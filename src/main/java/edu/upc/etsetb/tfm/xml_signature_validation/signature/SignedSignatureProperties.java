/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.util.Date;



/**
 *
 * @author mique
 */
public interface SignedSignatureProperties {
    
    public Date getSigningTime();
    public SignatureCertificate getSigningCertificate();
    public SignerDocument getSignerDocument();
    public PolicyIdentifier getPolicyIdentifier();
    public void setSigningTime(Date date);
    public void setSignatureCertificate(SignatureCertificate signatureCertificate);
    public void setSignerDocument(SignerDocument signerDocument);
    public void setPolicyIdentifier(PolicyIdentifier policyIdentifier);
    
}
