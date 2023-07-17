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
public interface ProofOfExistence {

    public Object getObject();
    public Date getSigningTime();
    public void setObject(Object object);
    public void setSigningTime(Date signingTime);
    
    public boolean isSignaturePOE(Signature signature);
    public void setAsSiganturePOE(Signature signature);
    public boolean isSignerPOEOfCertificate(SignatureCertificate signedCertificate);
    public void setAsSignerPOEOfCertificate(SignatureCertificate signerCertificate, SignatureCertificate signedCertificate);
    
}
