/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import org.bouncycastle.asn1.tsp.TSTInfo;

/**
 *
 * @author mique
 */
public interface TimeStamp extends Signature {
    public TSTInfo getTSTInfo();
    public long getDelayMs();
     public SignatureCertificate getTSACertificate();
    
    public void setTSTInfo(TSTInfo tstInfo);
    public void setDelayMs(long delay);
    public void setTSACertificate(SignatureCertificate signatureCertificate);
    
    public boolean hasDelay();
   
    
    
}
