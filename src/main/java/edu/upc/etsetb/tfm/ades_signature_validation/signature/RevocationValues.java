/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 *
 * @author mique
 */
public interface RevocationValues {
    public List<RevocationStatusInformation> getCRLValues();
    public List<RevocationStatusInformation> getOCSPValues();
    public RevocationStatusInformation requestRevocationStatusInformationOfCertificate(X509Certificate certificate);
    
    /* Shall return the latest before given date (or the earliest one if does not exist) */
    public RevocationStatusInformation getSavedRevocationStatusInformationOfCertificate(X509Certificate certificate, Date date);
    
    public void addCRLValue(RevocationStatusInformation crlValue);
    public void addOCSPValue(RevocationStatusInformation ocspValue);
}
