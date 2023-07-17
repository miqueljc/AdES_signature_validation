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
public interface RevocationStatusInformation {
    public DigestAlgorithm getDigestAlgorithm();
    public byte[] getEncoded();
    public Date getIssuanceDate();
    public Date getThisUpdate();
    public Date getNextUpdate();
    public Date getExpiredCertsOnCRL();
    public Date getArchiveCutOff();
    public Date getRevocationDate();
    public String getRevocationReason();
    public SignatureCertificate getSignatureCertificate();
    public List<SignatureCertificate> getCertificatesChain();
    public SignatureCertificate getRevokedCACertificate();
    
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm);
    public void setIssuanceDate(Date date);
    public void setThisUpdate(Date date);
    public void setNextUpdate(Date date);
    public void setExpiredCertsOnCRL(Date date);
    public void setArchiveCutOff(Date date);
    public void setSignatureCertificate(SignatureCertificate signingCertificate);
    public void addCertificateToChain(SignatureCertificate certificate);
    public void setRevokedCACertificate(SignatureCertificate certificate);
    public void setRevocationTime(Date date);
    public void setRevocationReason(String reason);
}
