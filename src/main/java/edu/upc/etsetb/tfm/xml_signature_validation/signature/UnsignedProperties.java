/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.util.List;
import java.util.Map;

/**
 *
 * @author mique
 */
public interface UnsignedProperties {
    public List<TimeStamp> getSignatureTimeStamps();
    public List<TimeStamp> getArchiveTimeStamps();
    public RevocationValues getRevocationValues();
    public List<SignatureCertificate> getCertificateValues();
    public List<EvidenceRecord> getEvidenceRecords();
    public void addSignatureTimeStamp(TimeStamp timestamp);
    public void addArchiveTimeStamp(TimeStamp timestamp);
    public void addRevocationValues(RevocationValues revocationValues);
    public void addCertificateValue(SignatureCertificate certificate);
    public void addEvidenceRecord(EvidenceRecord evidenceRecord);
}
