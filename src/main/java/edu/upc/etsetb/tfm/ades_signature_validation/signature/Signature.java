/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;

/**
 *
 * @author mique
 */
public interface Signature {
   
    public String getId();
    public String getSignatureValue();
    public String getSignatureAlgorithm();
    //public List<Reference> getReferences(); /* Already implemented in validating signature value */
    public String getCanonicalizationMethod();
    public String getFormat();
    
    /* Signed Signature properties */
    public Date getSigningTime();
    public SignatureCertificates getCertificateReferences(); /* From SigningCertificateV2 field */
    public List<X509Certificate> getX509DataCertificates(); /* From KeyInfo/X509Data */
    public PolicyIdentifier getPolicyIdentifier();
    
    /* signed data objects properties */
    public List<SignedDataObject> getSignedDataObjects();
    public List<CommitmentTypeIndication> getCommitmentTypeIndications();
    public List<TimeStamp> getAllDataObjectsTimestamps();
    public List<TimeStamp> getIndividualDataObjectsTimeStamps();
    
    /* unsigned properties */
    public List<TimeStamp> getSignatureTimeStamps();
    public List<TimeStamp> getArchiveTimeStamps();
    public RevocationValues getRevocationValues();
    public List<X509Certificate> getCertificateValues(); /* From CertificateValues field */
    public List<EvidenceRecord> getEvidenceRecords();    
    
    public List<TimeStamp> getAllSignatureTimeStamps();
    public List<String> getAllDeprecatedAlgorithms();
    public void addDeprecatedAlgorithm(String algorithm);
    
    public void setCertificatesChain(List<X509Certificate> chain);
    public List<X509Certificate> getCertificatesChain();
    
    public Map<X509Certificate,Date> getRevockedCertificates();
    public void addRevockedCerticate(X509Certificate certificate, Date revocationDate);
    
    
    public boolean verifyReferences();
    public boolean verifySignatureValue(); //xmldisg on java 8 for details
    public boolean verifyDigest(byte[] value, byte[] digest, String algorithm);
    public ProofOfExistence createPOE(Object object, Date date);
    
    
}
