/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.math.BigInteger;
import java.security.Principal;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 *
 * @author mique
 */
public interface SignatureCertificate {    
    public List<SignatureCertificate> getChainOfCertificates();
    public RevocationStatusInformation getRevocationStatusInformation();
    public DigestAlgorithm getSignersCertificateDigest();
    public List<DigestAlgorithm> getCertificatesDigests();
    public CertificateIdentifier getSelfCertificateIdentifier();
    public SignatureCertificate getSignerCertificate(SignerDocument signerDocument);
    public List<SignatureCertificate> getOtherCertificates();
    public CertificateIdentifier getOtherCertificateIdentifierFromIndex(int index);
    public boolean applyDigest(String digest, String algorithmName);
    public void checkValidity();
    public void checkValidity(Date date);
    public int getVersion();
    public BigInteger getSerialNumber();
    public Principal getIssuerDN();
    public Principal getSubjectDN();
    public Date getNotBefore();
    public Date getNotAfter();
    public byte[] getTBSCertificate();
    public byte[] getSignature();
    public String getSigAlgName();
    public String getSigAlgOID();
    public byte[] getSigAlgParams();
    public boolean[] getIssuerUniqueID();
    public boolean[] getSubjectUniqueID();
    public boolean[] getKeyUsage();
    public int getBasicConstraints();
    public String getEncoded();
    public void verify(PublicKey key);
    public void verify(PublicKey key, String sigProvider);
    public PublicKey getPublicKey();
    public boolean hasUnsupportedCriticalExtension();
    public Set<String> getCriticalExtensionOIDs();
    public Set<String> getNonCriticalExtensionOIDs();
    public byte[] getExtensionValue(String oid);
    
//    public List<DigestAlgorithm> getCertificatesDigests() {
//        if (this.otherCertificates.size() > 0) {
//            List<DigestAlgorithm> digests = null;
//            for (SignatureCertificate certificate : otherCertificates) {
//                digests.add(certificate.getSelfCertificateIdentifier().getDigestAlgorithm());
//            }
//            return digests;
//        } else {
//            return null;
//        }
//    }
    
    
//    public List<SignatureCertificate> getOtherCertificates() {
//        return this.otherCertificates;
//    }
//    
//    public CertificateIdentifier getOtherCertificateIdentifierFromIndex(int index) {
//        return otherCertificates.get(index).getSelfCertificateIdentifier();
//    }
//    
//    public CertificateIdentifier getSelfCertificateIdentifier() {
//        return this.certificateId;
//    }
//    
//    public void setSelfCertificateIdentifier(CertificateIdentifier certificateId) {
//        this.certificateId = certificateId;
//    }
//    
//    public void addOtherCertificate(SignatureCertificate otherSignatureCertificate) {
//        this.otherCertificates.add(otherSignatureCertificate);
//    }
//    
//    @Override
//    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public int getVersion() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public BigInteger getSerialNumber() {
//        return this.certificateId.getSerial();
//    }
//
//    @Override
//    public Principal getIssuerDN() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public Principal getSubjectDN() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public Date getNotBefore() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public Date getNotAfter() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public byte[] getTBSCertificate() throws CertificateEncodingException {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public byte[] getSignature() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public String getSigAlgName() {
//        return this.certificateId.getDigestAlgorithm().getPublicKey().getAlgorithm();
//    }
//
//    @Override
//    public String getSigAlgOID() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public byte[] getSigAlgParams() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public boolean[] getIssuerUniqueID() {
//        return this.certificateId.getIssuer();
//    }
//
//    @Override
//    public boolean[] getSubjectUniqueID() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public boolean[] getKeyUsage() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public int getBasicConstraints() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public byte[] getEncoded() throws CertificateEncodingException {
//        return this.certificateId.getDigestAlgorithm().getValue();
//    }
//
//    @Override
//    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public String toString() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public PublicKey getPublicKey() {
//        return this.certificateId.getDigestAlgorithm().getPublicKey();
//    }
//
//    @Override
//    public boolean hasUnsupportedCriticalExtension() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public Set<String> getCriticalExtensionOIDs() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public Set<String> getNonCriticalExtensionOIDs() {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }
//
//    @Override
//    public byte[] getExtensionValue(String oid) {
//        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
//    }

    
    
}
