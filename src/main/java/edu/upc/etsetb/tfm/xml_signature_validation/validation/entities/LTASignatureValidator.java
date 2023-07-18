/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.validation.entities;

import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.SubIndication;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.EncapsulatedPKIData;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.EvidenceRecord;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.LocalConfiguration;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.ObjectIdentifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PKIXCertificationPathVerifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PKIXCertificationPathVerifier.PathValidationStatus;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PolicyIdentifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.ProofOfExistence;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PublicKeyContent;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.Signature;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignatureCertificate;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignedDataObject;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignerDocument;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.TimeStamp;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints.ValidationModel;
import java.security.cert.TrustAnchor;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 *
 * @author mique
 */
public class LTASignatureValidator {
    private static LTASignatureValidator timeAvalabilitySignatureValidator;
    private Signature signature;
    private SignerDocument signerDocument;
    private SignatureCertificate signingCertificate;
    private Set<TrustAnchor> trustAnchors;
    private List<ObjectIdentifier> allowableValidationPolicyIds;
    private PolicyIdentifier signatureValidationPolicies;
    private LocalConfiguration localConfiguration;
    private Date validationTime;
    private Date signatureExistence;
    private PKIXCertificationPathVerifier chainPathVerifier;
    private List<EvidenceRecord> evidenceRecords;
    private List<ProofOfExistence> signaturePOEs;
    private Date bestSignatureTime;
    private List<TimeStamp> processedTimeStamps;
    
    
    protected LTASignatureValidator(Signature signature, SignerDocument signerDocument, SignatureCertificate signingCertificate, Set<TrustAnchor> trustAnchors, List<ObjectIdentifier> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, Date signatureExistence, PKIXCertificationPathVerifier chainPathVerifier, List<EvidenceRecord> evidenceRecords) {
        this.signature = signature;
        this.signerDocument = signerDocument;
        this.signingCertificate = signingCertificate;
        this.trustAnchors = trustAnchors;
        this.allowableValidationPolicyIds = allowableValidationPolicyIds;
        this.signatureValidationPolicies = signatureValidationPolicies;
        this.localConfiguration = localConfiguration;
        this.validationTime = validationTime;
        this.signatureExistence = signatureExistence;
        this.chainPathVerifier = chainPathVerifier;
        this.evidenceRecords = evidenceRecords;
        this.signaturePOEs = new ArrayList<>();
        this.bestSignatureTime = new Date();
        this.processedTimeStamps = new ArrayList<>();
    }
    
    public static LTASignatureValidator getInstance(Signature signature, SignerDocument signerDocument, SignatureCertificate signingCertificate, Set<TrustAnchor> trustAnchors, List<ObjectIdentifier> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, Date signatureExistence, PKIXCertificationPathVerifier chainPathVerifier, List<EvidenceRecord> evidenceRecords) {
        timeAvalabilitySignatureValidator = new LTASignatureValidator(signature, signerDocument, signingCertificate, trustAnchors, allowableValidationPolicyIds, signatureValidationPolicies, localConfiguration, validationTime, signatureExistence, chainPathVerifier,evidenceRecords);
        return timeAvalabilitySignatureValidator;
    }
    
    public Indication validate() throws ParseException {
        Indication result;
        Indication ltResult;
        
        /* LT Signature validation */
        LTSignatureValidator ltSignatureValidator = LTSignatureValidator.getInstance(this.signature, this.signerDocument, this.signingCertificate, this.trustAnchors, this.allowableValidationPolicyIds, this.signatureValidationPolicies, this.localConfiguration, this.validationTime, this.signatureExistence, this.chainPathVerifier);
        ltResult = ltSignatureValidator.validate();
        this.signature = ltSignatureValidator.getSignature();
        this.signingCertificate = ltSignatureValidator.getSigningCertificate();
        this.signatureValidationPolicies = ltSignatureValidator.getSignatureValidationPolicies();
        this.validationTime = ltSignatureValidator.getValidationTime();
        this.chainPathVerifier = ltSignatureValidator.getChainPathVerifier();
        

        /* Evidence Record Verification */
        result = verifyEvidenceRecords();

        
        if (ltResult.getValue() == Indication.PASSED) {
            return ltResult;
        } else if ((result.getValue() == Indication.PASSED)
                    && (ltResult.getValue() == Indication.INDETERMINATE)
                    && ((ltResult.getSubIndication() == SubIndication.REVOKED_NO_POE)
                        || (ltResult.getSubIndication() == SubIndication.REVOKED_CA_NO_POE)
                        || (ltResult.getSubIndication() == SubIndication.OUT_OF_BOUNDS_NO_POE)
                        || (ltResult.getSubIndication() == SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE))) {
            /* Add POE for signature at best-signature-time */
            this.signaturePOEs.add(this.signature.createPOE(this.signature, this.bestSignatureTime));
            
        } else {
            return ltResult;
        }
        
        /* Validate Time-Stamp attributes */
        result = validateSignatureTimeStamps();
        
        /* Past signature validation */
        if (result.getValue() == Indication.PASSED) {
            result = pastSignatureValidation(this.signature, this.signingCertificate, ltResult);
        }
                
        if (result.getValue() == Indication.PASSED) {
            /* Signature Acceptance Validation at ealiest existence time */
            setEarliestExistenceTime();
            BasicSignatureValidator basicSignatureValidator = BasicSignatureValidator.getInstance(this.signature, this.signerDocument, this.signingCertificate, this.trustAnchors, this.allowableValidationPolicyIds, this.signatureValidationPolicies, this.localConfiguration, this.validationTime, this.chainPathVerifier);
            result = basicSignatureValidator.validateSignatureAcceptance(this.signatureExistence);
        }

        return result;
    }
    
    private Indication verifyEvidenceRecords() throws ParseException {
        Indication pastSignatureValidationResult;
        Indication timeStampValidationResult;
        TimeStampValidator timeStampValidator;
        
        /* Check if evidence records are not given as input, take them from the signature */
        if (this.evidenceRecords == null) {
            this.evidenceRecords = this.signature.getUnsignedProperties().getEvidenceRecords();
        }
        
        /* Validate Evidence records */
        if (false == this.evidenceRecords.isEmpty()) {
            for (EvidenceRecord evidenceRecord : this.evidenceRecords) {
                if (true == evidenceRecord.isValid()) {
                    /* Extract POEs from the ER */
                    this.signaturePOEs.addAll(extractPOEs(evidenceRecord.getArchiveTimeStamp()));
                    
                    /* Time-Stamp validation */
                    timeStampValidator = TimeStampValidator.getInstance(evidenceRecord.getArchiveTimeStamp(), evidenceRecord.getArchiveTimeStamp().getSignedProperties().getSignedSignatureProperties().getSigningCertificate(), this.signatureValidationPolicies, this.allowableValidationPolicyIds, this.trustAnchors, this.localConfiguration, this.chainPathVerifier);
                    timeStampValidationResult = timeStampValidator.validate();
                    
                    /* Past Certificate Validation of the Time-Stamp of the ER */
                    pastSignatureValidationResult = pastSignatureValidation(evidenceRecord.getArchiveTimeStamp(), evidenceRecord.getArchiveTimeStamp().getTSACertificate(),timeStampValidationResult);
                    if (pastSignatureValidationResult.getValue() != Indication.PASSED) {
                        return pastSignatureValidationResult;
                    } else {
                        this.processedTimeStamps.add(evidenceRecord.getArchiveTimeStamp());
                    }
                }
            }
            
        }
        /* Add a POE for each object in the Signature at the current time */
        for (SignedDataObject signedDataObject : signature.getAllSignedDataObjects()) {
            this.signaturePOEs.add(this.signature.createPOE(signedDataObject, new Date()));
        }
        return Indication.getInstance(Indication.PASSED);
    }
    
    private List<ProofOfExistence> extractPOEs(TimeStamp timeStamp) throws ParseException {
        /* Initialize sets */
        List<EncapsulatedPKIData> setS = timeStamp.getAllObjectsAsReferences();
        
        List<ProofOfExistence> setP = new ArrayList<>();
        
        if (false == setS.isEmpty()){
            for (EncapsulatedPKIData archiveDataObject : setS) {
                if (true == this.signatureValidationPolicies.getCryptographicConstraints().isAlgorithmReliable(PublicKeyContent.stringToPublicKeyContent(archiveDataObject.getCertificate().getEncoded()).getAlgorithm(), timeStamp.getTSTInfo().getGenTime().getDate())) {
                    /* Add a POE for the Archive Data Object at time of Time-Stamp generation */
                    setP.add(this.signature.createPOE(archiveDataObject, timeStamp.getTSTInfo().getGenTime().getDate()));
                }
            }
        }
        return setP;
        
        
    }
    
    private Indication pastCertificateValidation(SignatureCertificate certificate) {
        /* Perform an equivalent of X.509 Certificate Validation without revocation checking and applying Validation Time Sliding process before applying X.509 Validation Constraints */
        /* If no validation time available, take current time */
        if (this.validationTime == null) {
            this.validationTime = new Date();
        }
        
        /* Check for otherCertificates */
        if (true == certificate.getChainOfCertificates().isEmpty()) {
            return Indication.getInstance(Indication.INDETERMINATE,SubIndication.NO_CERTIFICATE_CHAIN_FOUND);
        }
        /* Get path validation model */
        ValidationModel pathValidationModel = this.signatureValidationPolicies.getX509ValidationConstraints().getValidationModel();
        if ((ValidationModel.SHELL_MODEL != pathValidationModel)
            && (ValidationModel.CHAIN_MODEL != pathValidationModel)) {
            pathValidationModel = ValidationModel.CHAIN_MODEL;
        }
        /* Perfom certificates chain path verification */
        PathValidationStatus chainPathVerificationResult;
        chainPathVerificationResult = this.chainPathVerifier.validateChain(certificate.getChainOfCertificates(), this.validationTime, pathValidationModel);
        if (null == chainPathVerificationResult) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE);
        } else switch (chainPathVerificationResult) {
            case VALID -> {

                /* Validation Time Sliding process */
                Indication validationTimeSlidingProcessResult = validationTimeSlidingProcess(certificate.getChainOfCertificates());
                if (validationTimeSlidingProcessResult.getValue() != Indication.PASSED) {
                    return validationTimeSlidingProcessResult;
                }
                
                /* Apply X509 validation constraints to chain */
                if (false == this.signatureValidationPolicies.getX509ValidationConstraints().isChainMatched(certificate.getChainOfCertificates())) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CHAIN_CONSTRAINTS_FAILURE);
                }
                /* Apply cryptographic constraints to chain */
                if (false == this.signatureValidationPolicies.getCryptographicConstraints().isChainMatched(certificate.getChainOfCertificates())) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
                }
                /* Check if signing certificate is in validity range */
                Date signingCertificateValidityTime = this.signatureValidationPolicies.getX509ValidationConstraints().getSigningCertificateValidityRange();
                if ((signingCertificateValidityTime != null)
                        && ((new Date(certificate.getRevocationStatusInformation().getIssuanceDate().getTime() + signingCertificateValidityTime.getTime()))).after(this.validationTime)) {
                    return Indication.getInstance(Indication.PASSED);
                } else {
                    this.signingCertificate.getRevocationStatusInformation().setRevocationTime(new Date(certificate.getRevocationStatusInformation().getIssuanceDate().getTime() + signingCertificateValidityTime.getTime()));
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.OUT_OF_BOUNDS_NO_POE);
                }
            }
            case SIGNING_CERTIFICATE_REVOKED -> {
                return Indication.getInstance(Indication.INDETERMINATE, SubIndication.REVOKED_NO_POE);
            }
            case SIGNING_CERTIFICATE_ON_HOLD -> {
                return Indication.getInstance(Indication.INDETERMINATE, SubIndication.TRY_LATER);
            }
            case INTERMEDIATE_CA_REVOKED -> {
                return Indication.getInstance(Indication.INDETERMINATE, SubIndication.REVOKED_CA_NO_POE);
            }
            default -> {
                return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE);
            }
        }
    }
    
    private Indication validationTimeSlidingProcess(List<SignatureCertificate> chainOfCertificates) {
        boolean certificatePOEFound;
        boolean revocationInfoPOEFound;
        
        /* Set control-time to current time */
        Date controlTime = new Date();
        
        for (SignatureCertificate certificate : chainOfCertificates) {
            if ((certificate.getRevocationStatusInformation() == null)
                || (true == certificate.getRevocationStatusInformation().getIssuanceDate().after(controlTime))) {
                return Indication.getInstance(Indication.INDETERMINATE, SubIndication.NO_POE);
            }
            /* Check that POE of the signature and the revocation status information are before control-time */
            certificatePOEFound = false;
            revocationInfoPOEFound = false;
            for (ProofOfExistence poe : this.signaturePOEs) {
                if ((true == poe.getObject().equals(certificate))
                    && (poe.getSigningTime().before(controlTime))) {
                    certificatePOEFound = true;
                } else if ((true == poe.getObject().equals(certificate.getRevocationStatusInformation()))
                            && (poe.getSigningTime().before(controlTime))) {
                    revocationInfoPOEFound = true;
                } else {
                    /* Do nothing */
                }
            }
            if ((false == certificatePOEFound)
                || (false == revocationInfoPOEFound)) {
                return Indication.getInstance(Indication.INDETERMINATE, SubIndication.NO_POE);
            }
            
            /* Update control-time */
            if (certificate.getRevocationStatusInformation().getRevocationDate() != null) {
                if ((this.signatureValidationPolicies.getX509ValidationConstraints().getValidationModel() == ValidationModel.SHELL_MODEL)
                    || ((this.signatureValidationPolicies.getX509ValidationConstraints().getValidationModel()== ValidationModel.CHAIN_MODEL)
                        && ((true == certificate.getRevocationStatusInformation().getRevocationReason().equals("KEY_COMPROMISED"))
                            || (true == certificate.getRevocationStatusInformation().getRevocationReason().equals("UNKNOWN"))))) {
                    controlTime = certificate.getRevocationStatusInformation().getRevocationDate();
                }
            } else {
                BasicSignatureValidator basicSignatureValidator = BasicSignatureValidator.getInstance(this.signature, null, certificate.getRevocationStatusInformation().getSignatureCertificate(), this.trustAnchors, this.allowableValidationPolicyIds, this.signatureValidationPolicies, this.localConfiguration, this.validationTime, this.chainPathVerifier);
                if (Indication.FAILED == basicSignatureValidator.checkFreshness(certificate, this.signatureValidationPolicies.getX509ValidationConstraints(), controlTime).getValue()) {
                    controlTime = certificate.getRevocationStatusInformation().getIssuanceDate();
                }
            }
            
            /* Apply cryptographic constraints */
            if (false == this.signatureValidationPolicies.getCryptographicConstraints().isAlgorithmReliable(certificate.getSigAlgName(), controlTime)) {
                controlTime = this.signatureValidationPolicies.getCryptographicConstraints().getLastSecureAlgorithmDate(certificate.getSigAlgName());
            }
        }
        this.validationTime = controlTime;
        return Indication.getInstance(Indication.PASSED);
        
    }
    
    private Indication pastSignatureValidation(Signature signature, SignatureCertificate certificate, Indication validationTimeResult) throws ParseException {
        
        /* Past Certificate Validation */
        Indication pastCertificateResult = pastCertificateValidation(certificate);
        if (pastCertificateResult.getValue() != Indication.PASSED) {
            return pastCertificateResult;
        }
        /* Check if there is a POE of the Signature value at or before validation time */
        boolean isSignaturePOEFound = false;
        
        for (ProofOfExistence poe : this.signaturePOEs) {
            if (true == poe.isSignaturePOE(signature)) {
                if (this.validationTime.after(poe.getSigningTime())) {
                    isSignaturePOEFound = true;
                    /* Update best-signature-time */
                    if (this.bestSignatureTime.after(poe.getSigningTime())) {
                        this.bestSignatureTime = poe.getSigningTime();
                    }
                }
            }
        }
        if ((validationTimeResult.getValue() == Indication.INDETERMINATE)
            && (true == isSignaturePOEFound)) {
            switch(validationTimeResult.getSubIndication()) {
                case SubIndication.REVOKED_NO_POE:
                    return Indication.getInstance(Indication.PASSED);
                case SubIndication.REVOKED_CA_NO_POE:
                    /* Check if the Signer Certificate of the revoked CA is signer at or before the revocation time of the CA certificate */
                    for (ProofOfExistence poe : this.signaturePOEs) {
                        if (true == poe.isSignerPOEOfCertificate(this.signingCertificate.getRevocationStatusInformation().getRevokedCACertificate())) {
                            if (true == this.signingCertificate.getRevocationStatusInformation().getRevokedCACertificate().getRevocationStatusInformation().getRevocationDate().after(poe.getSigningTime())) {
                                return Indication.getInstance(Indication.PASSED);
                            }
                        }
                    }
                    break;
                case SubIndication.OUT_OF_BOUNDS_NO_POE:
                    /* Check if best-signature-time is before issuance time of the Signing Certificate */
                    if (true == this.bestSignatureTime.before(this.signingCertificate.getRevocationStatusInformation().getIssuanceDate())) {
                        return Indication.getInstance(Indication.INDETERMINATE, SubIndication.NOT_YET_VALID);
                    } else if (true == this.bestSignatureTime.before(this.signingCertificate.getRevocationStatusInformation().getRevocationDate())) {
                        return Indication.getInstance(Indication.PASSED);
                    } else {
                        /* Do nothing */
                    }
            }
        }
            
        if ((validationTimeResult.getValue() == Indication.INDETERMINATE)
            && (validationTimeResult.getSubIndication() == SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE)) {
            for (String algorithm : signature.getAllDeprecatedAlgorithms()) {
                for (ProofOfExistence poe : this.signaturePOEs) {
                    try {
                        if (true == (PublicKeyContent.stringToPublicKeyContent(((SignedDataObject)poe.getObject()).getEncoding()).getAlgorithm().equals(algorithm))
                             && (poe.getSigningTime().before(this.signatureValidationPolicies.getCryptographicConstraints().getLastSecureAlgorithmDate(algorithm)))) {
                            return Indication.getInstance(Indication.PASSED);
                        }

                    } catch (Exception e) {
                        /* Ignore poe */
                    }
                    
                }
            }
        }
        return validationTimeResult;
    }
    
    private void setEarliestExistenceTime() {
        for (ProofOfExistence poe : this.signaturePOEs) {
            if (true == poe.isSignaturePOE(this.signature)) {
                if (this.validationTime.after(poe.getSigningTime())) {
                    /* Update earliest time */
                    if (true == this.signatureExistence.after(poe.getSigningTime())) {
                        this.signatureExistence = poe.getSigningTime();
                    }
                }
            }
        }
    }
    
    private Indication validateSignatureTimeStamps() throws ParseException {
        TimeStampValidator timeStampValidator;
        Indication timeStampValidationResult;
        
        /* Validate all unprocessed time-stamps */
        for (TimeStamp timeStamp : this.signature.getAllSignatureTimeStamps()) {
            if (this.processedTimeStamps.contains(timeStamp)){
                continue;
            }
            timeStampValidator = TimeStampValidator.getInstance(timeStamp, timeStamp.getSignedProperties().getSignedSignatureProperties().getSigningCertificate(), this.signatureValidationPolicies, this.allowableValidationPolicyIds, this.trustAnchors, this.localConfiguration, this.chainPathVerifier);
            timeStampValidationResult = timeStampValidator.validate();
            if ((timeStampValidationResult.getValue() == Indication.PASSED)
                && (true == this.signatureValidationPolicies.getCryptographicConstraints().isAlgorithmReliable(timeStamp.getSignatureAlgorithm(), timeStamp.getTSTInfo().getGenTime().getDate()))) {
                this.signaturePOEs.addAll(extractPOEs(timeStamp));
            } else if ((timeStampValidationResult.getValue() == Indication.INDETERMINATE)
                        && ((timeStampValidationResult.getSubIndication() == SubIndication.REVOKED_NO_POE)
                            || (timeStampValidationResult.getSubIndication() == SubIndication.REVOKED_CA_NO_POE)
                            || (timeStampValidationResult.getSubIndication() == SubIndication.OUT_OF_BOUNDS_NO_POE)
                            || (timeStampValidationResult.getSubIndication() == SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE))) {
                if ((pastSignatureValidation(timeStamp, timeStamp.getTSACertificate(), timeStampValidationResult).getValue() == Indication.PASSED)
                    && (true == this.signatureValidationPolicies.getCryptographicConstraints().isAlgorithmReliable(timeStamp.getSignatureAlgorithm(), timeStamp.getTSTInfo().getGenTime().getDate()))) {
                    this.signaturePOEs.addAll(extractPOEs(timeStamp));
                    this.processedTimeStamps.add(timeStamp);
                }
            } else if (true == this.signatureValidationPolicies.getSignatureElementConstraints().isAttributeValidationNeeded(timeStamp)) {
                return timeStampValidationResult;
            } else{
                /* Do nothing */
            }
        }
        return Indication.getInstance(Indication.PASSED);
    }
}
