/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.validation.entities;

import edu.upc.etsetb.tfm.xml_signature_validation.signature.DigestAlgorithm;
import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.SubIndication;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.EncapsulatedPKIData;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.LocalConfiguration;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.ObjectIdentifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PKIXCertificationPathVerifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PKIXCertificationPathVerifier.PathValidationStatus;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PolicyIdentifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.Signature;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignatureCertificate;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignedDataObject;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignerDocument;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.TimeStamp;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints.ValidationModel;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 *
 * @author mique
 */
public class BasicSignatureValidator {
    
    private static BasicSignatureValidator basicSignatureValidation;
    private Signature signature;
    private SignerDocument signerDocument;
    private SignatureCertificate signingCertificate;
    private Set<TrustAnchor> trustAnchors;
    private List<ObjectIdentifier> allowableValidationPolicyIds;
    private PolicyIdentifier signatureValidationPolicies;
    private LocalConfiguration localConfiguration;
    private Date validationTime;
    private PKIXCertificationPathVerifier chainPathVerifier;

    
    protected BasicSignatureValidator(Signature signature, SignerDocument signerDocument, SignatureCertificate signingCertificate, Set<TrustAnchor> trustAnchors, List<ObjectIdentifier> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, PKIXCertificationPathVerifier chainPathVerifier) {
        this.signature = signature;
        this.signerDocument = signerDocument;
        this.signingCertificate = signingCertificate;
        this.trustAnchors = trustAnchors;
        this.allowableValidationPolicyIds = allowableValidationPolicyIds;
        this.signatureValidationPolicies = signatureValidationPolicies;
        this.localConfiguration = localConfiguration;
        this.validationTime = validationTime;
        this.chainPathVerifier = chainPathVerifier;
    }

    public static BasicSignatureValidator getInstance(Signature signature, SignerDocument signerDocument, SignatureCertificate signingCertificate, Set<TrustAnchor> trustAnchors, List<ObjectIdentifier> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, PKIXCertificationPathVerifier chainPathVerifier) {
        basicSignatureValidation = new BasicSignatureValidator(signature, signerDocument, signingCertificate, trustAnchors, allowableValidationPolicyIds, signatureValidationPolicies, localConfiguration, validationTime, chainPathVerifier);
        return basicSignatureValidation;
    }
    
    
    public Indication validate(boolean isSignatureWithTime) {
        Indication result;
        Indication signatureWithTimeResult = null;
        /* STEP 1: Format checking */
        
        
        /* STEP 2: Identification of the Signing Certificate */
        result = identifySigningCertificate();
        
        /* STEP 3: Validation Context Initialization */
        if (Indication.PASSED == result.getValue()) {
            result = initializeValidationContext();
        }
        
        /* STEP 4: X509 Certificate Validation */
        if (Indication.PASSED == result.getValue()) {
            result = validateX509Certificate();
        }
            
        /* STEP 5: Cryptographic Verification */
        if (Indication.PASSED == result.getValue()) {
            result = cryptographicVerification();
        } else if ((true == isSignatureWithTime)
                    && (result.getValue() == Indication.INDETERMINATE)
                    && ((result.getSubIndication() == SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE)
                        || (result.getSubIndication() == SubIndication.REVOKED_NO_POE)
                        || (result.getSubIndication() == SubIndication.REVOKED_CA_NO_POE)
                        || (result.getSubIndication() == SubIndication.TRY_LATER)
                        || (result.getSubIndication() == SubIndication.OUT_OF_BOUNDS_NO_POE))) {
            signatureWithTimeResult = Indication.getInstance(result.getValue(), result.getSubIndication());
            result = cryptographicVerification();
        } else {
            /* Do nothing */
        }
            
        /* STEP 6: Signature Acceptance Validation */
        if (Indication.PASSED == result.getValue()) {
            result = validateSignatureAcceptance(this.validationTime);
        }
        
        /* Return Basic Signature Validation or Signature With Time result */
        if ((signatureWithTimeResult != null)
            && ((result.getValue() == Indication.PASSED)
                || ((result.getValue() == Indication.INDETERMINATE)
                    && (result.getSubIndication() == SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE)))) {
            return signatureWithTimeResult;
        } else {
            return result;
        }
        
        
    }
    
    public Indication identifySigningCertificate() {
        /* If signing certificate is not provided, obtain certificate from signature */
        if (this.signingCertificate == null) {
            if (this.signature.getSignedProperties().getSignedSignatureProperties().getSigningCertificate() != null) {
                this.signingCertificate = this.signature.getSignedProperties().getSignedSignatureProperties().getSigningCertificate();
            } else {
                return Indication.getInstance(Indication.INDETERMINATE,SubIndication.NO_SIGNING_CERTIFICATE_FOUND);
            }
        }
        /* If signer's certificate reference is identified, use the signer's certificate digest */
        if (this.signingCertificate.getSignerCertificate(this.signerDocument) != null) {
            if (true == this.signingCertificate.applyDigest(this.signingCertificate.getSignerCertificate(this.signerDocument).getEncoded(), this.signature.getSignatureAlgorithm())) {
                return Indication.getInstance(Indication.PASSED);
            }
        }
        
        /* Otherwise use other referenced certificate's digest */
        List<SignatureCertificate> otherCertificates = new ArrayList<>();
        if (false == this.signingCertificate.getOtherCertificates().isEmpty()){
            otherCertificates.addAll(this.signingCertificate.getOtherCertificates());
            /* Compare computed digest with each of the list until one matches */
            for (SignatureCertificate referencedCertificate : otherCertificates) {
                if (true == this.signingCertificate.applyDigest(referencedCertificate.getEncoded(), referencedCertificate.getSigAlgName())) {
                    /* Check Issuer and Serial Number if exists */
                    if (((referencedCertificate.getIssuerUniqueID() != null)
                            && (false == Arrays.equals(this.signingCertificate.getIssuerUniqueID(), referencedCertificate.getIssuerUniqueID())))
                        || ((referencedCertificate.getSerialNumber() != null)
                            && (false == (this.signingCertificate.getSerialNumber().equals(referencedCertificate.getSerialNumber()))))) {
                        return Indication.getInstance(Indication.INDETERMINATE,SubIndication.INVALID_ISSUER_SERIAL);
                    } else {
                        return Indication.getInstance(Indication.PASSED);
                    }
                }
            }
        }
        return Indication.getInstance(Indication.INDETERMINATE,SubIndication.NO_SIGNING_CERTIFICATE_FOUND);
    }
    
    private Indication initializeValidationContext() {
        
        /* If no validation policy is provided as input, use default policy */
        if ((this.signatureValidationPolicies == null) || (this.signatureValidationPolicies.getId() == null) || (this.signatureValidationPolicies.getHash() == null)){
            this.signatureValidationPolicies = this.localConfiguration.getDefaultPolicyIdentifier();
        } else {
            boolean isPolicyAllowed = false;
            for (ObjectIdentifier id: this.allowableValidationPolicyIds) {
                /* If the given policy is not in the list of allowable policies, use default policy */
                if ((this.signatureValidationPolicies.getId().getIdentifier() != null)
                    && (id.getIdentifier() != null)
                    && (this.signatureValidationPolicies.getId().getIdentifier().equals(id.getIdentifier()))) {
                    isPolicyAllowed = true;
                    break;
                }
            }
            if (isPolicyAllowed == false) {
                this.signatureValidationPolicies = this.localConfiguration.getDefaultPolicyIdentifier();
            }
        }
        /* Get Policy document of the chosen policy */
        if (false == this.signatureValidationPolicies.getSignaturePolicyDocument()) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE);
        /* Parse the document to obtain the chosen policy constraints */
        } else if (false == this.signatureValidationPolicies.parseSignaturePolicyDocument()) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.POLICY_PROCESSING_ERROR);
        /* Compute digest of the policy document using the transformations in the signature attributes */
        } else if (false == Base64.getEncoder().encodeToString(this.signatureValidationPolicies.getHash().getValue()).equals(this.signatureValidationPolicies.applySignatureTransforms(this.signature))) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.POLICY_PROCESSING_ERROR);
        } else {
            this.signatureValidationPolicies.setContraints();
            return Indication.getInstance(Indication.PASSED); 
        }
        
    }
    
    public Indication checkFreshness(SignatureCertificate certificate, X509ValidationConstraints constraints, Date validationTime) {
        
        if ((constraints.getMaximumAcceptedRevocationFreshness() != null)
            && (certificate.getRevocationStatusInformation().getIssuanceDate() != null)) {
            /* Get maximum accepted time */
            Date maximumAcceptedTime = new Date(validationTime.getTime() - constraints.getMaximumAcceptedRevocationFreshness().getTime());
            if (certificate.getRevocationStatusInformation().getIssuanceDate().after(maximumAcceptedTime)) {
                /* Issuance time after maximum accepted time */
                return Indication.getInstance(Indication.PASSED);
            } else {
                /* Issuance time before maximum accepted time */
                certificate.getRevocationStatusInformation().setRevocationTime(new Date(maximumAcceptedTime.getTime()));
                this.signingCertificate.getRevocationStatusInformation().setRevokedCACertificate(certificate);
                return Indication.getInstance(Indication.FAILED);
            }
        } else if ((constraints.getMaximumAcceptedRevocationFreshness() == null)
                && (certificate.getRevocationStatusInformation().getIssuanceDate() != null)
                && (certificate.getRevocationStatusInformation().getNextUpdate() != null)
                && (certificate.getRevocationStatusInformation().getThisUpdate() != null)) {
            /* Get interval between thisUpdate and nextUpdate */
            Date intervalTime = new Date(certificate.getRevocationStatusInformation().getNextUpdate().getTime() - certificate.getRevocationStatusInformation().getThisUpdate().getTime());
            /* Get maximum accepted time */
            Date maximumAcceptedTime = new Date(validationTime.getTime() - intervalTime.getTime());
            if (certificate.getRevocationStatusInformation().getIssuanceDate().after(maximumAcceptedTime)) {
                /* Issuance time after maximum accepted time */
                return Indication.getInstance(Indication.PASSED);
            } else {
                /* Issuance time before maximum accepted time */
                certificate.getRevocationStatusInformation().setRevocationTime(new Date(maximumAcceptedTime.getTime()));
                this.signingCertificate.getRevocationStatusInformation().setRevokedCACertificate(certificate);
                return Indication.getInstance(Indication.FAILED);
            }
        } else {
            certificate.getRevocationStatusInformation().setRevocationTime(new Date());
            this.signingCertificate.getRevocationStatusInformation().setRevokedCACertificate(certificate);
            return Indication.getInstance(Indication.FAILED);
        }
    }
    
    private Indication validateX509Certificate() {
        /* If no validation time available, take current time */
        if (this.validationTime == null) {
            this.validationTime = new Date();
        }
        
        /* Check for otherCertificates */
        if (true == this.signingCertificate.getChainOfCertificates().isEmpty()) {
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
        chainPathVerificationResult = this.chainPathVerifier.validateChain(this.signingCertificate.getChainOfCertificates(), this.validationTime, pathValidationModel);
        if (null == chainPathVerificationResult) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE);
        } else switch (chainPathVerificationResult) {
            case VALID -> {
                /* Perfom freshnees check for all certificates in the chain */
                Indication freshnessResult;
                for (SignatureCertificate certificate : this.signingCertificate.getChainOfCertificates()) {
                    freshnessResult = checkFreshness(certificate, this.signatureValidationPolicies.getX509ValidationConstraints(), this.validationTime);
                    if (Indication.FAILED == freshnessResult.getValue()) {
                        return Indication.getInstance(Indication.INDETERMINATE, SubIndication.TRY_LATER);
                    }
                }
                /* Apply X509 validation constraints to chain */
                if (false == this.signatureValidationPolicies.getX509ValidationConstraints().isChainMatched(this.signingCertificate.getChainOfCertificates())) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CHAIN_CONSTRAINTS_FAILURE);
                }
                /* Apply cryptographic constraints to chain */
                if (false == this.signatureValidationPolicies.getCryptographicConstraints().isChainMatched(this.signingCertificate.getChainOfCertificates())) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
                }
                /* Check if signing certificate is in validity range */
                Date signingCertificateValidityTime = this.signatureValidationPolicies.getX509ValidationConstraints().getSigningCertificateValidityRange();
                if (true == ((new Date(this.signingCertificate.getRevocationStatusInformation().getIssuanceDate().getTime() + signingCertificateValidityTime.getTime()))).after(this.validationTime)) {
                    return Indication.getInstance(Indication.PASSED);
                } else {
                    this.signingCertificate.getRevocationStatusInformation().setRevocationTime(new Date(this.signingCertificate.getRevocationStatusInformation().getIssuanceDate().getTime() + signingCertificateValidityTime.getTime()));
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
    
    private Indication cryptographicVerification() {
        List<SignedDataObject> signedDataObjects;
        /* Check if signed data objects are obtainable */
        if ((this.signature.getSignedProperties().getSignedDataObjectProperties() != null)
            && (this.signature.getSignedProperties().getSignedDataObjectProperties().getSignedDataObjects() != null)) {
            signedDataObjects = this.signature.getSignedProperties().getSignedDataObjectProperties().getSignedDataObjects();
        } else {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.SIGNED_DATA_NOT_FOUND);
        }
        /* Check signed data objects integrity */
        for (SignedDataObject signedDataObject : signedDataObjects) {
            if (false == signedDataObject.checkIntegrity()) {
                return Indication.getInstance(Indication.FAILED, SubIndication.HASH_FAILURE);
            }
        }
        if (true == this.signature.checkSignatureValue(this.signature.getSignatureValue(), this.signature.getSignatureAlgorithm(), this.signingCertificate.getPublicKey())) {
            return Indication.getInstance(Indication.PASSED);
        } else{
            return Indication.getInstance(Indication.FAILED, SubIndication.SIG_CRYPTO_FAILURE);
        }
    }
    
    public Indication validateSignatureAcceptance(Date validationTime) {
        /* Check if all algorithms are compliant */
        List<String> algorithms = getAllSignatureAlgorithms();
        boolean deprecatedAlgorithmFound = false;
        for (String algorithm : algorithms) {
            if (false == this.signatureValidationPolicies.getCryptographicConstraints().isAlgorithmReliable(algorithm, validationTime)) {
                this.signature.addDeprectedAlgorithm(algorithm);
                deprecatedAlgorithmFound = true;
            }
        }
        if (true == deprecatedAlgorithmFound) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
        }
        
        /* Check that no mandatory attributes are missing */
        if (true == this.signatureValidationPolicies.getSignatureElementConstraints().containsMissingElement(this.signature)) {
            return Indication.getInstance(Indication.PASSED);
        } else {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE);
        }
    }
    
    public List<String> getAllSignatureAlgorithms() {
        List<String> algorithms = new ArrayList<>();
        
        algorithms.add(this.signature.getSignatureAlgorithm());
        if (false == algorithms.contains(this.signatureValidationPolicies.getHash().getAlgorithm())) {
            algorithms.add(this.signatureValidationPolicies.getHash().getAlgorithm());
        }
        if (false == algorithms.contains(this.signature.getSignedProperties().getSignedSignatureProperties().getSigningCertificate().getPublicKey().getAlgorithm())) {
            algorithms.add(this.signature.getSignedProperties().getSignedSignatureProperties().getSigningCertificate().getPublicKey().getAlgorithm());
        }
        for (SignatureCertificate otherCertificate : this.signature.getSignedProperties().getSignedSignatureProperties().getSigningCertificate().getOtherCertificates()) {
            if (false == algorithms.contains(otherCertificate.getPublicKey().getAlgorithm())) {
                algorithms.add(otherCertificate.getPublicKey().getAlgorithm());
            }
        }
        
        for (TimeStamp timestamp : this.signature.getSignedProperties().getSignedDataObjectProperties().getAllDataObjectsTimestamps()){
            if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                algorithms.add(timestamp.getSignatureAlgorithm());
            }
        }
        
        for (TimeStamp timestamp : this.signature.getSignedProperties().getSignedDataObjectProperties().getIndividualDataObjectsTimeStamps()){
            if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                algorithms.add(timestamp.getSignatureAlgorithm());
            }
        }
        
        for (TimeStamp timestamp : this.signature.getUnsignedProperties().getSignatureTimeStamps()) {
            if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                algorithms.add(timestamp.getSignatureAlgorithm());
            }
        }

        for (TimeStamp timestamp : this.signature.getUnsignedProperties().getArchiveTimeStamps()) {
            if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                algorithms.add(timestamp.getSignatureAlgorithm());
            }
        }
        for (SignatureCertificate otherCertificate : this.signature.getUnsignedProperties().getCertificateValues()) {
            if (false == algorithms.contains(otherCertificate.getPublicKey().getAlgorithm())) {
                algorithms.add(otherCertificate.getPublicKey().getAlgorithm());
            }
        }
        for (EncapsulatedPKIData encapsulatedPKIData: this.signature.getUnsignedProperties().getRevocationValues().getCRLValues()) {
            if (false == algorithms.contains(encapsulatedPKIData.getCertificate().getPublicKey().getAlgorithm())) {
                algorithms.add(encapsulatedPKIData.getCertificate().getPublicKey().getAlgorithm());
            }
        }
        
        return algorithms;
    }
    
    public Signature getSignature() {
        return this.signature;
    }
    public SignerDocument getSignerDocument() {
        return this.signerDocument;
    }
    public SignatureCertificate getSigningCertificate() {
        return this.signingCertificate;
    }
    public Set<TrustAnchor> getTrustAnchors() {
        return this.trustAnchors;
    }
    public List<ObjectIdentifier> getAllowableValidationPolicyIds() {
        return this.allowableValidationPolicyIds;
    }
    public PolicyIdentifier getSignatureValidationPolicies() {
        return this.signatureValidationPolicies;
    }
    public LocalConfiguration getLocalConfiguration() {
        return this.localConfiguration;
    }
    public Date getValidationTime() {
        return this.validationTime;
    }
    public PKIXCertificationPathVerifier getChainPathVerifier() {
        return this.chainPathVerifier;
    }

    
}