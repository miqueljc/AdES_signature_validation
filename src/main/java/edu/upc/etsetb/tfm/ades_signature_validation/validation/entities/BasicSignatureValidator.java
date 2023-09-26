/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.validation.entities;

import edu.upc.etsetb.tfm.ades_signatrue_validation.tools.entities.DigestAlgorithm;
import edu.upc.etsetb.tfm.ades_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.ades_signature_validation.report.entities.SubIndication;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.CertificateReference;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.LocalConfiguration;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.PKIXCertificationPathVerifier;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.PKIXCertificationPathVerifier.PathValidationStatus;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.PolicyIdentifier;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.RevocationStatusInformation;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.Signature;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.SignatureCertificates;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.SignedDataObject;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.TimeStamp;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints.ValidationModel;
import java.security.cert.CertificateEncodingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author mique
 */
public class BasicSignatureValidator {
    
    private static BasicSignatureValidator basicSignatureValidation;
    private Signature signature;
    private CertificateReference signingCertificateRef;
    private Set<TrustAnchor> trustAnchors;
    private List<String> allowableValidationPolicyIds;
    private PolicyIdentifier signatureValidationPolicies;
    private LocalConfiguration localConfiguration;
    private Date validationTime;
    private PKIXCertificationPathVerifier chainPathVerifier;

    
    protected BasicSignatureValidator(Signature signature, CertificateReference signingCertificateRef, Set<TrustAnchor> trustAnchors, List<String> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, PKIXCertificationPathVerifier chainPathVerifier) {
        this.signature = signature;
        this.signingCertificateRef = signingCertificateRef;
        this.trustAnchors = trustAnchors;
        this.allowableValidationPolicyIds = allowableValidationPolicyIds;
        this.signatureValidationPolicies = signatureValidationPolicies;
        this.localConfiguration = localConfiguration;
        this.validationTime = validationTime;
        this.chainPathVerifier = chainPathVerifier;
    }

    public static BasicSignatureValidator getInstance(Signature signature, CertificateReference signingCertificate, Set<TrustAnchor> trustAnchors, List<String> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, PKIXCertificationPathVerifier chainPathVerifier) {
        basicSignatureValidation = new BasicSignatureValidator(signature, signingCertificate, trustAnchors, allowableValidationPolicyIds, signatureValidationPolicies, localConfiguration, validationTime, chainPathVerifier);
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
        if (this.signingCertificateRef == null) {
            if ((this.signature != null)
                    && (this.signature.getCertificateReferences() != null)
                    && (this.signature.getCertificateReferences().getListOfCertificates() != null)
                    && (true == this.signature.getCertificateReferences().getListOfCertificates().isEmpty())) {
                this.signingCertificateRef = this.signature.getCertificateReferences().getCertificateByIndex(0);
            } else {
                return Indication.getInstance(Indication.INDETERMINATE,SubIndication.NO_SIGNING_CERTIFICATE_FOUND);
            }
        }
        /* Compare signing certificate reference with KeyInfo/X509Data certificates to find the signing certificate*/
        if ((this.signature.getX509DataCertificates() != null)
            && (false == this.signature.getX509DataCertificates().isEmpty())) {
            for (X509Certificate certificate : this.signature.getX509DataCertificates()) {
                try {
                    if (true == this.signature.verifyDigest(certificate.getEncoded(), this.signingCertificateRef.getDigest(), this.signingCertificateRef.getAlgorithm())) {
                         return Indication.getInstance(Indication.PASSED);
                    }
                } catch (CertificateEncodingException ex) {
                    /* Ignore certificate */
                }
            }
        }
        
        /* Otherwise use other certificate's values (from revocation values) */
        List<X509Certificate> certificateValues = new ArrayList<>();
        if (this.signature.getCertificateValues() != null) {
            certificateValues.addAll(this.signature.getCertificateValues());
        }
        /* Compare computed digest with each of the list until one matches */
        for (X509Certificate certificate : certificateValues) {
            try {
                if (true == this.signature.verifyDigest(certificate.getEncoded(), this.signingCertificateRef.getDigest(), this.signingCertificateRef.getAlgorithm())) {
                    /* Check Issuer and Serial Number if exists */
                    if (((certificate.getSerialNumber() != null)
                            && ((this.signingCertificateRef.getSerial() == null)
                            || (false == this.signingCertificateRef.getSerial().equals(certificate.getSerialNumber().toString()))))
                            || ((certificate.getIssuerUniqueID() != null)
                            && ((this.signingCertificateRef.getIssuer() == null)
                            || (false == Arrays.equals(this.signingCertificateRef.getIssuer(),certificate.getIssuerUniqueID()))))) {
                        return Indication.getInstance(Indication.INDETERMINATE,SubIndication.INVALID_ISSUER_SERIAL);
                    } else {
                        return Indication.getInstance(Indication.PASSED);
                    }
                }
            } catch (CertificateEncodingException ex) {
                /* Ignore certificate */
            }
        }
        return Indication.getInstance(Indication.INDETERMINATE,SubIndication.NO_SIGNING_CERTIFICATE_FOUND);
    }
    
    private Indication initializeValidationContext() {
        
        /* If no validation policy is provided as input, use default policy */
        if ((this.signatureValidationPolicies == null)
            || (this.signatureValidationPolicies.getId() == null)
            || (this.signatureValidationPolicies.getHash() == null)){
            this.signatureValidationPolicies = this.localConfiguration.getDefaultPolicyIdentifier();
        } else {
            boolean isPolicyAllowed = false;
            for (String id: this.allowableValidationPolicyIds) {
                /* If the given policy is not in the list of allowable policies, use default policy */
                if ((this.signatureValidationPolicies.getId() != null)
                    && (this.signatureValidationPolicies.getId().equals(id))) {
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
        /* Compute digest of the policy document using the transformations of the policy according to the signature format */
        } else if (false == Base64.getEncoder().encodeToString(this.signatureValidationPolicies.getHash()).equals(this.signatureValidationPolicies.applyTransforms(this.signature.getFormat()))) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.POLICY_PROCESSING_ERROR);
        } else {
            this.signatureValidationPolicies.setConstraints();
            return Indication.getInstance(Indication.PASSED); 
        }
        
    }
    
    public Indication checkFreshness(X509Certificate certificate, RevocationStatusInformation revocationInfo, X509ValidationConstraints constraints, Date validationTime) {
        
        if ((constraints.getMaximumAcceptedRevocationFreshness() != null)
            && (revocationInfo.getIssuanceDate() != null)) {
            /* Get maximum accepted time */
            Date maximumAcceptedTime = new Date(validationTime.getTime() - constraints.getMaximumAcceptedRevocationFreshness().getTime());
            if (revocationInfo.getIssuanceDate().after(maximumAcceptedTime)) {
                /* Issuance time after maximum accepted time */
                return Indication.getInstance(Indication.PASSED);
            } else {
                /* Issuance time before maximum accepted time */
                this.signature.addRevockedCerticate(certificate, validationTime);
                return Indication.getInstance(Indication.FAILED);
            }
        } else if ((constraints.getMaximumAcceptedRevocationFreshness() == null)
                && (revocationInfo.getIssuanceDate() != null)
                && (revocationInfo.getNextUpdate() != null)
                && (revocationInfo.getThisUpdate() != null)) {
            /* Get interval between thisUpdate and nextUpdate */
            Date intervalTime = new Date(revocationInfo.getNextUpdate().getTime() - revocationInfo.getThisUpdate().getTime());
            /* Get maximum accepted time */
            Date maximumAcceptedTime = new Date(validationTime.getTime() - intervalTime.getTime());
            if (revocationInfo.getIssuanceDate().after(maximumAcceptedTime)) {
                /* Issuance time after maximum accepted time */
                return Indication.getInstance(Indication.PASSED);
            } else {
                /* Issuance time before maximum accepted time */
                this.signature.addRevockedCerticate(certificate, new Date(maximumAcceptedTime.getTime()));
                return Indication.getInstance(Indication.FAILED);
            }
        } else {
            this.signature.addRevockedCerticate(certificate, new Date());
            return Indication.getInstance(Indication.FAILED);
        }
    }
    
    private Indication validateX509Certificate() {
        /* If no validation time available, take current time */
        if (this.validationTime == null) {
            this.validationTime = new Date();
        }
        
        /* Create chain of certificates */
        List<X509Certificate> listOfCertificates = new ArrayList<>();
        if (this.signature.getX509DataCertificates() != null) {
            listOfCertificates.addAll(this.signature.getX509DataCertificates());
        }
        if (this.signature.getCertificateValues() != null) {
            listOfCertificates.addAll(this.signature.getCertificateValues());
        }
        this.chainPathVerifier.createCertificatesChain(listOfCertificates);
        List<X509Certificate> certificatesChain = this.chainPathVerifier.getChainOfCertificates();
        if (true == certificatesChain.isEmpty()) {
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
        chainPathVerificationResult = this.chainPathVerifier.validateChain(this.signature, this.validationTime, pathValidationModel);
        if (null == chainPathVerificationResult) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE);
        } else switch (chainPathVerificationResult) {
            case VALID -> {
                /* Perfom freshnees check for all certificates in the chain */
                Indication freshnessResult;
                for (X509Certificate certificate : certificatesChain) {
                    freshnessResult = checkFreshness(certificate, this.signature.getRevocationValues().requestRevocationStatusInformationOfCertificate(certificate), this.signatureValidationPolicies.getX509ValidationConstraints(), this.validationTime);
                    if (Indication.FAILED == freshnessResult.getValue()) {
                        return Indication.getInstance(Indication.INDETERMINATE, SubIndication.TRY_LATER);
                    }
                }
                /* Apply X509 validation constraints to chain */
                if (false == this.signatureValidationPolicies.getX509ValidationConstraints().isChainMatched(certificatesChain)) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CHAIN_CONSTRAINTS_FAILURE);
                }
                /* Apply cryptographic constraints to chain */
                if (false == this.signatureValidationPolicies.getCryptographicConstraints().isChainMatched(certificatesChain)) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
                }
                /* Check if signing certificate is in validity range */
                Date signingCertificateValidityTime = this.signatureValidationPolicies.getX509ValidationConstraints().getSigningCertificateValidityRange();
                if (true == ((new Date(this.signature.getRevocationValues().requestRevocationStatusInformationOfCertificate(certificatesChain.get(0)).getIssuanceDate().getTime() + signingCertificateValidityTime.getTime()))).after(this.validationTime)) {
                    return Indication.getInstance(Indication.PASSED);
                } else {
                    this.signature.addRevockedCerticate(certificatesChain.get(0), new Date(this.signature.getRevocationValues().requestRevocationStatusInformationOfCertificate(certificatesChain.get(0)).getIssuanceDate().getTime() + signingCertificateValidityTime.getTime()));
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
        if (this.signature.getSignedDataObjects() != null) {
            signedDataObjects = this.signature.getSignedDataObjects();
        } else {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.SIGNED_DATA_NOT_FOUND);
        }
        /* Check signed data objects integrity */
        for (SignedDataObject signedDataObject : signedDataObjects) {
            if (false == signedDataObject.checkIntegrity()) {
                return Indication.getInstance(Indication.FAILED, SubIndication.HASH_FAILURE);
            }
        }
        if (true == this.signature.verifySignatureValue()) {
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
                if (false == this.signature.getAllDeprecatedAlgorithms().contains(algorithm)) {
                    this.signature.addDeprecatedAlgorithm(algorithm);
                }
                deprecatedAlgorithmFound = true;
            }
        }
        if (true == deprecatedAlgorithmFound) {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
        }
        
        /* Check that no mandatory attributes are missing */
        if (false == this.signatureValidationPolicies.getSignatureElementConstraints().containsMissingElement(this.signature)) {
            return Indication.getInstance(Indication.PASSED);
        } else {
            return Indication.getInstance(Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE);
        }
    }
    
    public List<String> getAllSignatureAlgorithms() {
        List<String> algorithms = new ArrayList<>();
        
        algorithms.add(this.signature.getSignatureAlgorithm());
        if (false == algorithms.contains(this.signatureValidationPolicies.getAlgorithm())) {
            algorithms.add(this.signatureValidationPolicies.getAlgorithm());
        }
        
        if (this.signature.getX509DataCertificates() != null) {
            for (X509Certificate certificate : this.signature.getX509DataCertificates()) {
                if (false == algorithms.contains(certificate.getPublicKey().getAlgorithm())) {
                    algorithms.add(certificate.getPublicKey().getAlgorithm());
                }
            }
        }
        
        if (this.signature.getCertificateValues() != null) {
            for (X509Certificate certificate : this.signature.getCertificateValues()) {
                if (false == algorithms.contains(certificate.getPublicKey().getAlgorithm())) {
                    algorithms.add(certificate.getPublicKey().getAlgorithm());
                }
            }
        }
        
        if (this.signature.getAllDataObjectsTimestamps() != null) {
            for (TimeStamp timestamp : this.signature.getAllDataObjectsTimestamps()){
                if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                    algorithms.add(timestamp.getSignatureAlgorithm());
                }
            }
        }
        
        if (this.signature.getIndividualDataObjectsTimeStamps() != null) {
            for (TimeStamp timestamp : this.signature.getIndividualDataObjectsTimeStamps()){
                if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                    algorithms.add(timestamp.getSignatureAlgorithm());
                }
            }
        }
        
        if (this.signature.getSignatureTimeStamps() != null) {
            for (TimeStamp timestamp : this.signature.getSignatureTimeStamps()) {
                if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                    algorithms.add(timestamp.getSignatureAlgorithm());
                }
            }
        }
        
        if (this.signature.getArchiveTimeStamps() != null) {
            for (TimeStamp timestamp : this.signature.getArchiveTimeStamps()) {
                if (false == algorithms.contains(timestamp.getSignatureAlgorithm())) {
                    algorithms.add(timestamp.getSignatureAlgorithm());
                }
            }
        }
        
        return algorithms;
    }
    
    public Signature getSignature() {
        return this.signature;
    }
    public CertificateReference getSigningCertificate() {
        return this.signingCertificateRef;
    }
    public Set<TrustAnchor> getTrustAnchors() {
        return this.trustAnchors;
    }
    public List<String> getAllowableValidationPolicyIds() {
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