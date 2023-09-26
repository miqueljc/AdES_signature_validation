/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.validation.entities;

import edu.upc.etsetb.tfm.ades_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.ades_signature_validation.report.entities.SubIndication;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.CertificateReference;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.LocalConfiguration;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.PKIXCertificationPathVerifier;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.PolicyIdentifier;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.Signature;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.TimeStamp;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 *
 * @author mique
 */
public class LTSignatureValidator {
    private static LTSignatureValidator timeSignatureValidator;
    private Signature signature;
    private CertificateReference signingCertificateRef;
    private Set<TrustAnchor> trustAnchors;
    private List<String> allowableValidationPolicyIds;
    private PolicyIdentifier signatureValidationPolicies;
    private LocalConfiguration localConfiguration;
    private Date validationTime;
    private Date signatureExistence;
    private PKIXCertificationPathVerifier chainPathVerifier;
    private Date bestSignatureTime;
    private List<TimeStamp> signatureTimeStamps;
    
    protected LTSignatureValidator(Signature signature, CertificateReference signingCertificateRef, Set<TrustAnchor> trustAnchors, List<String> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, Date signatureExistence, PKIXCertificationPathVerifier chainPathVerifier) {
        this.signature = signature;
        this.signingCertificateRef = signingCertificateRef;
        this.trustAnchors = trustAnchors;
        this.allowableValidationPolicyIds = allowableValidationPolicyIds;
        this.signatureValidationPolicies = signatureValidationPolicies;
        this.localConfiguration = localConfiguration;
        this.validationTime = validationTime;
        this.signatureExistence = signatureExistence;
        this.chainPathVerifier = chainPathVerifier;
        this.bestSignatureTime = new Date();
        this.signatureTimeStamps = new ArrayList<>();
    }

    public static LTSignatureValidator getInstance(Signature signature, CertificateReference signingCertificateRef, Set<TrustAnchor> trustAnchors, List<String> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, Date signatureExistence, PKIXCertificationPathVerifier chainPathVerifier) {
        timeSignatureValidator = new LTSignatureValidator(signature, signingCertificateRef, trustAnchors, allowableValidationPolicyIds, signatureValidationPolicies, localConfiguration, validationTime, signatureExistence, chainPathVerifier);
        return timeSignatureValidator;
    }
    
    public Indication validate() throws ParseException {
        Indication result;
        
        /* Basic signature validation */
        BasicSignatureValidator basicSignatureValidator = BasicSignatureValidator.getInstance(this.signature, this.signingCertificateRef, this.trustAnchors, this.allowableValidationPolicyIds, this.signatureValidationPolicies, this.localConfiguration, this.validationTime, this.chainPathVerifier);
        result = basicSignatureValidator.validate(true);
        this.signature = basicSignatureValidator.getSignature();
        this.signingCertificateRef = basicSignatureValidator.getSigningCertificate();
        this.signatureValidationPolicies = basicSignatureValidator.getSignatureValidationPolicies();
        this.validationTime = basicSignatureValidator.getValidationTime();
        this.chainPathVerifier = basicSignatureValidator.getChainPathVerifier();
        
        /* Signature Time-Stamp validation */
        /* Check if Basic Signature Validation result can be solved by changing the validation time */
        if ((result.getValue() == Indication.FAILED)
            || (result.getValue() == Indication.PASSED)
            || ((result.getValue() == Indication.INDETERMINATE) 
                && ((result.getSubIndication() != SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE)
                && (result.getSubIndication() != SubIndication.REVOKED_NO_POE)
                && (result.getSubIndication() != SubIndication.REVOKED_CA_NO_POE)
                && (result.getSubIndication() != SubIndication.TRY_LATER)
                && (result.getSubIndication() != SubIndication.OUT_OF_BOUNDS_NO_POE)))) {
            return result;
        }
        /* Check if result has changed */
        Indication timeStampsValidationResult = validateSignatureTimeStamps(result);
        if ((timeStampsValidationResult.getValue() != result.getValue())
            || (timeStampsValidationResult.getSubIndication() != result.getSubIndication())) {
            return timeStampsValidationResult;
        }
        
        /* Time comparison */
        result = compareTimes(result, basicSignatureValidator);
        
        /* Signature Acceptance Validation */
        if (result.getValue() == Indication.PASSED) {
            result = basicSignatureValidator.validateSignatureAcceptance(this.bestSignatureTime);
        }
        
        return result;
    }
    
    private Indication validateSignatureTimeStamps(Indication basicSignatureValidationResult) throws ParseException {
        
        /* If earliest existence time of the signature is not provided as input, set is to validation time */
        if (this.signatureExistence == null) {
            this.signatureExistence = this.validationTime;
        }
        /* Time-Stamps validation */
        this.bestSignatureTime = this.signatureExistence;
        TimeStampValidator timeStampValidator;
        this.signatureTimeStamps = this.signature.getAllSignatureTimeStamps();
        Iterator<TimeStamp> iterator = this.signatureTimeStamps.iterator();
        TimeStamp timeStamp;
        Indication timeStampValidationResult;
        while(iterator.hasNext()) {
            timeStamp = iterator.next();
            /* Check Time-Stamp validity */
            if (false == timeStamp.getFormat().equals(this.signature.getFormat())) {
                /* Remove timeStamp and check next one (if exists) */
                iterator.remove();
                continue;
            }
            /* Validate Time-Stamp */
            timeStampValidator = TimeStampValidator.getInstance(timeStamp, timeStamp.getCertificateReferences().getCertificateByIndex(0), this.signatureValidationPolicies, this.allowableValidationPolicyIds, this.trustAnchors, this.localConfiguration, this.chainPathVerifier);
            timeStampValidationResult = timeStampValidator.validate();
            /* If validation successes and generation time is before best-signature-time, update best-signature-time */
            if (timeStampValidationResult.getValue() == Indication.PASSED) {
                if (true == timeStamp.getTSTInfo().getGenTime().getDate().before(this.bestSignatureTime)) {
                    this.bestSignatureTime = timeStamp.getTSTInfo().getGenTime().getDate();
                }
            /* Check if Time-Stamp validation is needed */
            } else if (true == this.signatureValidationPolicies.getSignatureElementConstraints().isTimeStampValidationNeeded()) {
                return timeStampValidationResult;
            } else {
                iterator.remove();
            }
        }
        return basicSignatureValidationResult;
    }
    
    private Indication compareTimes(Indication basicSignatureValidationResult, BasicSignatureValidator basicSignatureValidator) throws ParseException {
        switch (basicSignatureValidationResult.getSubIndication()) {
            case SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE -> {
                List<String> algorithms = basicSignatureValidator.getAllSignatureAlgorithms();
                for (String algorithm : algorithms) {
                    if (false == this.signatureValidationPolicies.getCryptographicConstraints().isAlgorithmReliable(algorithm, this.bestSignatureTime)) {
                        return basicSignatureValidationResult;
                    }
                }
            }
            case SubIndication.REVOKED_NO_POE -> {
                for (X509Certificate certificate : this.signature.getRevockedCertificates().keySet()) {
                    if (this.signature.getRevockedCertificates().get(certificate).before(this.bestSignatureTime)) {
                        return basicSignatureValidationResult;
                    }
                }
            }
            case SubIndication.REVOKED_CA_NO_POE -> {
                for (X509Certificate certificate : this.signature.getRevockedCertificates().keySet()) {
                    if (this.signature.getRevockedCertificates().get(certificate).before(this.bestSignatureTime)) {
                        return basicSignatureValidationResult;
                    }
                }
            }
            case SubIndication.OUT_OF_BOUNDS_NO_POE -> {
                for (X509Certificate certificate : this.signature.getRevockedCertificates().keySet()) {
                    if (this.signature.getRevockedCertificates().get(certificate).after(this.bestSignatureTime)) {
                        
                    }
                }
                if (true == (new Date(this.signature.getRevocationValues().requestRevocationStatusInformationOfCertificate(this.signature.getCertificatesChain().get(0)).getIssuanceDate().getTime())).after(this.bestSignatureTime)) {
                    return Indication.getInstance(Indication.FAILED, SubIndication.NOT_YET_VALID);
                } else {
                    return Indication.getInstance(Indication.PASSED);
                }
            }
            case SubIndication.TRY_LATER -> {
                if (Indication.FAILED == basicSignatureValidator.checkFreshness(this.chainPathVerifier.getChainOfCertificates().get(0), this.signature.getRevocationValues().getSavedRevocationStatusInformationOfCertificate(this.chainPathVerifier.getChainOfCertificates().get(0), this.bestSignatureTime), this.signatureValidationPolicies.getX509ValidationConstraints(), this.bestSignatureTime).getValue()) {
                    return basicSignatureValidationResult;
                }
            }
            default -> {
                /* Do nothing */
            }
        }
        
        /* Check Time-Stamp tokens time values coherence */
        List<TimeStamp> signedTimeStamps = new ArrayList<>();
        if (this.signature.getAllDataObjectsTimestamps() != null) {
            signedTimeStamps.addAll(this.signature.getAllDataObjectsTimestamps());
        }
        if (this.signature.getIndividualDataObjectsTimeStamps() != null) {
            signedTimeStamps.addAll(this.signature.getIndividualDataObjectsTimeStamps());
        }
        
        for (TimeStamp signatureTimeStamp : this.signatureTimeStamps) {
            for (TimeStamp signedTimeStamp : signedTimeStamps) {
                /* Check that all signature Time-Stamps are posterior to every signed Time-Stamp */
                if (signatureTimeStamp.getTSTInfo().getGenTime().getDate().before(signedTimeStamp.getTSTInfo().getGenTime().getDate())) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.TIMESTAMP_ORDER_FAILURE);
                }
            }
        }
        
        /* Handle Time-Stamp delay if requested by policies */
        if (this.signatureValidationPolicies.getSignatureElementConstraints().isTimeStampDelayNeeded()) {
            for (TimeStamp signatureTimeStamp : this.signatureTimeStamps) {
                if ((false == signatureTimeStamp.hasDelay())
                    || (signatureTimeStamp.getTSTInfo().getGenTime().getDate().getTime() + signatureTimeStamp.getDelayMs() <= this.bestSignatureTime.getTime())) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE);
                }          
            }
        }

        return Indication.getInstance(Indication.PASSED);
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
