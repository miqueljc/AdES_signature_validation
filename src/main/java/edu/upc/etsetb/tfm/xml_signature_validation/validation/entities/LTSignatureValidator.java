/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.validation.entities;

import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.SubIndication;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.LocalConfiguration;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.ObjectIdentifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PKIXCertificationPathVerifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PolicyIdentifier;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.Signature;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignatureCertificate;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignerDocument;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.TimeStamp;
import java.security.cert.TrustAnchor;
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
    private SignerDocument signerDocument;
    private SignatureCertificate signingCertificate;
    private Set<TrustAnchor> trustAnchors;
    private List<ObjectIdentifier> allowableValidationPolicyIds;
    private PolicyIdentifier signatureValidationPolicies;
    private LocalConfiguration localConfiguration;
    private Date validationTime;
    private Date signatureExistence;
    private PKIXCertificationPathVerifier chainPathVerifier;
    private Date bestSignatureTime;
    private List<TimeStamp> signatureTimeStamps;
    
    protected LTSignatureValidator(Signature signature, SignerDocument signerDocument, SignatureCertificate signingCertificate, Set<TrustAnchor> trustAnchors, List<ObjectIdentifier> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, Date signatureExistence, PKIXCertificationPathVerifier chainPathVerifier) {
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
        this.bestSignatureTime = new Date();
        this.signatureTimeStamps = new ArrayList<>();
    }

    public static LTSignatureValidator getInstance(Signature signature, SignerDocument signerDocument, SignatureCertificate signingCertificate, Set<TrustAnchor> trustAnchors, List<ObjectIdentifier> allowableValidationPolicyIds, PolicyIdentifier signatureValidationPolicies, LocalConfiguration localConfiguration, Date validationTime, Date signatureExistence, PKIXCertificationPathVerifier chainPathVerifier) {
        timeSignatureValidator = new LTSignatureValidator(signature, signerDocument, signingCertificate, trustAnchors, allowableValidationPolicyIds, signatureValidationPolicies, localConfiguration, validationTime, signatureExistence, chainPathVerifier);
        return timeSignatureValidator;
    }
    
    public Indication validate() throws ParseException {
        Indication result;
        
        /* Basic signature validation */
        BasicSignatureValidator basicSignatureValidator = BasicSignatureValidator.getInstance(this.signature, this.signerDocument, this.signingCertificate, this.trustAnchors, this.allowableValidationPolicyIds, this.signatureValidationPolicies, this.localConfiguration, this.validationTime, this.chainPathVerifier);
        result = basicSignatureValidator.validate(true);
        this.signature = basicSignatureValidator.getSignature();
        this.signingCertificate = basicSignatureValidator.getSigningCertificate();
        this.signatureValidationPolicies = basicSignatureValidator.getSignatureValidationPolicies();
        this.validationTime = basicSignatureValidator.getValidationTime();
        this.chainPathVerifier = basicSignatureValidator.getChainPathVerifier();
        
        /* Signature Time-Stamp validation */
        /* Check if Basic Signature Validation result can be solved by changing the validation time */
        if ((result.getValue() == Indication.FAILED)
            || (result.getValue() == Indication.INDETERMINATE) 
                && ((result.getSubIndication() != SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE)
                && (result.getSubIndication() != SubIndication.REVOKED_NO_POE)
                && (result.getSubIndication() != SubIndication.REVOKED_CA_NO_POE)
                && (result.getSubIndication() != SubIndication.TRY_LATER)
                && (result.getSubIndication() != SubIndication.OUT_OF_BOUNDS_NO_POE))) {
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
        
        /* Revocation Freshness Checker */
        result = checkRevocationFreshness(result, basicSignatureValidator);
        
        /* Signature Acceptance Validation */
        result = basicSignatureValidator.validateSignatureAcceptance(this.bestSignatureTime);
        
        return result;
    }
    
    private Indication validateSignatureTimeStamps(Indication basicSignatureValidationResult) throws ParseException {
        
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
            timeStampValidator = TimeStampValidator.getInstance(timeStamp, timeStamp.getSignedProperties().getSignedSignatureProperties().getSigningCertificate(), this.signatureValidationPolicies, this.allowableValidationPolicyIds, this.trustAnchors, this.localConfiguration, this.chainPathVerifier);
            timeStampValidationResult = timeStampValidator.validate();
            /* If validation successes and generation time is before best-signature-time, update best-signature-time */
            if ((timeStampValidationResult.getValue() == Indication.PASSED)
                && (true == timeStamp.getTSTInfo().getGenTime().getDate().before(this.bestSignatureTime))) {
                this.bestSignatureTime = timeStamp.getTSTInfo().getGenTime().getDate();
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
                if (false == this.chainPathVerifier.getRevocationStatusInformation().getExpiredCertsOnCRL().after(this.bestSignatureTime)) {
                    return basicSignatureValidationResult;
                }
            }
            case SubIndication.REVOKED_CA_NO_POE -> {
                if (false == this.chainPathVerifier.getRevocationStatusInformation().getExpiredCertsOnCRL().after(this.bestSignatureTime)) {
                    return basicSignatureValidationResult;
                }
            }
            case SubIndication.OUT_OF_BOUNDS_NO_POE -> {
                if (true == this.signingCertificate.getRevocationStatusInformation().getIssuanceDate().after(this.bestSignatureTime)) {
                    return Indication.getInstance(Indication.FAILED, SubIndication.NOT_YET_VALID);
                } else {
                    return basicSignatureValidationResult;
                }
            }
            default -> {
                /* Do nothing */
            }
        }
        
        /* Check Time-Stamp tokens time values coherence */
        List<TimeStamp> signedTimeStamps = new ArrayList<>();
        signedTimeStamps.addAll(this.signature.getSignedProperties().getSignedDataObjectProperties().getAllDataObjectsTimestamps());
        signedTimeStamps.addAll(this.signature.getSignedProperties().getSignedDataObjectProperties().getIndividualDataObjectsTimeStamps());
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
                if ((true == signatureTimeStamp.hasDelay())
                    || (signatureTimeStamp.getTSTInfo().getGenTime().getDate().getTime() + signatureTimeStamp.getDelayMs() <= this.bestSignatureTime.getTime())) {
                    return Indication.getInstance(Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE);
                }          
            }
        }

        return basicSignatureValidationResult;
    }
    
    private Indication checkRevocationFreshness(Indication basicSignatureValidationResult, BasicSignatureValidator basicSignatureValidator) {
        if ((basicSignatureValidationResult.getValue() == Indication.INDETERMINATE)
            && (basicSignatureValidationResult.getSubIndication() == SubIndication.TRY_LATER)) {
            return basicSignatureValidator.checkFreshness(this.signingCertificate, this.signatureValidationPolicies.getX509ValidationConstraints(), this.bestSignatureTime);
        } else {
            return basicSignatureValidationResult;
        }
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