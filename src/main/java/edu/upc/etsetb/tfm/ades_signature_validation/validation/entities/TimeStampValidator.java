/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.validation.entities;

import edu.upc.etsetb.tfm.ades_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.CertificateReference;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.LocalConfiguration;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.PKIXCertificationPathVerifier;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.PolicyIdentifier;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.TimeStamp;
import java.security.cert.TrustAnchor;
import java.text.ParseException;
import java.util.List;
import java.util.Set;

/**
 *
 * @author mique
 */
public class TimeStampValidator {
    private static TimeStampValidator timeStampValidator;
    private TimeStamp timeStamp;
    private Set<TrustAnchor> trustAnchors;
    private PolicyIdentifier signatureValidationPolicies;
    private List<String> allowableValidationPolicyIds;
    private LocalConfiguration localConfiguration;
    private CertificateReference timeStampCertificate;
    private PKIXCertificationPathVerifier chainPathVerifier;
    
    
    protected TimeStampValidator(TimeStamp timeStamp, CertificateReference timeStampCertificate, PolicyIdentifier signatureValidationPolicies, List<String> allowableValidationPolicyIds, Set<TrustAnchor> trustAnchors, LocalConfiguration localConfiguration, PKIXCertificationPathVerifier chainPathVerifier) {
        this.timeStamp = timeStamp;
        this.timeStampCertificate = timeStampCertificate;
        this.signatureValidationPolicies = signatureValidationPolicies;
        this.allowableValidationPolicyIds = allowableValidationPolicyIds;
        this.localConfiguration = localConfiguration;
        this.trustAnchors = trustAnchors;
        this.chainPathVerifier = chainPathVerifier;
    }
    
    public static TimeStampValidator getInstance(TimeStamp timeStamp, CertificateReference timeStampCertificate, PolicyIdentifier signatureValidationPolicies, List<String> allowableValidationPolicyIds, Set<TrustAnchor> trustAnchors, LocalConfiguration localConfiguration, PKIXCertificationPathVerifier chainPathVerifier) {
        timeStampValidator = new TimeStampValidator(timeStamp, timeStampCertificate, signatureValidationPolicies, allowableValidationPolicyIds, trustAnchors, localConfiguration, chainPathVerifier);
        return timeStampValidator;
    }
    
    public Indication validate() throws ParseException {
        Indication result;
        BasicSignatureValidator basicSignatureValidator = BasicSignatureValidator.getInstance(timeStamp, timeStampCertificate, trustAnchors, allowableValidationPolicyIds, signatureValidationPolicies, localConfiguration, timeStamp.getTSTInfo().getGenTime().getDate(), chainPathVerifier);
    
        result = basicSignatureValidator.validate(false);
        
        return result;
    }
}
