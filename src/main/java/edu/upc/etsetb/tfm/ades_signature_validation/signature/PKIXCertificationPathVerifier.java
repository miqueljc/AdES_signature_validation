/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature;

import edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints.ValidationModel;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 *
 * @author mique
 */
public interface PKIXCertificationPathVerifier {
    
    public void createCertificatesChain(List<X509Certificate> certificates);
    
    /* This method validates the chain and adds revocation information. Also saves in the signature the revoked certificates with the  */
    public PathValidationStatus validateChain(Signature signature, Date validationTime, ValidationModel validationModel);
    
    public List<X509Certificate> getChainOfCertificates();
    
    public enum PathValidationStatus {
        VALID, SIGNING_CERTIFICATE_REVOKED, SIGNING_CERTIFICATE_ON_HOLD, INTERMEDIATE_CA_REVOKED, OTHER;
    }
}
