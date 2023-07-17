/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints.ValidationModel;
import java.util.Date;
import java.util.List;

/**
 *
 * @author mique
 */
public interface PKIXCertificationPathVerifier {
    public RevocationStatusInformation getRevocationStatusInformation();
    public void setRevocationStatusInformation(RevocationStatusInformation revocationStatusInformation);
    
    
    public PathValidationStatus validateChain(List<SignatureCertificate> certificatesChain, Date validationTime, ValidationModel validationModel);
    
    public enum PathValidationStatus {
        VALID, SIGNING_CERTIFICATE_REVOKED, SIGNING_CERTIFICATE_ON_HOLD, INTERMEDIATE_CA_REVOKED, OTHER;
    }
}
