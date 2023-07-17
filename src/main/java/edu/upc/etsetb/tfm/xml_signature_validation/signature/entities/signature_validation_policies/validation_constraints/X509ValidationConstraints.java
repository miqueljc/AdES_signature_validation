/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints;

import edu.upc.etsetb.tfm.xml_signature_validation.signature.SignatureCertificate;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.ValidationConstraint;
import java.util.Date;
import java.util.List;

/**
 *
 * @author mique
 */
public interface X509ValidationConstraints extends ValidationConstraint{
    public ValidationModel getValidationModel();
    public Date getMaximumAcceptedRevocationFreshness();
    public boolean isChainMatched(List<SignatureCertificate> chain);
    public Date getSigningCertificateValidityRange();
    
    public enum ValidationModel {
        CHAIN_MODEL, SHELL_MODEL;
    }
}
