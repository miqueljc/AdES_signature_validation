/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.validation_constraints;

import edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.ValidationConstraint;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 *
 * @author mique
 */
public interface CryptographicConstraints extends ValidationConstraint{
    public boolean isChainMatched(List<X509Certificate> chain);
    public boolean isAlgorithmReliable(String algorithm, Date validationTime);
    public Date getLastSecureAlgorithmDate(String algorithm);
    
}
