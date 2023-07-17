/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints;

import edu.upc.etsetb.tfm.xml_signature_validation.signature.Signature;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.ValidationConstraint;

/**
 *
 * @author mique
 */
public interface SignatureElementConstraints extends ValidationConstraint{
    public boolean containsMissingElement(Signature signature);
    public boolean isTimeStampValidationNeeded();
    public boolean isTimeStampDelayNeeded();
    public boolean isAttributeValidationNeeded(Object object);
}
