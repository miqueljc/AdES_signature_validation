/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature;

import java.util.Date;

/**
 *
 * @author mique
 */
public interface ProofOfExistence {

    public Object getObject();
    public Date getSigningDate();
    public void setObject(Object object);
    public void setSigningTime(Date signingDate);
    
}
