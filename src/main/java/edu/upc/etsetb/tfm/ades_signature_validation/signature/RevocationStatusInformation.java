/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature;

import java.util.Date;
import java.util.List;

/**
 *
 * @author mique
 */
public interface RevocationStatusInformation {
    public byte[] getEncoded();
    public Date getIssuanceDate();
    public Date getThisUpdate();
    public Date getNextUpdate();
    public Date getRevocationDate();
    public String getRevocationReason();
}
