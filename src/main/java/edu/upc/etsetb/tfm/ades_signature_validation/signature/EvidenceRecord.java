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
public interface EvidenceRecord {
    public TimeStamp getArchiveTimeStamp();
    public List<String> getArchivedDataObjects();
    
    public void setArchiveTimeStamp(TimeStamp timeStamp);
    public void addArchivedDataObject(String objectReference);
    
    public boolean isValid();
}
