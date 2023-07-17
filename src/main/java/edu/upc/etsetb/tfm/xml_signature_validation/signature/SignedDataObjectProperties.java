/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.util.List;
import org.bouncycastle.asn1.esf.CommitmentTypeIndication;

/**
 *
 * @author mique
 */
public interface SignedDataObjectProperties {
    public List<SignedDataObject> getSignedDataObjects();
    public List<CommitmentTypeIndication> getCommitmentTypeIndications();
    public List<TimeStamp> getAllDataObjectsTimestamps();
    public List<TimeStamp> getIndividualDataObjectsTimeStamps();
    public void addSignedDataObject(SignedDataObject signingDataObject);
    public void addCommitmentTypeIndication(CommitmentTypeIndication commitmentTypeIndication);
    public void addAllDataObjectsTimeStamp(TimeStamp timeStamp);
    public void addIndividualDataObjectsTimeStamp(TimeStamp timeStamp);
}
