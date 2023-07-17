/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.signature;

import java.util.List;

/**
 *
 * @author mique
 */
public interface ObjectIdentifier {
    
    public String getIdentifier();
    public OIDFormat getOIDFormat();
    public String getDescription();
    public List<String> getDocumentationReferences();
    
    public void setIdentifier(String identifier);
    public void setOIDFormat(OIDFormat oidFormat);
    public void setDescription(String description);
    public void addDocumentationReference(String documentationReferences);
    
    public enum OIDFormat {
        OID_AS_URI, OID_AS_URN;
    }
}
