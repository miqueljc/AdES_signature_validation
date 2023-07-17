/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.report.entities;

/**
 *
 * @author mique
 */
public class SubIndication {
    
    public static final int NO_SIGNING_CERTIFICATE_FOUND = 0;
    public static final int INVALID_ISSUER_SERIAL = 1;
    public static final int NO_CERTIFICATE_CHAIN_FOUND = 2;
    public static final int REVOKED_NO_POE = 3;
    public static final int TRY_LATER = 4;
    public static final int REVOKED_CA_NO_POE = 5;
    public static final int CERTIFICATE_CHAIN_GENERAL_FAILURE = 6;
    public static final int CHAIN_CONSTRAINTS_FAILURE = 7;
    public static final int CRYPTO_CONSTRAINTS_FAILURE_NO_POE = 8;
    public static final int OUT_OF_BOUNDS_NO_POE = 9;
    public static final int SIGNED_DATA_NOT_FOUND = 10;
    public static final int HASH_FAILURE = 11;
    public static final int SIG_CRYPTO_FAILURE = 12;
    public static final int SIG_CONSTRAINTS_FAILURE = 13;
    public static final int SIGNATURE_POLICY_NOT_AVAILABLE = 14;
    public static final int POLICY_PROCESSING_ERROR = 15;
    public static final int NOT_YET_VALID = 16;
    public static final int TIMESTAMP_ORDER_FAILURE = 17;
    public static final int NO_POE = 18;
    
    private static SubIndication subIndication;
    private int value;
    
    protected SubIndication(int value) {
        this.value = value;
    }
    
    public static SubIndication getInstance(int value) {
        SubIndication subIndication = new SubIndication(value);
        return subIndication;
    }
    
    public int getValue(){
        return this.value;
    }
    
    public void setValue(int value) {
        this.value = value;
    }
}
