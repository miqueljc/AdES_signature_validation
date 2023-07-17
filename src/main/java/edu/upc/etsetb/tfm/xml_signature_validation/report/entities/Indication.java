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
public class Indication {
    public static final int PASSED = 0;
    public static final int FAILED = 1;
    public static final int INDETERMINATE = 2;
    
    private static Indication indication;
    private int value;
    private SubIndication subIndication;
    
    protected Indication (int value, int subIndication) {
        this.value = value;
        this.subIndication = new SubIndication(subIndication);
    }
    
    protected Indication (int value) {
        this.value = value;
    }
    
    public static Indication getInstance(int value, int subIndication) {
        indication = new Indication(value, subIndication);
        return indication;
    }
    
    public static Indication getInstance(int value) {
        indication = new Indication(value);
        return indication;
    }
    
    public int getValue() {
        return this.value;
    }
    
    public int getSubIndication() {
        return this.subIndication.getValue();
    }
    
    public void setValue(int value) {
        this.value = value;
    }
    
    public void setSubIndication(int subIndication) {
        this.subIndication.setValue(subIndication);
    }
}
