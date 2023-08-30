/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.xml_signature_validation.validation.entities;

import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.Indication;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author mique
 */
public class ReportGenerator {
    private String filename;
    
    public ReportGenerator(String filename) {
        this.filename = filename;
    }
    
    public static ReportGenerator startReport() {
        File f = new File("SignatureValidationReport.txt");
        try {
            int i = 0;
            while (!f.createNewFile()) {
                i++;
                f = new File("SignatureValidationReport_"+i+".txt");
            }
            System.out.println("File created: " + f.getName());
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        return new ReportGenerator(f.getAbsolutePath());
    }
    
    public void addSectionTitle(String number, String titleName) {
        try {
            FileWriter writer = new FileWriter(this.filename);
            writer.write("Section " + number + ": " + titleName + "\n");
            writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
    
    public void addNewLine(String text) {
        try {
            FileWriter writer = new FileWriter(this.filename);
            writer.write(text + "\n");
            writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
    
    public void addFinalResult(Indication result) {
        try {
            FileWriter writer = new FileWriter(this.filename);
            writer.write("Signature Validation Result: ");
            if (result.getValue() == Indication.PASSED) {
                writer.write("TOTAL_PASSED\n");
            } else if (result.getValue() == Indication.INDETERMINATE) {
                writer.write("INDETERMINATE\n");
            } else {
                writer.write("TOTAL_FAILED\n");
            }
            writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
    
    
}
