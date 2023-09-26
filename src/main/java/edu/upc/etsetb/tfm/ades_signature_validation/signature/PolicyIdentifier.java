/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.upc.etsetb.tfm.ades_signature_validation.signature;

import edu.upc.etsetb.tfm.ades_signatrue_validation.tools.entities.DigestAlgorithm;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.validation_constraints.CryptographicConstraints;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.validation_constraints.SignatureElementConstraints;
import edu.upc.etsetb.tfm.ades_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author mique
 */
public interface PolicyIdentifier {
        
    public String getId();
    public byte[] getHash();
    public String getAlgorithm();
    
    public boolean getSignaturePolicyDocument();
    public boolean parseSignaturePolicyDocument();
    public void setConstraints();
    
    public String applyTransforms(String signatureFormat);

    public X509ValidationConstraints getX509ValidationConstraints();
    public CryptographicConstraints getCryptographicConstraints();
    public SignatureElementConstraints getSignatureElementConstraints();

    public static String getPolicyDocumentFromURL(String policyURL) {
        String policyDocument = null;
        try {
            URL url = new URL(policyURL);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String line;
                StringBuilder response = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                policyDocument = response.toString();
                // Process the policy document as needed
                System.out.println("Policy Document: " + policyDocument);
            } else {
                System.out.println("Failed to retrieve the policy document. Response code: " + responseCode);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return policyDocument;
    }
    
    
//    public static PolicyIdentifier getDefaultPolicy() {
//        /* Get the policy selected as default */
//        List<String> defaultPolicyDocumentationReferences = new ArrayList<>();
//        defaultPolicyDocumentationReferences.add("https://www.itsme-id.com/content-assets/53388/1674210745-compl_pol_genericsignaturevalidationservicepolicy-version-1-3.pdf");
//        ObjectIdentifier defaultPolicyId = ObjectIdentifier.getInstance("https://www.itsme-id.com/nl-BE/legal/document-repository",
//                                                                         ObjectIdentifier.Qualifier.OID_AS_URI,
//                                                                         "COMPL_POL_GenericSignatureValidationServicePolicy. OID: 1.3.6.1.4.1.49274.1.1.4.1.3",
//                                                                         defaultPolicyDocumentationReferences);
//
//        byte[] defaultPolicyHashValue = DigestAlgorithm.StringToByte("AD973F5E4A0D62E1DCCA763D28598617E4300A0E");
//
//        PublicKeyContent defaultPolicyPublicKey = PublicKeyContent.stringToPublicKeyContent("30820122300D06092A864886F70D01010105000382010F003082010A0282010100C2AF962F33207EE0F9DB89BA9E427FC0F4A98F1E254AE4D1A1C7342E8D02235C879537FAAAC39E847BC95F62E30D44FD2B4B58FFDE33E2719884FB1C7CFAC02FC86227ED0FED40214DD492D63C1A9C0E876CB47F8D18C16E12ABB7F206802A855D6D9413C2FCBA18C501FB11AA1BC7278DE332DB2C62A15AE02F802FAE5BEF6445FC985C45DCABA0309CDF2717BF02771635E06D824708E9A5AF2722759A0C7029E9B8095CD58A7E7630521E9227717E6E6B48FFA340F8223B1714CD63B39F01EDF127DB5D320034D06F477E9027A4EAC148F373267A0BDB5C9D9CCBC9BE8153638C86A730B440142C1F1C4A01F395B4C4C1566B7F325B7B781F42E8B3B131F10203010001");
//
//        List<SignatureValidationPolicy> defaultValidationPolicies = new ArrayList<>();
//
//        return new PolicyIdentifier(false, defaultPolicyId, new DigestAlgorithm(defaultPolicyPublicKey), defaultValidationPolicies);
//    }
}
