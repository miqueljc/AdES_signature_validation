package edu.upc.etsetb.tfm.xml_signature_validation.signature;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.SubIndication;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PKIXCertificationPathVerifier.PathValidationStatus;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints.ValidationModel;
import edu.upc.etsetb.tfm.xml_signature_validation.validation.entities.BasicSignatureValidator;
import java.math.BigInteger;
import java.security.cert.TrustAnchor;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.runners.MockitoJUnitRunner;

/**
 *
 * @author mique
 */
@ExtendWith(MockitoExtension.class)
public class BasicSignatureValidatorTest {
    
    @InjectMocks
    private BasicSignatureValidator instance;
    @Mock
    private Signature signatureMock;
    @Mock
    private SignerDocument signerDocumentMock;
    @Mock
    private SignatureCertificate signingCertificateMock;
    @Mock
    private Set<TrustAnchor> trustAnchorsMock;
    @Mock
    private List<ObjectIdentifier> allowableValidationPolicyIdsMock;
    @Mock
    private PolicyIdentifier signatureValidationPoliciesMock;
    @Mock
    private LocalConfiguration localConfigurationMock;
    @Mock
    private Date validationTimeMock;
    @Mock
    private PKIXCertificationPathVerifier chainPathVerifierMock;
    
    public BasicSignatureValidatorTest() {
        
    }
    
    @BeforeAll
    public static void setUpClass() {
        
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }
    
    /*
    * TEST 01
    * 
    * Description:
    * Verify that no Signing Certificate is detected when no Signing Certificate is provided as input and the Signing Certificate is not obtainable from Signature
    * 
    * Inputs:
    * signingCertificateMock is null
    * 
    * Outputs:
    * validationResult is INDETERMINATE, NO_SIGNING_CERTIFICATE_FOUND
    */
    @Test
    public void test_01_NoSigningCertificateInSignature() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = null;
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedSignatureProperties mockedSignedSignatureProperties = mock(SignedSignatureProperties.class);
        
        /* Calls to mocks */
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(null);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, validationResult.getSubIndication());

    }
    
    /*
    * TEST 02
    * 
    * Description:
    * Verify that a Signing Certificate is detected when no Signing Certificate is provided as input and the Signers Certificate is identified from Signature
    * Verify that default policy is taken when no policy is given as input and policy document is obtained and parsed successfully
    * Verify that validation stops when chain of certificates is not obtainable
    * 
    * Inputs:
    * signingCertificateMock is null
    * signatureValidationPoliciesMock is null
    *
    * Outputs:
    * validationResult is INDETERMINATE, NO_CERTIFICATE_CHAIN_FOUND
    */
    @Test
    public void test_02_SignerCertificateFound_NoInputPolicyDocumentObtainedAndParsed_ChainEmpty() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = null;
        this.signatureValidationPoliciesMock = null;
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedSignatureProperties mockedSignedSignatureProperties = mock(SignedSignatureProperties.class);
        SignatureCertificate mockedSigningCertificate = mock(SignatureCertificate.class);
        SignatureCertificate mockedSignerCertificate = mock(SignatureCertificate.class);
        String mockedSignerCertificateDigest = "AB12343BF";
        String mockedSignerCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        List<SignatureCertificate> mockedChainOfCertificates = new ArrayList<>();
        
        
        /* Calls to mocks */
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(mockedSigningCertificate);
        Mockito.when(mockedSigningCertificate.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedSignerCertificate);
        Mockito.when(mockedSignerCertificate.getEncoded()).thenReturn(mockedSignerCertificateDigest);
        Mockito.when(this.signatureMock.getSignatureAlgorithm()).thenReturn(mockedSignerCertificateAlgorithm);
        Mockito.when(mockedSigningCertificate.applyDigest(mockedSignerCertificateDigest, mockedSignerCertificateAlgorithm)).thenReturn(true);
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(this.signatureMock.getSignatureValue()).thenReturn(mockedSignerCertificateDigest);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(this.signatureMock)).thenReturn(mockedSignerCertificateDigest);
        Mockito.when(mockedSigningCertificate.getChainOfCertificates()).thenReturn(mockedChainOfCertificates);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, validationResult.getSubIndication());

    }
    
    /*
    * TEST 03
    * 
    * Description:
    * Verify that a Signing Certificate is identified as the second referenced certificate when no Signing Certificate is not provided as input and the Signers Certificate is not identified from Signature
    * Verify that the validation stops when the document of a given input valid policy is not obtainable
    * 
    * Inputs:
    * signingCertificateMock is null
    * signatureValidationPoliciesMock is not null
    *
    * Outputs:
    * validationResult is INDETERMINATE, SIGNATURE_POLICY_NOT_AVAILABLE
    */
    @Test
    public void test_03_SigningCertificateReferenceFound_PolicyDocumentNotObtained() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = null;
        this.signatureValidationPoliciesMock = mock(PolicyIdentifier.class);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedSignatureProperties mockedSignedSignatureProperties = mock(SignedSignatureProperties.class);
        SignatureCertificate mockedSigningCertificate = mock(SignatureCertificate.class);
        String mockedOtherCertificateDigest = "AB12343BF";
        String mockedOtherCertificateAlgorithm = "RSA-256";
        List<SignatureCertificate> mockedOtherCertificates = new ArrayList<>();
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        mockedOtherCertificates.add(mockedCertificate);
        mockedOtherCertificates.add(mockedCertificate);
        boolean[] mockedIssuer = new boolean[]{false,false,false};
        BigInteger mockedSerialNumber = mock(BigInteger.class);
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        
        /* Calls to mocks */
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(mockedSigningCertificate);
        Mockito.when(mockedSigningCertificate.getSignerCertificate(this.signerDocumentMock)).thenReturn(null);
        Mockito.when(mockedSigningCertificate.getOtherCertificates()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedCertificate.getEncoded()).thenReturn(mockedOtherCertificateDigest);
        Mockito.when(mockedCertificate.getSigAlgName()).thenReturn(mockedOtherCertificateAlgorithm);
        Mockito.when(mockedSigningCertificate.applyDigest(mockedOtherCertificateDigest, mockedOtherCertificateAlgorithm)).thenReturn(false).thenReturn(true);
        Mockito.when(mockedCertificate.getIssuerUniqueID()).thenReturn(mockedIssuer);
        Mockito.when(mockedSigningCertificate.getIssuerUniqueID()).thenReturn(mockedIssuer);
        Mockito.when(mockedCertificate.getSerialNumber()).thenReturn(mockedSerialNumber);
        Mockito.when(mockedSigningCertificate.getSerialNumber()).thenReturn(mockedSerialNumber);
        Mockito.when(this.signatureValidationPoliciesMock.getId()).thenReturn(null);
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(false);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 04
    * 
    * Description:
    * Verify that a Signing Certificate is not identified when no Signing Certificate is provided as input, the Signers Certificate is not identified from Signature and the Signing Certificate has no references
    * 
    * Inputs:
    * signingCertificateMock is not null
    *
    * Outputs:
    * validationResult is INDETERMINATE, NO_SIGNING_CERTIFICATE_FOUND
    */
    @Test
    public void test_04_InputSigningCertificateNoSignerCertificateFoundNoReferences() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        
        /* Calls to mocks */
        Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(null);
        Mockito.when(this.signingCertificateMock.getOtherCertificates()).thenReturn(new ArrayList<>());
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, validationResult.getSubIndication());

    }
    
    /*
    * TEST 05
    * 
    * Description:
    * Verify that a Signing Certificate is identified when no Signing Certificate is provided as input, the Signers Certificate is identified from Signature but it is invalid and the Signing Certificate obtained from Signature has a valid reference
    * Verify that validation stops when the policy can be obtained but not parsed properly
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is not null
    *
    * Outputs:
    * validationResult is INDETERMINATE, POLICY_PROCESSING_ERROR
    */
    @Test
    public void test_05_InvalidSignerCertificateSigningCertificateReferenceFound_PolicyDocumentNotParsed() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = mock(PolicyIdentifier.class);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        String mockedCertificateDigest = "AB12343BF";
        String mockedCertificateAlgorithm = "RSA-256";
        List<SignatureCertificate> mockedOtherCertificates = new ArrayList<>();
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        mockedOtherCertificates.add(mockedCertificate);
        ObjectIdentifier mockedObjectIdentifier = mock(ObjectIdentifier.class);
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);

        /* Calls to mocks */
        Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
        Mockito.when(mockedCertificate.getEncoded()).thenReturn(mockedCertificateDigest);
        Mockito.when(this.signatureMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedCertificate.getSigAlgName()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(this.signingCertificateMock.applyDigest(mockedCertificateDigest, mockedCertificateAlgorithm)).thenReturn(false).thenReturn(true);
        Mockito.when(this.signingCertificateMock.getOtherCertificates()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedCertificate.getIssuerUniqueID()).thenReturn(null);
        Mockito.when(mockedCertificate.getSerialNumber()).thenReturn(null);
        Mockito.when(this.signatureValidationPoliciesMock.getId()).thenReturn(mockedObjectIdentifier);
        Mockito.when(this.signatureValidationPoliciesMock.getHash()).thenReturn(null);
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(false);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.POLICY_PROCESSING_ERROR, validationResult.getSubIndication());

    }
    
    /*
    * TEST 06
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that validation stops when the policy can be obtained but the digest computed from the policy is not equal to the signature digest
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is not null
    *
    * Outputs:
    * validationResult is INDETERMINATE, POLICY_PROCESSING_ERROR
    */
    @Test
    public void test_06_SigningCertificateFound_InvalidPolicyDocumentDigest() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = mock(PolicyIdentifier.class);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        String mockedCertificateDigest = "AB12343FAA";
        String mockedCertificateDigest2 = "AB12343BF";
        String mockedCertificateAlgorithm = "RSA-256";
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        ObjectIdentifier mockedObjectIdentifier = mock(ObjectIdentifier.class);
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        
        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        Mockito.when(this.signatureValidationPoliciesMock.getId()).thenReturn(mockedObjectIdentifier);
        Mockito.when(this.signatureValidationPoliciesMock.getHash()).thenReturn(null);
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(this.signatureMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(this.signatureMock)).thenReturn(mockedCertificateDigest2);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.POLICY_PROCESSING_ERROR, validationResult.getSubIndication());

    }
    
    /*
    * TEST 07
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is considered as valid when is it the fourth allowed policy
    * Verify that validation stops when the path validation model of the chain of certificates gives null as a result
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is not null
    * allowableValidationPolicyIdsMock has 4 policies
    *
    * Outputs:
    * validationResult is INDETERMINATE, CERTIFICATE_CHAIN_GENERAL_FAILURE
    */
    @Test
    public void test_07_SigningCertificateFound_InputPolicyValid_NullPathValidationModel() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = mock(PolicyIdentifier.class);
        this.allowableValidationPolicyIdsMock = new ArrayList<>();
        ObjectIdentifier mockedObjectIdentifier = mock(ObjectIdentifier.class);
        this.allowableValidationPolicyIdsMock.add(mockedObjectIdentifier);
        this.allowableValidationPolicyIdsMock.add(mockedObjectIdentifier);
        this.allowableValidationPolicyIdsMock.add(mockedObjectIdentifier);
        this.allowableValidationPolicyIdsMock.add(mockedObjectIdentifier);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        String mockedCertificateDigest = "AB12343BF";
        String mockedCertificateAlgorithm = "RSA-256";
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        DigestAlgorithm mockedHash = mock(DigestAlgorithm.class);
        String mockedIdentifier1 = "1";
        String mockedIdentifier2 = "2";
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        
        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        Mockito.when(this.signatureValidationPoliciesMock.getId()).thenReturn(mockedObjectIdentifier);
        Mockito.when(this.signatureValidationPoliciesMock.getHash()).thenReturn(mockedHash);
        Mockito.when(mockedObjectIdentifier.getIdentifier()).thenReturn(null).thenReturn(mockedIdentifier1).thenReturn(null)
                                                            .thenReturn(mockedIdentifier1).thenReturn(mockedIdentifier2)
                                                            .thenReturn(mockedIdentifier1).thenReturn(mockedIdentifier2)
                                                            .thenReturn(mockedIdentifier1).thenReturn(mockedIdentifier1)
                                                            .thenReturn(mockedIdentifier1).thenReturn(mockedIdentifier1);
        Mockito.when(this.signatureValidationPoliciesMock.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(this.signatureValidationPoliciesMock.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(this.signatureMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(this.signatureValidationPoliciesMock.applySignatureTransforms(this.signatureMock)).thenReturn(mockedCertificateDigest);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(this.signatureValidationPoliciesMock.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.SHELL_MODEL);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.SHELL_MODEL)).thenReturn(null);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 08
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives SIGNING_CERTIFICATE_REVOKED as a result
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is not null
    * allowableValidationPolicyIdsMock has 1 policy
    *
    * Outputs:
    * validationResult is INDETERMINATE, REVOKED_NO_POE
    */
    @Test
    public void test_08_SigningCertificateFound_InputPolicyInvalid_SigningCertificateRevoked() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = mock(PolicyIdentifier.class);
        this.allowableValidationPolicyIdsMock = new ArrayList<>();
        ObjectIdentifier mockedObjectIdentifier = mock(ObjectIdentifier.class);
        this.allowableValidationPolicyIdsMock.add(mockedObjectIdentifier);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        String mockedCertificateDigest = "AB12343BF";
        String mockedCertificateAlgorithm = "RSA-256";
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        DigestAlgorithm mockedHash = mock(DigestAlgorithm.class);
        String mockedIdentifier1 = "1";
        String mockedIdentifier2 = "2";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.SIGNING_CERTIFICATE_REVOKED;
        
        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        Mockito.when(this.signatureValidationPoliciesMock.getId()).thenReturn(mockedObjectIdentifier);
        Mockito.when(this.signatureValidationPoliciesMock.getHash()).thenReturn(mockedHash);
        Mockito.when(mockedObjectIdentifier.getIdentifier()).thenReturn(mockedIdentifier1).thenReturn(mockedIdentifier2)
                                                            .thenReturn(mockedIdentifier1).thenReturn(mockedIdentifier2);
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(this.signatureMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(this.signatureMock)).thenReturn(mockedCertificateDigest);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.REVOKED_NO_POE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 09
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives INTERMEDIATE_CA_REVOKED as a result
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    *
    * Outputs:
    * validationResult is INDETERMINATE, REVOKED_CA_NO_POE
    */
    @Test
    public void test_09_SigningCertificateFound_InputPolicyInvalid_IntermediateCertificateRevoked() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
         /* Initialize local mocked variables */
        String mockedCertificateDigest = "AB12343BF";
        String mockedCertificateAlgorithm = "RSA-256";
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.INTERMEDIATE_CA_REVOKED;

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.REVOKED_CA_NO_POE, validationResult.getSubIndication());

    }
    
    
    /**************************************************************
     ********************* SUPPORT FUNCTIONS **********************
     *************************************************************/
    private void identifySigningCertificateForcePassed(SignatureCertificate mockedCertificate, String mockedCertificateDigest, String mockedCertificateAlgorithm) {
        Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
        Mockito.when(mockedCertificate.getEncoded()).thenReturn(mockedCertificateDigest);
        Mockito.when(this.signatureMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(this.signingCertificateMock.applyDigest(mockedCertificateDigest, mockedCertificateAlgorithm)).thenReturn(true);
    }
    
    private void initializeValidationContextForcePassed(PolicyIdentifier mockedPolicyIdentifier, String mockedCertificateDigest) {
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(this.signatureMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(this.signatureMock)).thenReturn(mockedCertificateDigest);
    }
}
