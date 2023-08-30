package edu.upc.etsetb.tfm.xml_signature_validation.signature;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.Indication;
import edu.upc.etsetb.tfm.xml_signature_validation.report.entities.SubIndication;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.PKIXCertificationPathVerifier.PathValidationStatus;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.CryptographicConstraints;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.SignatureElementConstraints;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints;
import edu.upc.etsetb.tfm.xml_signature_validation.signature.entities.signature_validation_policies.validation_constraints.X509ValidationConstraints.ValidationModel;
import edu.upc.etsetb.tfm.xml_signature_validation.validation.entities.BasicSignatureValidator;
import java.math.BigInteger;
import java.security.PublicKey;
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
        String mockedSignerCertificateDigest = "BQUF";
        String mockedSignerCertificateAlgorithm = "RSA-256";
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
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
        Mockito.when(mockedPolicyIdentifier.getHash()).thenReturn(mockedDigestAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getValue()).thenReturn(mockedPolicyHashValue);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(signatureMock)).thenReturn(mockedSignerCertificateDigest);
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
        String mockedCertificateAlgorithm = "RSA-256";
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        ObjectIdentifier mockedObjectIdentifier = mock(ObjectIdentifier.class);
        
        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        Mockito.when(this.signatureValidationPoliciesMock.getId()).thenReturn(mockedObjectIdentifier);
        Mockito.when(this.signatureValidationPoliciesMock.getHash()).thenReturn(null);
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getHash()).thenReturn(mockedDigestAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getValue()).thenReturn(mockedPolicyHashValue);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(signatureMock)).thenReturn(mockedCertificateDigest);
        
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
        String mockedCertificateDigest = "AB12343FAA";
        String mockedCertificateAlgorithm = "RSA-256";
        String mockedCertificateDigest2 = "BQUF";
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
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
        Mockito.when(signatureValidationPoliciesMock.getHash()).thenReturn(mockedDigestAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getValue()).thenReturn(mockedPolicyHashValue);
        Mockito.when(signatureValidationPoliciesMock.applySignatureTransforms(signatureMock)).thenReturn(mockedCertificateDigest2);
        
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
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
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
        Mockito.when(mockedPolicyIdentifier.getHash()).thenReturn(mockedDigestAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getValue()).thenReturn(mockedPolicyHashValue);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(signatureMock)).thenReturn(mockedCertificateDigest);
        
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
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.INTERMEDIATE_CA_REVOKED;

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
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
    
    /*
    * TEST 10
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives OTHER as a result
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    *
    * Outputs:
    * validationResult is INDETERMINATE, CERTIFICATE_CHAIN_GENERAL_FAILURE
    */
    @Test
    public void test_10_SigningCertificateFound_InputPolicyInvalid_ChainGeneralFailure() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.OTHER;

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 11
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result and a certificate in the chain is not fresh because the issuance time is before maximum accepted time
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, TRY_LATER
    */
    @Test
    public void test_11_SigningCertificateFound_InputPolicyInvalid_CertificateBeforeMaximumAcceptedTime() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(100);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.TRY_LATER, validationResult.getSubIndication());

    }
    
    /*
    * TEST 12
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result, all certificates in the chain are fresh and the chain is not compliant with the constraints
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, CHAIN_CONSTRAINTS_FAILURE
    */
    @Test
    public void test_12_SigningCertificateFound_InputPolicyInvalid_CertificateAfterMaximumAcceptedTimeAndChainX509ConstraintsFailure() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(false);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 13
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result, and a certificate in the chain is not fresh because the issuance time is before maximum accepted time
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, TRY_LATER
    */
    @Test
    public void test_13_SigningCertificateFound_InputPolicyInvalid_CertificateAfterMaximumAcceptedTimeAndNoMaximumAcceptedRevocationFreshness() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = null;
        Date mockedNextUpdate = new Date(800);
        Date mockedThisUpdate = new Date(200);
        Date mockedIssuanceDate = new Date(500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedRevocationStatusInformation.getNextUpdate()).thenReturn(mockedNextUpdate);
        Mockito.when(mockedRevocationStatusInformation.getThisUpdate()).thenReturn(mockedThisUpdate);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.TRY_LATER, validationResult.getSubIndication());

    }
    
    /*
    * TEST 14
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result, all certificates in the chain are fresh and the chain is not compliant with the cryptographic constraints
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE
    */
    @Test
    public void test_14_SigningCertificateFound_InputPolicyInvalid_CertificateBeforeMaximumAcceptedTimeAndNoMaximumAcceptedRevocationFreshnessAndChainCryptoConstraintsFailure() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
         /* Initialize local mocked variables */
         byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = null;
        Date mockedNextUpdate = new Date(800);
        Date mockedThisUpdate = new Date(200);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedRevocationStatusInformation.getNextUpdate()).thenReturn(mockedNextUpdate);
        Mockito.when(mockedRevocationStatusInformation.getThisUpdate()).thenReturn(mockedThisUpdate);
        Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
        Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(false);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 15
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result and a certificate in the chain has no issuance time.
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, TRY_LATER
    */
    @Test
    public void test_15_SigningCertificateFound_InputPolicyInvalid_CertificateNoIssuanceTime() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
         /* Initialize local mocked variables */
         byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = null;
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.TRY_LATER, validationResult.getSubIndication());

    }
    
    /*
    * TEST 16
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result, a certificate in the chain has no issuance time and there is no maximum accepted revocation freshness.
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, TRY_LATER
    */
    @Test
    public void test_16_SigningCertificateFound_InputPolicyInvalid_CertificateNoMaximumRevocationFreshnessAndNoIssuanceTime() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
         /* Initialize local mocked variables */
         byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = null;
        Date mockedIssuanceDate = null;
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.TRY_LATER, validationResult.getSubIndication());

    }
    
    /*
    * TEST 17
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result, a certificate in the chain has no NextUpdate parameter and there is no maximum accepted revocation freshness.
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, TRY_LATER
    */
    @Test
    public void test_17_SigningCertificateFound_InputPolicyInvalid_CertificateNoMaximumRevocationFreshnessAndNoNextUpdate() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
         /* Initialize local mocked variables */
         byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = null;
        Date mockedIssuanceDate = new Date(1000);
        Date mockedNextUpdate = null;
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedRevocationStatusInformation.getNextUpdate()).thenReturn(mockedNextUpdate);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.TRY_LATER, validationResult.getSubIndication());

    }
    
    /*
    * TEST 18
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result, a certificate in the chain has no ThisUpdate parameter and there is no maximum accepted revocation freshness.
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, TRY_LATER
    */
    @Test
    public void test_18_SigningCertificateFound_InputPolicyInvalid_CertificateNoMaximumRevocationFreshnessAndNoThisUpdate() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
         /* Initialize local mocked variables */
         byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = null;
        Date mockedIssuanceDate = new Date(1000);
        Date mockedNextUpdate = new Date(200);
        Date mockedThisUpdate = null;
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedRevocationStatusInformation.getNextUpdate()).thenReturn(mockedNextUpdate);
        Mockito.when(mockedRevocationStatusInformation.getThisUpdate()).thenReturn(mockedThisUpdate);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.TRY_LATER, validationResult.getSubIndication());

    }
    
    /*
    * TEST 19
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that validation stops when the path validation model of the chain of certificates gives VALID as a result, and the issuance time plus validity range is before validation time
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, OUT_OF_BOUNDS_NO_POE
    */
    @Test
    public void test_19_SigningCertificateFound_InputPolicyInvalid_InvalidValidityRange() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
         /* Initialize local mocked variables */
         byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(400);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
        Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 20
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that the chain of certificates is valid
    * Verify that validation stops when signed data object properties are not obtainable
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, SIGNED_DATA_NOT_FOUND
    */
    @Test
    public void test_20_SigningCertificateFound_InputPolicyInvalid_ValidChain_NoDataObjectProperties() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(600);
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedDataObjectProperties mockedSignedDataObjectProperties = null;

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
        Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, validationResult.getSubIndication());

    }
    
    /*
    * TEST 21
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that the chain of certificates is valid
    * Verify that validation stops when signed data objects are not obtainable
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, SIGNED_DATA_NOT_FOUND
    */
    @Test
    public void test_21_SigningCertificateFound_InputPolicyInvalid_ValidChain_NoDataObjects() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(600);
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedDataObjectProperties mockedSignedDataObjectProperties = mock(SignedDataObjectProperties.class);
        List<SignedDataObject> mockedSignedDataObjects = null;

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange);
        
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
       
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, validationResult.getSubIndication());

    }
    
    /*
    * TEST 22
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that the chain of certificates is valid
    * Verify that validation stops when a signed data object intergrity check fails
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, HASH_FAILURE
    */
    @Test
    public void test_22_SigningCertificateFound_InputPolicyInvalid_ValidChain_ObjectIntegrityFailure() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(600);
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedDataObjectProperties mockedSignedDataObjectProperties = mock(SignedDataObjectProperties.class);
        List<SignedDataObject> mockedSignedDataObjects = new ArrayList<>();
        SignedDataObject mockedSignedDataObject = mock(SignedDataObject.class);
        mockedSignedDataObjects.add(mockedSignedDataObject);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange);
        
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
        Mockito.when(mockedSignedDataObject.checkIntegrity()).thenReturn(false);
       
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.FAILED, validationResult.getValue());
        Assert.assertEquals(SubIndication.HASH_FAILURE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 23
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that the chain of certificates is valid
    * Verify that validation stops when signature value check fails
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is FAILED, SIG_CRYPTO_FAILURE
    */
    @Test
    public void test_23_SigningCertificateFound_InputPolicyInvalid_ValidChain_InvalidSignatureValue() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(600);
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedDataObjectProperties mockedSignedDataObjectProperties = mock(SignedDataObjectProperties.class);
        List<SignedDataObject> mockedSignedDataObjects = new ArrayList<>();
        SignedDataObject mockedSignedDataObject = mock(SignedDataObject.class);
        mockedSignedDataObjects.add(mockedSignedDataObject);
        PublicKey mockedPublicKey = mock(PublicKey.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange);
        
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
        Mockito.when(mockedSignedDataObject.checkIntegrity()).thenReturn(true);
        Mockito.when(signingCertificateMock.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(signatureMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(signatureMock.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(false);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.FAILED, validationResult.getValue());
        Assert.assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 24
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that the chain of certificates is valid
    * Verify that cryptographic verification succeeds
    * Verify that validation stops when a deprecated algorithm is detected
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE
    */
    @Test
    public void test_24_SigningCertificateFound_InputPolicyInvalid_ValidChain_DeprecatedAlgorithm() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(600);
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedDataObjectProperties mockedSignedDataObjectProperties = mock(SignedDataObjectProperties.class);
        List<SignedDataObject> mockedSignedDataObjects = new ArrayList<>();
        SignedDataObject mockedSignedDataObject = mock(SignedDataObject.class);
        mockedSignedDataObjects.add(mockedSignedDataObject);
        PublicKey mockedPublicKey = mock(PublicKey.class);
        List<String> mockedSignatureAlgorithms = new ArrayList<>();
        mockedSignatureAlgorithms.add(mockedCertificateAlgorithm);
        SignedSignatureProperties mockedSignedSignatureProperties = mock(SignedSignatureProperties.class);
        List<TimeStamp> mockedTimeStamps = new ArrayList<>();
        TimeStamp mockedTimeStamp = mock(TimeStamp.class);
        mockedTimeStamps.add(mockedTimeStamp);
        UnsignedProperties mockedUnsignedProperties = mock(UnsignedProperties.class);
        List<SignatureCertificate> mockedOtherCertificates = new ArrayList<>();
        SignatureCertificate mockedOtherCertificate = mock(SignatureCertificate.class);
        mockedOtherCertificates.add(mockedOtherCertificate);
        RevocationValues mockedRevocationValues = mock(RevocationValues.class);
        List<EncapsulatedPKIData> mockedCRLValues = new ArrayList<>();
        EncapsulatedPKIData mockedEncapsulatedPKIData = mock(EncapsulatedPKIData.class);
        mockedCRLValues.add(mockedEncapsulatedPKIData);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange);
        
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
        Mockito.when(mockedSignedDataObject.checkIntegrity()).thenReturn(true);
        Mockito.when(signingCertificateMock.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(signatureMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(signatureMock.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
        Mockito.when(signatureMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(signingCertificateMock);
        Mockito.when(mockedPublicKey.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getAllDataObjectsTimestamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedTimeStamp.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getIndividualDataObjectsTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(signatureMock.getUnsignedProperties()).thenReturn(mockedUnsignedProperties);
        Mockito.when(mockedUnsignedProperties.getArchiveTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedUnsignedProperties.getCertificateValues()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedOtherCertificate.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedUnsignedProperties.getRevocationValues()).thenReturn(mockedRevocationValues);
        Mockito.when(mockedRevocationValues.getCRLValues()).thenReturn(mockedCRLValues);
        Mockito.when(mockedEncapsulatedPKIData.getCertificate()).thenReturn(mockedOtherCertificate);
        Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, validationTimeMock)).thenReturn(false);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 25
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that the chain of certificates is valid
    * Verify that cryptographic verification succeeds
    * Verify that validation stops when a mandatory attribute is missing
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is INDETERMINATE, SIG_CONSTRAINTS_FAILURE
    */
    @Test
    public void test_25_SigningCertificateFound_InputPolicyInvalid_ValidChain_MissingMandatoryAttribute() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(600);
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedDataObjectProperties mockedSignedDataObjectProperties = mock(SignedDataObjectProperties.class);
        List<SignedDataObject> mockedSignedDataObjects = new ArrayList<>();
        SignedDataObject mockedSignedDataObject = mock(SignedDataObject.class);
        mockedSignedDataObjects.add(mockedSignedDataObject);
        PublicKey mockedPublicKey = mock(PublicKey.class);
        SignedSignatureProperties mockedSignedSignatureProperties = mock(SignedSignatureProperties.class);
        List<TimeStamp> mockedTimeStamps = new ArrayList<>();
        TimeStamp mockedTimeStamp = mock(TimeStamp.class);
        mockedTimeStamps.add(mockedTimeStamp);
        UnsignedProperties mockedUnsignedProperties = mock(UnsignedProperties.class);
        List<SignatureCertificate> mockedOtherCertificates = new ArrayList<>();
        SignatureCertificate mockedOtherCertificate = mock(SignatureCertificate.class);
        mockedOtherCertificates.add(mockedOtherCertificate);
        RevocationValues mockedRevocationValues = mock(RevocationValues.class);
        List<EncapsulatedPKIData> mockedCRLValues = new ArrayList<>();
        EncapsulatedPKIData mockedEncapsulatedPKIData = mock(EncapsulatedPKIData.class);
        mockedCRLValues.add(mockedEncapsulatedPKIData);
        SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange);
        cryptographicVerificationForcePassed(mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
        
        Mockito.when(signatureMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(signingCertificateMock);
        Mockito.when(mockedPublicKey.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getAllDataObjectsTimestamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedTimeStamp.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getIndividualDataObjectsTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(signatureMock.getUnsignedProperties()).thenReturn(mockedUnsignedProperties);
        Mockito.when(mockedUnsignedProperties.getArchiveTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedUnsignedProperties.getCertificateValues()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedOtherCertificate.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedUnsignedProperties.getRevocationValues()).thenReturn(mockedRevocationValues);
        Mockito.when(mockedRevocationValues.getCRLValues()).thenReturn(mockedCRLValues);
        Mockito.when(mockedEncapsulatedPKIData.getCertificate()).thenReturn(mockedOtherCertificate);
        Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, validationTimeMock)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getSignatureElementConstraints()).thenReturn(mockedSignatureElementConstraints);
        Mockito.when(mockedSignatureElementConstraints.containsMissingElement(signatureMock)).thenReturn(false);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
        Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationResult.getSubIndication());

    }
    
    /*
    * TEST 26
    * 
    * Description:
    * Verify that a Signing Certificate is identified when Signing Certificate is provided as input, the Signers Certificate is identified from Signature and it is valid
    * Verify that input policy is not in the allowable policies list and the default validation is used instead
    * Verify that the chain of certificates is valid
    * Verify that cryptographic verification succeeds
    * Verify that validation ends with a valid result when a mandatory attributes are not missing
    *
    * Inputs:
    * signingCertificateMock is not null
    * signatureValidationPoliciesMock is null
    * validationTimeMock is 2000 milliseconds after standard base time
    *
    * Outputs:
    * validationResult is PASSED
    */
    @Test
    public void test_26_ValidBasicSignature() {
        /* Initialize mocked class variables */
        this.signingCertificateMock = mock(SignatureCertificate.class);
        this.signatureValidationPoliciesMock = null;
        this.validationTimeMock = new Date(2000);
        this.instance = BasicSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, chainPathVerifierMock);
        
        /* Initialize local mocked variables */
        byte[] mockedPolicyHashValue = new byte[]{(byte)5,(byte)5,(byte)5};
        DigestAlgorithm mockedDigestAlgorithm = mock(DigestAlgorithm.class);
        String mockedCertificateDigest = "BQUF";
        String mockedCertificateAlgorithm = "RSA-256";
        PolicyIdentifier mockedPolicyIdentifier = mock(PolicyIdentifier.class);
        SignatureCertificate mockedCertificate = mock(SignatureCertificate.class);
        List<SignatureCertificate> mockedChain = new ArrayList<>();
        mockedChain.add(mockedCertificate);
        X509ValidationConstraints mockedX09ValidationContraints = mock(X509ValidationConstraints.class);
        CryptographicConstraints mockedCryptographicConstraints = mock(CryptographicConstraints.class);
        PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
        Date mockedMaximumAcceptedRevocationFreshness = new Date(1000);
        Date mockedIssuanceDate = new Date(1500);
        RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
        Date mockedValidityRange = new Date(600);
        SignedProperties mockedSignedProperties = mock(SignedProperties.class);
        SignedDataObjectProperties mockedSignedDataObjectProperties = mock(SignedDataObjectProperties.class);
        List<SignedDataObject> mockedSignedDataObjects = new ArrayList<>();
        SignedDataObject mockedSignedDataObject = mock(SignedDataObject.class);
        mockedSignedDataObjects.add(mockedSignedDataObject);
        PublicKey mockedPublicKey = mock(PublicKey.class);
        SignedSignatureProperties mockedSignedSignatureProperties = mock(SignedSignatureProperties.class);
        List<TimeStamp> mockedTimeStamps = new ArrayList<>();
        TimeStamp mockedTimeStamp = mock(TimeStamp.class);
        mockedTimeStamps.add(mockedTimeStamp);
        UnsignedProperties mockedUnsignedProperties = mock(UnsignedProperties.class);
        List<SignatureCertificate> mockedOtherCertificates = new ArrayList<>();
        SignatureCertificate mockedOtherCertificate = mock(SignatureCertificate.class);
        mockedOtherCertificates.add(mockedOtherCertificate);
        RevocationValues mockedRevocationValues = mock(RevocationValues.class);
        List<EncapsulatedPKIData> mockedCRLValues = new ArrayList<>();
        EncapsulatedPKIData mockedEncapsulatedPKIData = mock(EncapsulatedPKIData.class);
        mockedCRLValues.add(mockedEncapsulatedPKIData);
        SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);

        /* Calls to mocks */
        identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
        initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
        validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange);
        cryptographicVerificationForcePassed(mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
        
        Mockito.when(signatureMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(signingCertificateMock);
        Mockito.when(mockedPublicKey.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getAllDataObjectsTimestamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedTimeStamp.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getIndividualDataObjectsTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(signatureMock.getUnsignedProperties()).thenReturn(mockedUnsignedProperties);
        Mockito.when(mockedUnsignedProperties.getArchiveTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedUnsignedProperties.getCertificateValues()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedOtherCertificate.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedUnsignedProperties.getRevocationValues()).thenReturn(mockedRevocationValues);
        Mockito.when(mockedRevocationValues.getCRLValues()).thenReturn(mockedCRLValues);
        Mockito.when(mockedEncapsulatedPKIData.getCertificate()).thenReturn(mockedOtherCertificate);
        Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, validationTimeMock)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getSignatureElementConstraints()).thenReturn(mockedSignatureElementConstraints);
        Mockito.when(mockedSignatureElementConstraints.containsMissingElement(signatureMock)).thenReturn(true);
        
        /* Function to test */
        Indication validationResult = this.instance.validate(false);
        
        /* Verify function calls */
        
        /* Verify tested function output */
        Assert.assertEquals(Indication.PASSED, validationResult.getValue());

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
    
    private void initializeValidationContextForcePassed(PolicyIdentifier mockedPolicyIdentifier, String mockedCertificateDigest, byte[] mockedPolicyHashValue, DigestAlgorithm mockedDigestAlgorithm) {
        
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getHash()).thenReturn(mockedDigestAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getValue()).thenReturn(mockedPolicyHashValue);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(signatureMock)).thenReturn(mockedCertificateDigest);
    }
    
    private void validateX509CertificateForcePassed(List<SignatureCertificate> mockedChain, PolicyIdentifier mockedPolicyIdentifier, X509ValidationConstraints mockedX09ValidationContraints, PathValidationStatus mockedPathValidationStatus, Date mockedMaximumAcceptedRevocationFreshness, SignatureCertificate mockedCertificate, RevocationStatusInformation mockedRevocationStatusInformation, Date mockedIssuanceDate, CryptographicConstraints mockedCryptographicConstraints, Date mockedValidityRange) {
        Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
        Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
    }
    
    private void cryptographicVerificationForcePassed(SignedProperties mockedSignedProperties, SignedDataObjectProperties mockedSignedDataObjectProperties, List<SignedDataObject> mockedSignedDataObjects, PublicKey mockedPublicKey, String mockedCertificateDigest, String mockedCertificateAlgorithm) {
        Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
        Mockito.when(mockedSignedDataObjects.get(0).checkIntegrity()).thenReturn(true);
        Mockito.when(signingCertificateMock.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(signatureMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(signatureMock.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
        
    }
    
    private void validateSignatureAcceptance(String mockedCertificateAlgorithm, DigestAlgorithm mockedDigestAlgorithm, SignedProperties mockedSignedProperties, SignedSignatureProperties mockedSignedSignatureProperties, PublicKey mockedPublicKey, SignedDataObjectProperties mockedSignedDataObjectProperties, List<TimeStamp> mockedTimeStamps, TimeStamp mockedTimeStamp, UnsignedProperties mockedUnsignedProperties, List<SignatureCertificate> mockedOtherCertificates, SignatureCertificate mockedOtherCertificate, RevocationValues mockedRevocationValues, List<EncapsulatedPKIData> mockedCRLValues, EncapsulatedPKIData mockedEncapsulatedPKIData, CryptographicConstraints mockedCryptographicConstraints, PolicyIdentifier mockedPolicyIdentifier, SignatureElementConstraints mockedSignatureElementConstraints) {
        Mockito.when(signatureMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(signingCertificateMock);
        Mockito.when(mockedPublicKey.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getAllDataObjectsTimestamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedTimeStamp.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getIndividualDataObjectsTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(signatureMock.getUnsignedProperties()).thenReturn(mockedUnsignedProperties);
        Mockito.when(mockedUnsignedProperties.getArchiveTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedUnsignedProperties.getCertificateValues()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedOtherCertificate.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedUnsignedProperties.getRevocationValues()).thenReturn(mockedRevocationValues);
        Mockito.when(mockedRevocationValues.getCRLValues()).thenReturn(mockedCRLValues);
        Mockito.when(mockedEncapsulatedPKIData.getCertificate()).thenReturn(mockedOtherCertificate);
        Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, validationTimeMock)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getSignatureElementConstraints()).thenReturn(mockedSignatureElementConstraints);
        Mockito.when(mockedSignatureElementConstraints.containsMissingElement(signatureMock)).thenReturn(true);
    }
}