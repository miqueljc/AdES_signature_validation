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
import edu.upc.etsetb.tfm.xml_signature_validation.validation.entities.LTSignatureValidator;
import edu.upc.etsetb.tfm.xml_signature_validation.validation.entities.TimeStampValidator;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.TrustAnchor;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.tsp.TSTInfo;
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
public class LTSignatureValidatorTest {
    
    @InjectMocks
    private LTSignatureValidator instance;
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
    private Date signatureExistenceMock;
    @Mock
    private PKIXCertificationPathVerifier chainPathVerifierMock;
    @Mock
    private Date bestSignatureTimeMock;
    @Mock
    private List<TimeStamp> signatureTimestampsMocks;
    
    public LTSignatureValidatorTest() {
        
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
    * Verify that Basic Signature Validation returns FAILED
    * 
    * Outputs:
    * validationResult is FAILED
    */
    @Test
    public void test_01_BasicSignatureValidationCopyFailure() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(2000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);

            Mockito.when(this.signatureMock.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
            Mockito.when(mockedSignedDataObject.checkIntegrity()).thenReturn(false);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.FAILED, validationResult.getValue());
            Assert.assertEquals(SubIndication.HASH_FAILURE, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 02
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that algorithm is not reliable at best-signature-time
    * 
    * Outputs:
    * validationResult is INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE
    */
    @Test
    public void test_02_BasicSignatureValidationCryptoConstraints_AlgorithmNotReliable() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(1500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedTime = mock(DERGeneralizedTime.class);
            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(false).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedTSTInfo);
            Mockito.when(mockedTSTInfo.getGenTime()).thenReturn(mockedTime);
            Mockito.when(mockedTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true).thenReturn(false);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
            Assert.assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 03
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that algorithm is reliable at best-signature-time and that the signature timestamps are not coherent
    * 
    * Outputs:
    * validationResult is INDETERMINATE, TIMESTAMP_ORDER_FAILURE
    */
    @Test
    public void test_03_BasicSignatureValidationCryptoConstraints_TimestampsNotCoherent() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(1500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            TSTInfo mockedSignedTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignedTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedSignedTimeStampGenDate = new Date(3100);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(false).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);

            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(mockedTimeStamp.getTSTInfo()).thenReturn(mockedSignedTimeStampTSTInfo);
            Mockito.when(mockedSignedTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignedTimeStampTime);
            Mockito.when(mockedSignedTimeStampTime.getDate()).thenReturn(mockedSignedTimeStampGenDate);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
            Assert.assertEquals(SubIndication.TIMESTAMP_ORDER_FAILURE, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 04
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, REVOKED_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that signing certificate expired before best-signature-time
    * 
    * Outputs:
    * validationResult is INDETERMINATE, REVOKED_NO_POE
    */
    @Test
    public void test_04_BasicSignatureValidationNoPOE_SigningCertificateExpired() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            PathValidationStatus mockedPathValidationStatusInvalid = PathValidationStatus.SIGNING_CERTIFICATE_REVOKED;
            PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(1500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            RevocationStatusInformation mockedChainRevocationInformation = mock(RevocationStatusInformation.class);
            Date mockedExpiredCertsDate = new Date(2900);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatusInvalid);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(chainPathVerifierMock.getRevocationStatusInformation()).thenReturn(mockedChainRevocationInformation);
            Mockito.when(mockedChainRevocationInformation.getExpiredCertsOnCRL()).thenReturn(mockedExpiredCertsDate);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
            Assert.assertEquals(SubIndication.REVOKED_NO_POE, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 05
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, REVOKED_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that a signature time-stamp is generated before best-signature-time minus the delay when delay is needed
    * 
    * Outputs:
    * validationResult is INDETERMINATE, SIG_CONSTRAINTS_FAILURE
    */
    @Test
    public void test_05_BasicSignatureValidationNoPOE_DelayActiveInvalidGenTime() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            PathValidationStatus mockedPathValidationStatusInvalid = PathValidationStatus.SIGNING_CERTIFICATE_REVOKED;
            PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(1500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            RevocationStatusInformation mockedChainRevocationInformation = mock(RevocationStatusInformation.class);
            Date mockedExpiredCertsDate = new Date(3100);
            TSTInfo mockedSignedTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignedTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedSignedTimeStampGenDate = new Date(2900);
            long mockedDelay = -50;

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatusInvalid);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(chainPathVerifierMock.getRevocationStatusInformation()).thenReturn(mockedChainRevocationInformation);
            Mockito.when(mockedChainRevocationInformation.getExpiredCertsOnCRL()).thenReturn(mockedExpiredCertsDate);
            
            Mockito.when(mockedTimeStamp.getTSTInfo()).thenReturn(mockedSignedTimeStampTSTInfo);
            Mockito.when(mockedSignedTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignedTimeStampTime);
            Mockito.when(mockedSignedTimeStampTime.getDate()).thenReturn(mockedSignedTimeStampGenDate);
            Mockito.when(mockedSignatureElementConstraints.isTimeStampDelayNeeded()).thenReturn(true);
            Mockito.when(mockedSignatureTimeStamp.hasDelay()).thenReturn(true);
            Mockito.when(mockedSignatureTimeStamp.getDelayMs()).thenReturn(mockedDelay);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
            Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 06
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, REVOKED_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that CA certificate expired before best-signature-time
    * 
    * Outputs:
    * validationResult is INDETERMINATE, REVOKED_CA_NO_POE
    */
    @Test
    public void test_06_BasicSignatureValidationCANoPOE_CACertificateExpired() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            PathValidationStatus mockedPathValidationStatusInvalid = PathValidationStatus.INTERMEDIATE_CA_REVOKED;
            PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(1500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            RevocationStatusInformation mockedChainRevocationInformation = mock(RevocationStatusInformation.class);
            Date mockedExpiredCertsDate = new Date(2900);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatusInvalid);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(chainPathVerifierMock.getRevocationStatusInformation()).thenReturn(mockedChainRevocationInformation);
            Mockito.when(mockedChainRevocationInformation.getExpiredCertsOnCRL()).thenReturn(mockedExpiredCertsDate);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
            Assert.assertEquals(SubIndication.REVOKED_CA_NO_POE, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 07
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, REVOKED_CA_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that a signature time-stamp is generated before best-signature-time minus the delay when delay is needed
    * Verify that Signature Acceptance Validation at best-signature-time result PASSED
    * 
    * Outputs:
    * validationResult is PASSED
    */
    @Test
    public void test_07_BasicSignatureValidationCANoPOE_DelayActiveValidGenTime_ValidSignatureAcceptance() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            PathValidationStatus mockedPathValidationStatusInvalid = PathValidationStatus.INTERMEDIATE_CA_REVOKED;
            PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(1500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            RevocationStatusInformation mockedChainRevocationInformation = mock(RevocationStatusInformation.class);
            Date mockedExpiredCertsDate = new Date(3100);
            TSTInfo mockedSignedTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignedTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedSignedTimeStampGenDate = new Date(2900);
            long mockedDelay = 50;

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatusInvalid);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(chainPathVerifierMock.getRevocationStatusInformation()).thenReturn(mockedChainRevocationInformation);
            Mockito.when(mockedChainRevocationInformation.getExpiredCertsOnCRL()).thenReturn(mockedExpiredCertsDate);
            
            Mockito.when(mockedTimeStamp.getTSTInfo()).thenReturn(mockedSignedTimeStampTSTInfo);
            Mockito.when(mockedSignedTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignedTimeStampTime);
            Mockito.when(mockedSignedTimeStampTime.getDate()).thenReturn(mockedSignedTimeStampGenDate);
            Mockito.when(mockedSignatureElementConstraints.isTimeStampDelayNeeded()).thenReturn(true);
            Mockito.when(mockedSignatureTimeStamp.hasDelay()).thenReturn(true);
            Mockito.when(mockedSignatureTimeStamp.getDelayMs()).thenReturn(mockedDelay);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.PASSED, validationResult.getValue());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 08
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, OUT_OF_BOUNDS_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that issuance time of revocation status information of the signing certificate is after best-signature-time
    * 
    * Outputs:
    * validationResult is FAILED, NOT_YET_VALID
    */
    @Test
    public void test_08_BasicSignatureValidationOutOfBounds_IssuanceDateAfterBestSignatureTime() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(3500);
            Date mockedIssuanceDate2 = new Date(3800);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(400);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedExpiredCertsDate = new Date(3100);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate).thenReturn(mockedIssuanceDate2, mockedIssuanceDate2, mockedIssuanceDate2, mockedIssuanceDate2, mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
                       
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.FAILED, validationResult.getValue());
            Assert.assertEquals(SubIndication.NOT_YET_VALID, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 09
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, OUT_OF_BOUNDS_NO_POE
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that issuance time of revocation status information of the signing certificate is before best-signature-time
    * Verify that Signature Acceptance Validation at best-signature-time result PASSED
    * 
    * Outputs:
    * validationResult is PASSED
    */
    @Test
    public void test_09_BasicSignatureValidationOutOfBounds_IssuanceTimeBeforeBestSignatureTime() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            Date mockedMaximumAcceptedRevocationFreshness = new Date(3000);
            Date mockedIssuanceDate = new Date(2500);
            Date mockedIssuanceDate2 = new Date(3800);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(400);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedExpiredCertsDate = new Date(2900);
            TSTInfo mockedSignedTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignedTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedSignedTimeStampGenDate = new Date(2900);
            RevocationStatusInformation mockedSigningCertificateRevocationStatusInformation = mock(RevocationStatusInformation.class);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate).thenReturn(mockedIssuanceDate2, mockedIssuanceDate2, mockedIssuanceDate2, mockedIssuanceDate);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);

            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.PASSED, validationResult.getValue());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 10
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, TRY_LATER
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that signing certificate is not fresh at best-signature-time
    * 
    * Outputs:
    * validationResult is INDETERMINATE, TRY_LATER
    */
    @Test
    public void test_10_BasicSignatureValidationTryLater_SigningCertificateNotFresh() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            PathValidationStatus mockedPathValidationStatusInvalid = PathValidationStatus.SIGNING_CERTIFICATE_ON_HOLD;
            PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
            Date mockedMaximumAcceptedRevocationFreshness = new Date(2000);
            Date mockedIssuanceDate = new Date(3500);
            Date mockedIssuanceDate2 = new Date(500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            RevocationStatusInformation mockedSignedCertificateRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedExpiredCertsDate = new Date(2900);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatusInvalid);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate2);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedSignedCertificateRevocationStatusInformation);
            Mockito.when(mockedSignedCertificateRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate2);
            
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
            Assert.assertEquals(SubIndication.TRY_LATER, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 11
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, TRY_LATER
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that signing certificate is fresh at best-signature-time and delay is requested by the policy but it is not available
    * 
    * Outputs:
    * validationResult is INDETERMINATE, SIG_CONSTRAINTS_FAILURE
    */
    @Test
    public void test_11_BasicSignatureValidationTryLater_SigningCertificateFreshDelayNotAvailable() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            PathValidationStatus mockedPathValidationStatusInvalid = PathValidationStatus.SIGNING_CERTIFICATE_ON_HOLD;
            PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
            Date mockedMaximumAcceptedRevocationFreshness = new Date(2000);
            Date mockedIssuanceDate = new Date(3500);
            Date mockedIssuanceDate2 = new Date(2500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            RevocationStatusInformation mockedSignedCertificateRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedExpiredCertsDate = new Date(2900);
            TSTInfo mockedSignedTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignedTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedSignedTimeStampGenDate = new Date(2900);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatusInvalid);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate2);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedSignedCertificateRevocationStatusInformation);
            Mockito.when(mockedSignedCertificateRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate2);
            
            Mockito.when(mockedTimeStamp.getTSTInfo()).thenReturn(mockedSignedTimeStampTSTInfo);
            Mockito.when(mockedSignedTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignedTimeStampTime);
            Mockito.when(mockedSignedTimeStampTime.getDate()).thenReturn(mockedSignedTimeStampGenDate);
            Mockito.when(mockedSignatureElementConstraints.isTimeStampDelayNeeded()).thenReturn(true);
            Mockito.when(mockedSignatureTimeStamp.hasDelay()).thenReturn(false);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.INDETERMINATE, validationResult.getValue());
            Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationResult.getSubIndication());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    * TEST 12
    * 
    * Description:
    * Verify that Basic Signature Validation returns INTERMINATE, TRY_LATER
    * Verify that the signature time-stamp validation result is PASSED and that the generated time is before best-signature-time
    * Verify that signing certificate is fresh at best-signature-time and delay is not requested by the policy
    * Verify that Signature Acceptance Validation at best-signature-time result PASSED
    * 
    * Outputs:
    * validationResult is PASSED
    */
    @Test
    public void test_12_BasicSignatureValidationTryLater_SigningCertificateFreshDelayNotNeeded() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.instance = LTSignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock);
            
            
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
            PathValidationStatus mockedPathValidationStatusInvalid = PathValidationStatus.SIGNING_CERTIFICATE_ON_HOLD;
            PathValidationStatus mockedPathValidationStatus = PathValidationStatus.VALID;
            Date mockedMaximumAcceptedRevocationFreshness = new Date(2000);
            Date mockedIssuanceDate = new Date(3500);
            Date mockedIssuanceDate2 = new Date(2500);
            RevocationStatusInformation mockedRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedValidityRange = new Date(5000);
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
            SignatureElementConstraints mockedSignatureElementConstraints = mock(SignatureElementConstraints.class);
            List<TimeStamp> mockedSignatureTimeStamps = new ArrayList<>();
            TimeStamp mockedSignatureTimeStamp = mock(TimeStamp.class);
            TimeStamp mockedSignatureTimeStamp2 = mock(TimeStamp.class);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp2);
            mockedSignatureTimeStamps.add(mockedSignatureTimeStamp);
            String mockedFormat = "XAdES";
            String mockedFormat2 = "CAdES";
            Date mockedGenerationDate = new Date(3000);
            SignatureCertificate mockedSignatureTimeStampCertificate = mock(SignatureCertificate.class);
            TSTInfo mockedSignatureTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignatureTimeStampTime = mock(DERGeneralizedTime.class);
            RevocationStatusInformation mockedSignedCertificateRevocationStatusInformation = mock(RevocationStatusInformation.class);
            Date mockedExpiredCertsDate = new Date(2900);
            TSTInfo mockedSignedTimeStampTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedSignedTimeStampTime = mock(DERGeneralizedTime.class);
            Date mockedSignedTimeStampGenDate = new Date(2900);

            
            /* Calls to mocks */
            Mockito.when(this.signingCertificateMock.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(this.signatureMock, this.signingCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(this.signatureMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.signingCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
            Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(ValidationModel.CHAIN_MODEL);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, this.validationTimeMock, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatusInvalid);
            Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
            Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate, mockedIssuanceDate2);
            Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
            Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
            Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
            cryptographicVerificationForcePassed(signatureMock, signingCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints);
            
            Mockito.when(signatureMock.getAllSignatureTimeStamps()).thenReturn(mockedSignatureTimeStamps);
            Mockito.when(mockedSignatureTimeStamp2.getFormat()).thenReturn(mockedFormat2);
            Mockito.when(mockedSignatureTimeStamp.getFormat()).thenReturn(mockedFormat);
            Mockito.when(signatureMock.getFormat()).thenReturn(mockedFormat);
            
            Mockito.when(mockedSignatureTimeStampCertificate.getSignerCertificate(null)).thenReturn(mockedCertificate);
            identifySigningCertificateForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedSignatureTimeStamp, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
            Mockito.when(mockedSignatureTimeStampCertificate.getChainOfCertificates()).thenReturn(mockedChain);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStampCertificate.getPublicKey()).thenReturn(mockedPublicKey);
            Mockito.when(mockedSignatureTimeStamp.getSignatureValue()).thenReturn(mockedCertificateDigest);
            Mockito.when(mockedSignatureTimeStamp.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
            Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
            Mockito.when(mockedSignatureTimeStampCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
            Mockito.when(mockedSignatureTimeStamp.getSignedProperties()).thenReturn(mockedSignedProperties);
            Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
            cryptographicVerificationForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedSignatureTimeStamp, mockedSignatureTimeStampCertificate, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
                    
            Mockito.when(mockedSignatureTimeStamp.getTSTInfo()).thenReturn(mockedSignatureTimeStampTSTInfo);
            Mockito.when(mockedSignatureTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignatureTimeStampTime);
            Mockito.when(mockedSignatureTimeStampTime.getDate()).thenReturn(mockedGenerationDate);
            
            Mockito.when(signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedSignedCertificateRevocationStatusInformation);
            Mockito.when(mockedSignedCertificateRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate2);
            
            Mockito.when(mockedTimeStamp.getTSTInfo()).thenReturn(mockedSignedTimeStampTSTInfo);
            Mockito.when(mockedSignedTimeStampTSTInfo.getGenTime()).thenReturn(mockedSignedTimeStampTime);
            Mockito.when(mockedSignedTimeStampTime.getDate()).thenReturn(mockedSignedTimeStampGenDate);
            Mockito.when(mockedSignatureElementConstraints.isTimeStampDelayNeeded()).thenReturn(false);
            
            /* Function to test */
            Indication validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.PASSED, validationResult.getValue());
        } catch (ParseException ex) {
            Logger.getLogger(LTSignatureValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**************************************************************
     ********************* SUPPORT FUNCTIONS **********************
     *************************************************************/
    private void identifySigningCertificateForcePassed(Signature mockedSignature, SignatureCertificate mockedSigningCertificate, SignatureCertificate mockedCertificate, String mockedCertificateDigest, String mockedCertificateAlgorithm) {
        //Mockito.when(mockedSigningCertificate.getSignerCertificate(this.signerDocumentMock)).thenReturn(mockedCertificate);
        Mockito.when(mockedCertificate.getEncoded()).thenReturn(mockedCertificateDigest);
        Mockito.when(mockedSignature.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSigningCertificate.applyDigest(mockedCertificateDigest, mockedCertificateAlgorithm)).thenReturn(true);
    }
    
    private void initializeValidationContextForcePassed(Signature mockedSignature, PolicyIdentifier mockedPolicyIdentifier, String mockedCertificateDigest, byte[] mockedPolicyHashValue, DigestAlgorithm mockedDigestAlgorithm) {
        
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getHash()).thenReturn(mockedDigestAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getValue()).thenReturn(mockedPolicyHashValue);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(mockedSignature)).thenReturn(mockedCertificateDigest);
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
        //Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
        Mockito.when(this.signingCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
    }
    
    private void cryptographicVerificationForcePassed(Signature mockedSignature, SignatureCertificate mockedSignatureCertificate, SignedProperties mockedSignedProperties, SignedDataObjectProperties mockedSignedDataObjectProperties, List<SignedDataObject> mockedSignedDataObjects, PublicKey mockedPublicKey, String mockedCertificateDigest, String mockedCertificateAlgorithm) {
        Mockito.when(mockedSignature.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
        Mockito.when(mockedSignedDataObjects.get(0).checkIntegrity()).thenReturn(true);
        Mockito.when(mockedSignatureCertificate.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedSignature.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(mockedSignature.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
        
    }
    
    private void validateSignatureAcceptanceForcePassed(String mockedCertificateAlgorithm, DigestAlgorithm mockedDigestAlgorithm, SignedProperties mockedSignedProperties, SignedSignatureProperties mockedSignedSignatureProperties, PublicKey mockedPublicKey, SignedDataObjectProperties mockedSignedDataObjectProperties, List<TimeStamp> mockedTimeStamps, TimeStamp mockedTimeStamp, UnsignedProperties mockedUnsignedProperties, List<SignatureCertificate> mockedOtherCertificates, SignatureCertificate mockedOtherCertificate, RevocationValues mockedRevocationValues, List<EncapsulatedPKIData> mockedCRLValues, EncapsulatedPKIData mockedEncapsulatedPKIData, CryptographicConstraints mockedCryptographicConstraints, PolicyIdentifier mockedPolicyIdentifier, SignatureElementConstraints mockedSignatureElementConstraints) {
        Mockito.when(signatureMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(signingCertificateMock);
        Mockito.when(signingCertificateMock.getPublicKey()).thenReturn(mockedPublicKey);
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
    
    private void validateX509CertificateForcePassed(SignatureCertificate timestampCertificateMock, List<SignatureCertificate> mockedChain, PolicyIdentifier mockedPolicyIdentifier, X509ValidationConstraints mockedX09ValidationContraints, PathValidationStatus mockedPathValidationStatus, Date mockedMaximumAcceptedRevocationFreshness, SignatureCertificate mockedCertificate, RevocationStatusInformation mockedRevocationStatusInformation, Date mockedIssuanceDate, CryptographicConstraints mockedCryptographicConstraints, Date mockedValidityRange, Date mockedGenerationDate) {
        Mockito.when(timestampCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
        //Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
        Mockito.when(timestampCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
    }
    
    private void validateSignatureAcceptanceForcePassed(TimeStamp timestampMock, SignatureCertificate timestampCertificateMock, String mockedCertificateAlgorithm, DigestAlgorithm mockedDigestAlgorithm, SignedProperties mockedSignedProperties, SignedSignatureProperties mockedSignedSignatureProperties, PublicKey mockedPublicKey, SignedDataObjectProperties mockedSignedDataObjectProperties, List<TimeStamp> mockedTimeStamps, TimeStamp mockedTimeStamp, UnsignedProperties mockedUnsignedProperties, List<SignatureCertificate> mockedOtherCertificates, SignatureCertificate mockedOtherCertificate, RevocationValues mockedRevocationValues, List<EncapsulatedPKIData> mockedCRLValues, EncapsulatedPKIData mockedEncapsulatedPKIData, CryptographicConstraints mockedCryptographicConstraints, PolicyIdentifier mockedPolicyIdentifier, SignatureElementConstraints mockedSignatureElementConstraints, Date mockedGenerationDate) {
        Mockito.when(timestampMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(timestampCertificateMock);
        Mockito.when(timestampCertificateMock.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedPublicKey.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getAllDataObjectsTimestamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedTimeStamp.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getIndividualDataObjectsTimeStamps()).thenReturn(new ArrayList<>());
        Mockito.when(timestampMock.getUnsignedProperties()).thenReturn(mockedUnsignedProperties);
        Mockito.when(mockedUnsignedProperties.getArchiveTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedUnsignedProperties.getCertificateValues()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedOtherCertificate.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedUnsignedProperties.getRevocationValues()).thenReturn(mockedRevocationValues);
        Mockito.when(mockedRevocationValues.getCRLValues()).thenReturn(mockedCRLValues);
        Mockito.when(mockedEncapsulatedPKIData.getCertificate()).thenReturn(mockedOtherCertificate);
        //Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true).thenReturn(false);
        Mockito.when(mockedPolicyIdentifier.getSignatureElementConstraints()).thenReturn(mockedSignatureElementConstraints);
        Mockito.when(mockedSignatureElementConstraints.containsMissingElement(timestampMock)).thenReturn(true);
    }
    
    private void validateTimeStampForcePassed(TimeStamp timestampMock, SignatureCertificate timestampCertificateMock) throws ParseException {
        /* Initialize mocked class variables */
            timestampMock = mock(TimeStamp.class);
            timestampCertificateMock = mock(SignatureCertificate.class);
            
            /* Initialize local mocked variables */
            TSTInfo mockedTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedTime = mock(DERGeneralizedTime.class);
            Date mockedGenerationDate = new Date(3000);
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
            Mockito.when(timestampMock.getTSTInfo()).thenReturn(mockedTSTInfo);
            Mockito.when(mockedTSTInfo.getGenTime()).thenReturn(mockedTime);
            Mockito.when(mockedTime.getDate()).thenReturn(mockedGenerationDate);
            
            identifySigningCertificateForcePassed(timestampMock, timestampCertificateMock, mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(timestampMock, mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            validateX509CertificateForcePassed(timestampCertificateMock, mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange, mockedGenerationDate);
            cryptographicVerificationForcePassed(timestampMock, timestampCertificateMock, mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(timestampMock, timestampCertificateMock, mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            
    }
    
    
}