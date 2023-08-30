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
public class TimeStampValidatorTest {
    
    @InjectMocks
    private TimeStampValidator instance;
    @Mock
    private TimeStamp timestampMock;
    @Mock
    private SignatureCertificate timestampCertificateMock;
    @Mock
    private Set<TrustAnchor> trustAnchorsMock;
    @Mock
    private List<ObjectIdentifier> allowableValidationPolicyIdsMock;
    @Mock
    private PolicyIdentifier signatureValidationPoliciesMock;
    @Mock
    private LocalConfiguration localConfigurationMock;
    @Mock
    private PKIXCertificationPathVerifier chainPathVerifierMock;
    
    public TimeStampValidatorTest() {
        
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
    * Verify that Time-stamp validation returns the same result as Basic Signature Validation
    * 
    * Inputs:
    * timestampCertificateMock is not null
    * timestampGenerationTimeMock is current time
    * 
    * Outputs:
    * validationResult is PASSED
    */
    @Test
    public void test_01_BasicSignatureValidationCopy() {
        try {
            /* Initialize mocked class variables */
            this.timestampMock = mock(TimeStamp.class);
            this.signatureValidationPoliciesMock = null;
            this.timestampCertificateMock = mock(SignatureCertificate.class);
            this.instance = TimeStampValidator.getInstance(timestampMock, timestampCertificateMock, signatureValidationPoliciesMock, allowableValidationPolicyIdsMock, trustAnchorsMock, localConfigurationMock, chainPathVerifierMock);
            
            /* Initialize local mocked variables */
            TSTInfo mockedTSTInfo = mock(TSTInfo.class);
            DERGeneralizedTime mockedTime = mock(DERGeneralizedTime.class);
            Date mockedGenerationDate = mock(Date.class);
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
            
            identifySigningCertificateForcePassed(mockedCertificate, mockedCertificateDigest, mockedCertificateAlgorithm);
            initializeValidationContextForcePassed(mockedPolicyIdentifier, mockedCertificateDigest, mockedPolicyHashValue, mockedDigestAlgorithm);
            validateX509CertificateForcePassed(mockedChain, mockedPolicyIdentifier, mockedX09ValidationContraints, mockedPathValidationStatus, mockedMaximumAcceptedRevocationFreshness, mockedCertificate, mockedRevocationStatusInformation, mockedIssuanceDate, mockedCryptographicConstraints, mockedValidityRange, mockedGenerationDate);
            cryptographicVerificationForcePassed(mockedSignedProperties, mockedSignedDataObjectProperties, mockedSignedDataObjects, mockedPublicKey, mockedCertificateDigest, mockedCertificateAlgorithm);
            validateSignatureAcceptanceForcePassed(mockedCertificateAlgorithm, mockedDigestAlgorithm, mockedSignedProperties, mockedSignedSignatureProperties, mockedPublicKey, mockedSignedDataObjectProperties, mockedTimeStamps, mockedTimeStamp, mockedUnsignedProperties, mockedOtherCertificates, mockedOtherCertificate, mockedRevocationValues, mockedCRLValues, mockedEncapsulatedPKIData, mockedCryptographicConstraints, mockedPolicyIdentifier, mockedSignatureElementConstraints, mockedGenerationDate);
            
            
            /* Function to test */
            Indication validationResult;
            validationResult = instance.validate();
            
            /* Verify function calls */
            
            /* Verify tested function output */
            Assert.assertEquals(Indication.PASSED, validationResult.getValue());
        } catch (ParseException ex) {
            Logger.getLogger(TimeStampValidatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**************************************************************
     ********************* SUPPORT FUNCTIONS **********************
     *************************************************************/
    private void identifySigningCertificateForcePassed(SignatureCertificate mockedCertificate, String mockedCertificateDigest, String mockedCertificateAlgorithm) {
        Mockito.when(this.timestampCertificateMock.getSignerCertificate(null)).thenReturn(mockedCertificate);
        Mockito.when(mockedCertificate.getEncoded()).thenReturn(mockedCertificateDigest);
        Mockito.when(this.timestampMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(this.timestampCertificateMock.applyDigest(mockedCertificateDigest, mockedCertificateAlgorithm)).thenReturn(true);
    }
    
    private void initializeValidationContextForcePassed(PolicyIdentifier mockedPolicyIdentifier, String mockedCertificateDigest, byte[] mockedPolicyHashValue, DigestAlgorithm mockedDigestAlgorithm) {
        
        Mockito.when(this.localConfigurationMock.getDefaultPolicyIdentifier()).thenReturn(mockedPolicyIdentifier);
        Mockito.when(mockedPolicyIdentifier.getSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.parseSignaturePolicyDocument()).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getHash()).thenReturn(mockedDigestAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getValue()).thenReturn(mockedPolicyHashValue);
        Mockito.when(mockedPolicyIdentifier.applySignatureTransforms(timestampMock)).thenReturn(mockedCertificateDigest);
    }
    
    private void validateX509CertificateForcePassed(List<SignatureCertificate> mockedChain, PolicyIdentifier mockedPolicyIdentifier, X509ValidationConstraints mockedX09ValidationContraints, PathValidationStatus mockedPathValidationStatus, Date mockedMaximumAcceptedRevocationFreshness, SignatureCertificate mockedCertificate, RevocationStatusInformation mockedRevocationStatusInformation, Date mockedIssuanceDate, CryptographicConstraints mockedCryptographicConstraints, Date mockedValidityRange, Date mockedGenerationDate) {
        Mockito.when(this.timestampCertificateMock.getChainOfCertificates()).thenReturn(mockedChain);
        Mockito.when(mockedPolicyIdentifier.getX509ValidationConstraints()).thenReturn(mockedX09ValidationContraints);
        Mockito.when(mockedX09ValidationContraints.getValidationModel()).thenReturn(null);
        Mockito.when(this.chainPathVerifierMock.validateChain(mockedChain, mockedGenerationDate, ValidationModel.CHAIN_MODEL)).thenReturn(mockedPathValidationStatus);
        Mockito.when(mockedX09ValidationContraints.getMaximumAcceptedRevocationFreshness()).thenReturn(mockedMaximumAcceptedRevocationFreshness);
        Mockito.when(mockedCertificate.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
        Mockito.when(mockedRevocationStatusInformation.getIssuanceDate()).thenReturn(mockedIssuanceDate);
        Mockito.when(mockedX09ValidationContraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getCryptographicConstraints()).thenReturn(mockedCryptographicConstraints);
        Mockito.when(mockedCryptographicConstraints.isChainMatched(mockedChain)).thenReturn(true);
        Mockito.when(mockedX09ValidationContraints.getSigningCertificateValidityRange()).thenReturn(mockedValidityRange);
        Mockito.when(this.timestampCertificateMock.getRevocationStatusInformation()).thenReturn(mockedRevocationStatusInformation);
    }
    
    private void cryptographicVerificationForcePassed(SignedProperties mockedSignedProperties, SignedDataObjectProperties mockedSignedDataObjectProperties, List<SignedDataObject> mockedSignedDataObjects, PublicKey mockedPublicKey, String mockedCertificateDigest, String mockedCertificateAlgorithm) {
        Mockito.when(this.timestampMock.getSignedProperties()).thenReturn(mockedSignedProperties);
        Mockito.when(mockedSignedProperties.getSignedDataObjectProperties()).thenReturn(mockedSignedDataObjectProperties);
        Mockito.when(mockedSignedDataObjectProperties.getSignedDataObjects()).thenReturn(mockedSignedDataObjects);
        Mockito.when(mockedSignedDataObjects.get(0).checkIntegrity()).thenReturn(true);
        Mockito.when(timestampCertificateMock.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(timestampMock.getSignatureValue()).thenReturn(mockedCertificateDigest);
        Mockito.when(timestampMock.checkSignatureValue(mockedCertificateDigest, mockedCertificateAlgorithm, mockedPublicKey)).thenReturn(true);
        
    }
    
    private void validateSignatureAcceptanceForcePassed(String mockedCertificateAlgorithm, DigestAlgorithm mockedDigestAlgorithm, SignedProperties mockedSignedProperties, SignedSignatureProperties mockedSignedSignatureProperties, PublicKey mockedPublicKey, SignedDataObjectProperties mockedSignedDataObjectProperties, List<TimeStamp> mockedTimeStamps, TimeStamp mockedTimeStamp, UnsignedProperties mockedUnsignedProperties, List<SignatureCertificate> mockedOtherCertificates, SignatureCertificate mockedOtherCertificate, RevocationValues mockedRevocationValues, List<EncapsulatedPKIData> mockedCRLValues, EncapsulatedPKIData mockedEncapsulatedPKIData, CryptographicConstraints mockedCryptographicConstraints, PolicyIdentifier mockedPolicyIdentifier, SignatureElementConstraints mockedSignatureElementConstraints, Date mockedGenerationDate) {
        Mockito.when(timestampMock.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedDigestAlgorithm.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedProperties.getSignedSignatureProperties()).thenReturn(mockedSignedSignatureProperties);
        Mockito.when(mockedSignedSignatureProperties.getSigningCertificate()).thenReturn(timestampCertificateMock);
        Mockito.when(mockedPublicKey.getAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getAllDataObjectsTimestamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedTimeStamp.getSignatureAlgorithm()).thenReturn(mockedCertificateAlgorithm);
        Mockito.when(mockedSignedDataObjectProperties.getIndividualDataObjectsTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(timestampMock.getUnsignedProperties()).thenReturn(mockedUnsignedProperties);
        Mockito.when(mockedUnsignedProperties.getArchiveTimeStamps()).thenReturn(mockedTimeStamps);
        Mockito.when(mockedUnsignedProperties.getCertificateValues()).thenReturn(mockedOtherCertificates);
        Mockito.when(mockedOtherCertificate.getPublicKey()).thenReturn(mockedPublicKey);
        Mockito.when(mockedUnsignedProperties.getRevocationValues()).thenReturn(mockedRevocationValues);
        Mockito.when(mockedRevocationValues.getCRLValues()).thenReturn(mockedCRLValues);
        Mockito.when(mockedEncapsulatedPKIData.getCertificate()).thenReturn(mockedOtherCertificate);
        Mockito.when(mockedCryptographicConstraints.isAlgorithmReliable(mockedCertificateAlgorithm, mockedGenerationDate)).thenReturn(true);
        Mockito.when(mockedPolicyIdentifier.getSignatureElementConstraints()).thenReturn(mockedSignatureElementConstraints);
        Mockito.when(mockedSignatureElementConstraints.containsMissingElement(timestampMock)).thenReturn(true);
    }
    
    
}