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
import edu.upc.etsetb.tfm.xml_signature_validation.validation.entities.LTASignatureValidator;
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
public class LTASignatureValidatorTest {
    
    @InjectMocks
    private LTASignatureValidator instance;
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
    private List<EvidenceRecord> evidenceRecordsMock;
    @Mock
    private List<ProofOfExistence> signaturePOEsMock;
    @Mock
    private Date bestSignatureTimeMock;
    @Mock
    private List<TimeStamp> processedTimeStampsMock;
    
    public LTASignatureValidatorTest() {
        
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
    * Verify that Long-Time Signature Validation returns PASSED
    * Verify that Evidence Records are empty
    * 
    * Outputs:
    * validationResult is PASSED
    */
    @Test
    public void test_01_LTSignatureValidationCopyPassed_EmptyEvidenceRecords() {
        try {
            /* Initialize mocked class variables */
            this.signingCertificateMock = mock(SignatureCertificate.class);
            this.signatureValidationPoliciesMock = null;
            this.validationTimeMock = new Date(4000);
            this.signatureExistenceMock = null;
            this.bestSignatureTimeMock = new Date(3000);
            this.evidenceRecordsMock = new ArrayList<>();
            
            this.instance = LTASignatureValidator.getInstance(signatureMock, signerDocumentMock, signingCertificateMock, trustAnchorsMock, allowableValidationPolicyIdsMock, signatureValidationPoliciesMock, localConfigurationMock, validationTimeMock, signatureExistenceMock, chainPathVerifierMock, evidenceRecordsMock);
            
            
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