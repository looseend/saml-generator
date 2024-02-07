package com.rackspace.saml;

import java.io.ByteArrayOutputStream;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.signature.impl.*;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;


@SuppressWarnings("ALL")
public class SamlAssertionProducer {

	private String privateKeyLocation;
	private String publicKeyLocation;
	private final CertManager certManager = new CertManager();
	
	public Response createSAMLResponse(final String subjectId, final DateTime authenticationTime,
			                           final String credentialType, final HashMap<String, List<String>> attributes, String issuer, Integer samlAssertionDays) {
		
		try {
			DefaultBootstrap.bootstrap();
			
			Signature signature = createSignature();
			Status status = createStatus();
			Issuer responseIssuer = null;
			Issuer assertionIssuer = null;
			Subject subject = null;
			AttributeStatement attributeStatement = null;
			
			if (issuer != null) {
				responseIssuer = createIssuer(issuer);
				assertionIssuer = createIssuer(issuer);
			}
			
			if (subjectId != null) {
				subject = createSubject(subjectId, samlAssertionDays);
			}
			
			if (attributes != null && attributes.size() != 0) {
				attributeStatement = createAttributeStatement(attributes);
			}
			
			AuthnStatement authnStatement = createAuthnStatement(authenticationTime);
			
			Assertion assertion = createAssertion(new DateTime(), subject, assertionIssuer, authnStatement, attributeStatement);
//			assertion.setSignature(signature);

			Response response = createResponse(new DateTime(), responseIssuer, status, assertion);
			response.setSignature(signature);
			
			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element element = marshaller.marshall(response);
			
			if (signature != null) {
				Signer.signObject(signature);
			}
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLHelper.writeNode(element, baos);
		
			return response;
			
		} catch (Throwable t) {
			t.printStackTrace();
			return null;
		}
	}

	public String getPrivateKeyLocation() {
		return privateKeyLocation;
	}

	public void setPrivateKeyLocation(String privateKeyLocation) {
		this.privateKeyLocation = privateKeyLocation;
	}

	public String getPublicKeyLocation() {
		return publicKeyLocation;
	}

	public void setPublicKeyLocation(String publicKeyLocation) {
		this.publicKeyLocation = publicKeyLocation;
	}
	
	private Response createResponse(final DateTime issueDate, Issuer issuer, Status status, Assertion assertion) {
		ResponseBuilder responseBuilder = new ResponseBuilder();
		Response response = responseBuilder.buildObject();
		response.setID(UUID.randomUUID().toString());
		response.setIssueInstant(issueDate);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(issuer);
		response.setStatus(status);
		response.getAssertions().add(assertion);
		return response;
	}
	
	private Assertion createAssertion(final DateTime issueDate, Subject subject, Issuer issuer, AuthnStatement authnStatement,
			                          AttributeStatement attributeStatement) {
		AssertionBuilder assertionBuilder = new AssertionBuilder();
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssueInstant(issueDate);
		assertion.setSubject(subject);
		assertion.setIssuer(issuer);
		
		if (authnStatement != null)
			assertion.getAuthnStatements().add(authnStatement);
		
		if (attributeStatement != null)
			assertion.getAttributeStatements().add(attributeStatement);
		
		return assertion;
	}
	
	private Issuer createIssuer(final String issuerName) {
		// create Issuer object
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerName);	
		return issuer;
	}
	
	private Subject createSubject(final String subjectId, final Integer samlAssertionDays) {
		DateTime currentDate = new DateTime();
		if (samlAssertionDays != null)
			currentDate = currentDate.plusDays(samlAssertionDays);
		
		// create name element
		NameIDBuilder nameIdBuilder = new NameIDBuilder(); 
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(subjectId);
		nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
	
		SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
		SubjectConfirmationData subjectConfirmationData = dataBuilder.buildObject();
		subjectConfirmationData.setNotOnOrAfter(currentDate);
		
		SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
		SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		
		// create subject element
		SubjectBuilder subjectBuilder = new SubjectBuilder();
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		
		return subject;
	}
	
	private AuthnStatement createAuthnStatement(final DateTime issueDate) {
		// create authcontextclassref object
		AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef classRef = classRefBuilder.buildObject();
		classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified");
		
		// create authcontext object
		AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
		AuthnContext authnContext = authContextBuilder.buildObject();
		authnContext.setAuthnContextClassRef(classRef);
		
		// create authenticationstatement object
		AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
		AuthnStatement authnStatement = authStatementBuilder.buildObject();
		authnStatement.setAuthnInstant(issueDate);
		authnStatement.setAuthnContext(authnContext);
		
		return authnStatement;
	}
	
	private AttributeStatement createAttributeStatement(HashMap<String, List<String>> attributes) {
		// create authenticationstatement object
		AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
		
		AttributeBuilder attributeBuilder = new AttributeBuilder();
		if (attributes != null) {
			for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
				Attribute attribute = attributeBuilder.buildObject();
				attribute.setName(entry.getKey());
				
				for (String value : entry.getValue()) {
					XSStringBuilder stringBuilder = new XSStringBuilder();
					XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
					attributeValue.setValue(value);
					attribute.getAttributeValues().add(attributeValue);
				}
				
				attributeStatement.getAttributes().add(attribute);
			}
		}
		
		return attributeStatement;
	}

	private Status createStatus() {
		StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);

		StatusBuilder statusBuilder = new StatusBuilder();
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);

		return status;
	}
	
	private Signature createSignature() throws Throwable {
		if (publicKeyLocation != null && privateKeyLocation != null) {


			SignatureBuilder builder = new SignatureBuilder();
			Signature signature = builder.buildObject();
			Credential signingCredential = certManager.getSigningCredential(publicKeyLocation, privateKeyLocation);
			RSAPublicKey publicKey = (RSAPublicKey) signingCredential.getPublicKey();
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);


			KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
			X509DataBuilder x509DataBuilder = new X509DataBuilder();
			X509Data x509Data = x509DataBuilder.buildObject();
			X509Certificate x509Certificate = new X509CertificateBuilder().buildObject();
			x509Certificate.setValue(Base64.getUrlEncoder().encodeToString(((BasicX509Credential)signingCredential).getEntityCertificate().getEncoded()));
			x509Data.getX509Certificates().add(x509Certificate);

			ModulusBuilder modulusBuilder = new ModulusBuilder();
			Modulus modulus = modulusBuilder.buildObject();
			modulus.setValue(
					Base64.getUrlEncoder().encodeToString(publicKey.getModulus().toByteArray()));

			Exponent exponent = new ExponentBuilder().buildObject();
			exponent.setValue(Base64.getUrlEncoder().encodeToString(publicKey.getPublicExponent().toByteArray()));

			RSAKeyValue rsaKeyValue = new RSAKeyValueBuilder().buildObject();
			rsaKeyValue.setModulus(modulus);
			rsaKeyValue.setExponent(exponent);

			KeyValue keyValue = new KeyValueBuilder().buildObject();
			keyValue.setRSAKeyValue(rsaKeyValue);

			KeyName keyName = new KeyNameBuilder().buildObject();
			keyName.setValue("o0lxOjHa_R53BHHZCJ5YoG_vHkXsYJO4T6zAngMVRCo");

			KeyInfo keyInfo = keyInfoBuilder.buildObject();
			keyInfo.getKeyNames().add(keyName);
			keyInfo.getKeyValues().add(keyValue);
			keyInfo.getX509Datas().add(x509Data);
			signature.setKeyInfo(keyInfo);

			return signature;

		}
		
		return null;
	}
}
