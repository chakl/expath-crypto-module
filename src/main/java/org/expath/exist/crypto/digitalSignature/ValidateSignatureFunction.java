/*
 * eXist-db EXPath Cryptographic library
 * eXist-db wrapper for EXPath Cryptographic Java library
 * Copyright (C) 2016 Claudius Teodorescu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.expath.exist.crypto.digitalSignature;

import java.io.*;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Iterator;
import java.util.Properties;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;

import org.exist.storage.serializers.Serializer;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.*;
import org.expath.exist.crypto.EXpathCryptoException;
import org.expath.exist.crypto.ExistExpathCryptoModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.digitalSignature.ValidateXmlSignature;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;

/**
 * Cryptographic extension functions.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius
 *         Teodorescu</a>
 */
public class ValidateSignatureFunction extends BasicFunction {

	private static final Logger LOG = LoggerFactory.getLogger(ValidateSignatureFunction.class);

	private static final String FS_VALIDATE_SIGNATURE_NAME = "validate-signature";
	private static final String FS_VALIDATE_SIGNATURE_BY_CERTFILE_NAME = "validate-signature-by-certfile";

	public final static FunctionSignature FS_VALIDATE_SIGNATURE = functionSignature(FS_VALIDATE_SIGNATURE_NAME,
			"This function validates an XML Digital Signature.",
			returns(Type.BOOLEAN, "boolean value true() if the signature is valid, otherwise return value false()."),
			param("data", Type.NODE, "The enveloped, enveloping, or detached signature."));

	public final static FunctionSignature FS_VALIDATE_SIGNATURE_BY_CERTFILE = functionSignature(FS_VALIDATE_SIGNATURE_BY_CERTFILE_NAME,
			"This function validates an XML Digital Signature using the public key from a PEM encoded X.509 certificate file.",
			returns(Type.BOOLEAN, "boolean value true() if the signature is valid, otherwise return value false()."),
			param("data", Type.NODE, "The enveloped, enveloping, or detached signature."),
			param("certfile",  Type.STRING,"The name of a PEM encoded X.509 certificate to read the validation key from."));

	public ValidateSignatureFunction(final XQueryContext context, final FunctionSignature signature) {
		super(context, signature);
	}

	private static final Properties defaultOutputKeysProperties = new Properties();
	static {
		defaultOutputKeysProperties.setProperty(OutputKeys.INDENT, "no");
		defaultOutputKeysProperties.setProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		defaultOutputKeysProperties.setProperty(OutputKeys.ENCODING, "UTF-8");
	}

	@Override
	public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws EXpathCryptoException {
		if (args[0].isEmpty()) {
			return Sequence.EMPTY_SEQUENCE;
		}

		Document inputDOMDoc = null;
		try {
			inputDOMDoc = getInputDOMDoc(args[0].itemAt(0));
		} catch (SAXException | ParserConfigurationException | IOException e) {
			LOG.error(e.getMessage(), e);
			return Sequence.EMPTY_SEQUENCE;
		}

		Boolean isValid = false;
		switch (getName().getLocalPart()) {
			case FS_VALIDATE_SIGNATURE_NAME:
				try {
					isValid = ValidateXmlSignature.validate(inputDOMDoc);
				} catch (CryptoException | IOException | XMLSignatureException e) {
					throw new EXpathCryptoException(this, e);
				}
				return new BooleanValue(isValid);

			case FS_VALIDATE_SIGNATURE_BY_CERTFILE_NAME:
				if (args[1].isEmpty()) {
					LOG.error("Missing certfile name");
					return Sequence.EMPTY_SEQUENCE;
				}

				PublicKey pk = null;
				try {
					FileInputStream fis = new FileInputStream(String.valueOf(args[1]));
					BufferedInputStream bis = new BufferedInputStream(fis);
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					Certificate cert = null;
					while (bis.available() > 0) {
						cert = cf.generateCertificate(bis);
						System.out.println(cert.toString());
					}
					pk = cert.getPublicKey();
					System.out.println(pk.toString());

					isValid = ValidateXmlSignatureByPublicKey(inputDOMDoc, pk);
				} catch (Exception ex) {
					throw new EXpathCryptoException(this, ex);
				}

				return new BooleanValue(isValid);

			default:
				throw new EXpathCryptoException(this, ExistExpathCryptoModule.NO_FUNCTION,
						"No function: " + getName() + "#" + getSignature().getArgumentCount());
		}
	}

	private Document getInputDOMDoc(Item item) throws SAXException, ParserConfigurationException, IOException {
		// get and process the input document or node to InputStream, in order to be
		// transformed into DOM Document
		final Serializer serializer = context.getBroker().getSerializer();
		serializer.reset();

		final Properties outputProperties = new Properties(defaultOutputKeysProperties);
		serializer.setProperties(outputProperties);

		// initialize the document builder
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = null;
		db = dbf.newDocumentBuilder();

		// process the input string to DOM document
		Document inputDOMDoc = null;
		Reader reader = new StringReader(serializer.serialize((NodeValue) item));
		inputDOMDoc = db.parse(new InputSource(reader));

		return inputDOMDoc;
	}

	private Boolean ValidateXmlSignatureByPublicKey(Document inputDOMDoc, PublicKey pk) throws Exception {
		boolean coreValidity = false;

		// Find Signature element.
		NodeList nl = inputDOMDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			throw new Exception("Cannot find Signature element");
		}
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		// Create a DOMValidateContext, specify public key and document context.
		DOMValidateContext valContext = new DOMValidateContext(pk, nl.item(0));
		// register ID element (handle stricter @ID attribute requirements in JRE8)
		valContext.setIdAttributeNS(inputDOMDoc.getDocumentElement(), null, "ID");
		// only needed for debugging, disable for production
		//valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

		// Unmarshal the XMLSignature.
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);

		// Validate the XMLSignature.
		coreValidity = signature.validate(valContext);
		System.out.println("signature.validate is : " + coreValidity);

		// dump signed data for debugging
		Iterator iterator = signature.getSignedInfo().getReferences().iterator();
		System.out.println("---- START PRINTING SIGNED DATA DUMP ----");
		while(iterator.hasNext()) {
			InputStream is = ((Reference) iterator.next()).getDigestInputStream();
			// Display the data.
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int length;
			while (is != null && (length = is.read(buffer)) != -1 ) {
				result.write(buffer, 0, length);
			}
			System.out.println(result.toString("UTF-8"));
			System.out.println("----");
		}
		System.out.println("---- STOP PRINTING SIGNED DATA DUMP ----");

		// Check core validation status.
		if (coreValidity == false) {
			System.err.println("Signature failed core validation");
			boolean sv = signature.getSignatureValue().validate(valContext);
			System.out.println("signature validation status: " + sv);
			if (sv == false) {
				// Check the validation status of each Reference.
				Iterator i = signature.getSignedInfo().getReferences().iterator();
				for (int j = 0; i.hasNext(); j++) {
					boolean refValid = ((Reference) i.next()).validate(valContext);
					System.out.println("ref[" + j + "] validity status: " + refValid);
				}
			}
		} else {
			System.out.println("Signature passed core validation");
		}
		return coreValidity;
	}
}
