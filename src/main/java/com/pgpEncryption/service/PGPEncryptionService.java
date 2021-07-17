package com.pgpEncryption.service;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class PGPEncryptionService {

	private static final int KEY_FLAGS = 27;
	private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[] { PGPSignature.POSITIVE_CERTIFICATION,
			PGPSignature.CASUAL_CERTIFICATION, PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION };
	
    public static void encrypt(String publicKeyFileName, String inputFileName,String outputFileName, boolean asciiArmored, boolean integrityCheck) throws Exception {
    	FileInputStream keyIn = null;
    	FileOutputStream out = null;
    	try {
    		keyIn = new FileInputStream(publicKeyFileName);
    		out = new FileOutputStream(outputFileName);
    		encryptFile(out, inputFileName, readPublicKey(keyIn), asciiArmored, integrityCheck);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			closeStream(out);
			closeStream(keyIn);
		}
    }

    public static void decrypt(String inputFileName,String outputFileName, String secretKeyFileName, String passphrase) throws Exception {
        FileInputStream in = null;
        FileInputStream keyIn = null;
        FileOutputStream out = null;
        
        try {
        	in = new FileInputStream(inputFileName);
        	keyIn = new FileInputStream(secretKeyFileName);
        	out = new FileOutputStream(outputFileName);
        	decryptFile(in, out, keyIn, passphrase.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			closeStream(in);
			closeStream(out);
			closeStream(keyIn);
		}
    }

	public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {

		PGPPublicKey publicKey = null;
		try {
			final PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
	
			final Iterator<PGPPublicKeyRing> publicKeyRingIt = keyRingCollection.getKeyRings();
	
			while (publicKey == null && publicKeyRingIt.hasNext()) {
				final PGPPublicKeyRing kRing = publicKeyRingIt.next();
				final Iterator<PGPPublicKey> publicKeyIt = kRing.getPublicKeys();
				while (publicKey == null && publicKeyIt.hasNext()) {
					final PGPPublicKey key = publicKeyIt.next();
					if (key.isEncryptionKey()) {
						publicKey = key;
					}
				}
			}
	
			if (publicKey == null) {
				throw new IllegalArgumentException("Can't find public key in the key ring.");
			} else if (!isForEncryption(publicKey)) {
				throw new IllegalArgumentException("KeyID " + publicKey.getKeyID() + " not flagged for encryption.");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return publicKey;
	}

	@SuppressWarnings("unchecked")
	public static PGPSecretKey readSecretKey(InputStream in) throws IOException, PGPException {
		PGPSecretKey secretKey = null;
		try {
			final PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());
	
			final Iterator<PGPSecretKeyRing> rIt = keyRingCollection.getKeyRings();
			while (secretKey == null && rIt.hasNext()) {
				final PGPSecretKeyRing keyRing = rIt.next();
				final Iterator<PGPSecretKey> secretKeyIt = keyRing.getSecretKeys();
				while (secretKey == null && secretKeyIt.hasNext()) {
					final PGPSecretKey key = secretKeyIt.next();
					if (key.isSigningKey()) {
						secretKey = key;
					}
				}
			}
			if (secretKey == null) {
				throw new IllegalArgumentException("Can't find private key in the key ring.");
			} else if (!secretKey.isSigningKey()) {
				throw new IllegalArgumentException("Private key does not allow signing.");
			} else if (secretKey.getPublicKey().isRevoked()) {
				throw new IllegalArgumentException("Private key has been revoked.");
			} else if (!hasKeyFlags(secretKey.getPublicKey(), KeyFlags.SIGN_DATA)) {
				throw new IllegalArgumentException("Key cannot be used for signing.");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return secretKey;
	}

	public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID, char[] pass)
			throws IOException, PGPException, NoSuchProviderException {
		
		final PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn),new JcaKeyFingerprintCalculator());
		return findPrivateKey(pgpSec.getSecretKey(keyID), pass);
	}

	public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass) throws PGPException {
		
		if (pgpSecKey == null) return null;

		final PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
		return pgpSecKey.extractPrivateKey(decryptor);
	}

	public static void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd) throws Exception {
		
		InputStream idInputStream= null;
		InputStream privateKeyInputStream = null;
		
		try {
			Security.addProvider(new BouncyCastleProvider());
			in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
	
			final PGPObjectFactory pgpFactory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
			PGPEncryptedDataList enc;
	
			Object factoryObj = pgpFactory.nextObject();
			if (factoryObj instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) factoryObj;
			} else {
				enc = (PGPEncryptedDataList) pgpFactory.nextObject();
			}
			final Iterator<PGPPublicKeyEncryptedData> publicKeyIt = enc.getEncryptedDataObjects();
			PGPPrivateKey privateKey = null;
			PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
	
			while (privateKey == null && publicKeyIt.hasNext()) {
				publicKeyEncryptedData = publicKeyIt.next();
				privateKey = findPrivateKey(keyIn, publicKeyEncryptedData.getKeyID(), passwd);
			}
	
			if (privateKey == null) {
				throw new IllegalArgumentException("Secret key for message not found.");
			}
	
			privateKeyInputStream = publicKeyEncryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
			final PGPObjectFactory plainFactory = new PGPObjectFactory(privateKeyInputStream, new JcaKeyFingerprintCalculator());
	
			Object message = plainFactory.nextObject();
	
			if (message instanceof PGPCompressedData) {
				final PGPCompressedData cData = (PGPCompressedData) message;
				final PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
				message = pgpFact.nextObject();
			}
			
			if (message instanceof PGPLiteralData) {
				final PGPLiteralData ld = (PGPLiteralData) message;
				idInputStream = ld.getInputStream();
				int ch;
	
				while ((ch = idInputStream.read()) >= 0) {
					out.write(ch);
				}
			} else if (message instanceof PGPOnePassSignatureList) {
				throw new PGPException("Encrypted message contains a signed message - not literal data.");
			} else {
				throw new PGPException("Message is not a simple encrypted file - type unknown.");
			}
	
			if (publicKeyEncryptedData.isIntegrityProtected()) {
				if (!publicKeyEncryptedData.verify()) {
					throw new PGPException("Message failed integrity check");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			closeStream(idInputStream);
			closeStream(privateKeyInputStream);
		}
	}

	public static void encryptFile(OutputStream out, String fileName, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck) throws IOException, NoSuchProviderException, PGPException {
		
		Security.addProvider(new BouncyCastleProvider());
		OutputStream encDataGenerator = null;
		
		try {
			if (armor) {
				out = new ArmoredOutputStream(out);
			}
	
			final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
			PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
			comData.close();
	
			final BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
			dataEncryptor.setWithIntegrityPacket(withIntegrityCheck);
			dataEncryptor.setSecureRandom(new SecureRandom());
	
			final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
			encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));
	
			final byte[] bytes = bOut.toByteArray();
			encDataGenerator = encryptedDataGenerator.open(out, bytes.length);
			encDataGenerator.write(bytes);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			closeStream(encDataGenerator);
		}

	}

	public static boolean isForEncryption(PGPPublicKey key) {
		if (key.getAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN || key.getAlgorithm() == PublicKeyAlgorithmTags.DSA
				|| key.getAlgorithm() == PublicKeyAlgorithmTags.EC
				|| key.getAlgorithm() == PublicKeyAlgorithmTags.ECDSA) {
			return false;
		}

		return hasKeyFlags(key, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
	}

	private static boolean hasKeyFlags(PGPPublicKey encKey, int keyUsage) {
		if (encKey.isMasterKey()) {
			for (int i = 0; i != MASTER_KEY_CERTIFICATION_TYPES.length; i++) {
				for (Iterator<PGPSignature> eIt = encKey.getSignaturesOfType(MASTER_KEY_CERTIFICATION_TYPES[i]); eIt.hasNext();) {
					PGPSignature sig = eIt.next();
					if (!isMatchingUsage(sig, keyUsage)) {
						return false;
					}
				}
			}
		} else {
			for (Iterator<PGPSignature> eIt = encKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING); eIt.hasNext();) {
				PGPSignature sig = eIt.next();
				if (!isMatchingUsage(sig, keyUsage)) {
					return false;
				}
			}
		}
		return true;
	}

	private static boolean isMatchingUsage(PGPSignature sig, int keyUsage) {
		if (sig.hasSubpackets()) {
			PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
			if (sv.hasSubpacket(KEY_FLAGS)) {
				if ((sv.getKeyFlags() == 0 && keyUsage == 0)) {
					return false;
				}
			}
		}
		return true;
	}
	
	public static void closeStream(Closeable c) {
 		if (c != null) {
 			try {
 				c.close();
 			} catch (IOException e) {
 				e.printStackTrace();
 			}
 		}
 	}

}
