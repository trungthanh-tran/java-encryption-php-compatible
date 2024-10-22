package vn.vgpjsc.crypt;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import java.util.Base64;
import java.security.SecureRandom;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class MacCalculationExample {
	private String key;
	private byte[] keyBytes;
	public static void main(String[] args) {
		try {
			// Clear text to be encrypted. You set your info here
			String clearText = "Crazy Fox";
			MacCalculationExample acCalculationExample = new MacCalculationExample("/*Your base64 key from php env here*/");
			String php = acCalculationExample.calculatePHPModel(clearText);
			System.out.println(php);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public MacCalculationExample(String key) {
		this.key = key;
		this.keyBytes = Base64.getDecoder().decode(this.key);
	}
	
	public String getKey() {
		return this.key;
	}
	
	public String calculatePHPModel(String clearText) throws Exception {
		String toPHP = null;
		SecureRandom secureRandom = new SecureRandom();
		byte[] ivGen = new byte[16];
		secureRandom.nextBytes(ivGen);
		String base64Iv = Base64.getEncoder().encodeToString(ivGen);

		byte[] iv = Base64.getDecoder().decode(base64Iv);
		SecretKeySpec secretKey = new SecretKeySpec(this.keyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

		byte[] encryptedValue = cipher.doFinal(clearText.getBytes("UTF-8"));
		String encryptedData = Base64.getEncoder().encodeToString(encryptedValue);
		String hash = hash(base64Iv, encryptedData);

		EncryptionData encryptionData = new EncryptionData(base64Iv, encryptedData, hash);
		Gson gson = new GsonBuilder().disableHtmlEscaping().create(); // No special escaping
		String json = gson.toJson(encryptionData);
		// Check for JSON errors
		if (json == null) {
			throw new Exception("Could not encrypt the data.");
		}
		toPHP = Base64.getEncoder().encodeToString(json.getBytes());
		return toPHP;
	}

	/**
	 * Calculate MACSHA256 as PHP
	 * 
	 * @param iv    IV from AES as String
	 * @param value encoded String in Base64
	 * @param key   base64
	 * @return SHA256
	 * @throws Exception
	 */
	public String hash(String iv, String value) throws Exception {
		// Calculate as PHP crypt
		String data = iv + value;

		// Create HMAC using SHA-256
		Mac mac = Mac.getInstance("HmacSHA256");
		SecretKeySpec secretKeySpec = new SecretKeySpec(this.keyBytes, "HmacSHA256");
		mac.init(secretKeySpec);

		// Compute the MAC
		byte[] macBytes = mac.doFinal(data.getBytes("UTF-8"));
		return new String(Hex.encodeHex(macBytes));
	}

	static final String HEXES = "0123456789abcdef";

	/**
	 * Hex to string
	 * @param raw
	 * @return
	 */
	public static String getHex(byte[] raw) {
		if (raw == null) {
			return null;
		}
		final StringBuilder hex = new StringBuilder(2 * raw.length);
		for (final byte b : raw) {
			hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
		}
		return hex.toString();
	}

}

/**
 * PHP model for crypt
 * @author me
 *
 */
class EncryptionData {
	public String iv;
	public String value;
	public String mac;

	// Constructor
	public EncryptionData(String iv, String value, String mac) {
		this.iv = iv;
		this.value = value;
		this.mac = mac;
	}
}
