package com.project.terminal;

import com.sun.javacard.apduio.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Terminal {

	private static InputStream is;
	private static OutputStream os;
	private static CadClientInterface cad;
    private static Socket socket;
    
    private static String cap_path = "..\\CardApplet\\apdu_scripts\\cap-com.project.wallet.script";
    
    private static byte[] pin = new byte[] {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05};
    private static byte[] key = "ana_are_farfurii".getBytes(); // idk men ran out of ideas

	public static void main(String[] args) {
		System.out.println("Terminal starting...");
		
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			establishConnection();
			powerUp();
			
			System.out.println("Executing cap file...");
			executeCap();
			
			System.out.println("Creating applet...");
			exchangeApdu(createApplet());
			System.out.println("Selecting wallet...");
			exchangeApdu(selectWallet());
			
			System.out.println("Verifying PIN plain text...");
			exchangeApdu(verifyPIN());
			System.out.println("Verifying PIN encrypted...");
			exchangeApdu(verifyEncryptedPIN());
			System.out.println("Getting balance...");
			exchangeApdu(getBalance());
			
			powerDown();
		} catch (Exception e) {
			System.out.println("Caught exception");
			System.out.println(e.getMessage());
		}
        
        System.out.println("Exiting...");
	}

	private static void establishConnection() throws IOException{
		socket = new Socket("localhost", 9025);
        is = socket.getInputStream();
        os = socket.getOutputStream();
        cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
	}
	
	private static void powerUp() throws IOException, CadTransportException {
		byte[] response = cad.powerUp();
		System.out.print("Power up response: ");
		System.out.println(Arrays.toString(response));
	}
	
	private static void powerDown() throws IOException, CadTransportException {
		cad.powerDown();
		System.out.println("CAD powered down");
	}
	
	private static void executeCap() throws IOException, CadTransportException {
		BufferedReader reader = new BufferedReader(new FileReader(cap_path));
		String line = reader.readLine();

		while (line != null) {
			if (line.isEmpty() || line.charAt(0) != '0') {
				line = reader.readLine();
				continue;
			}
			
			System.out.println(line);

			String[] splits = line.split(" ");
			byte[] header = new byte[4];

			for (int i = 0; i < 4; i++) {
				String hex = splits[i].split("x")[1];
				header[i] = DatatypeConverter.parseHexBinary(hex)[0];
			}

			int offset = 5;
			int dataSize = splits.length - offset - 1;
			byte[] dataIn = new byte[dataSize];

			for (int i = 0; i < splits.length - offset - 1; i++) {
				String hex = splits[i + offset].split("x")[1];
				dataIn[i] = DatatypeConverter.parseHexBinary(hex)[0];
			}

			Apdu apdu = new Apdu();
			apdu.command = header;
			apdu.dataIn = dataIn;
			apdu.setDataIn(apdu.dataIn);
			
			cad.exchangeApdu(apdu);
			System.out.println(apdu);
			System.out.println();
			
			line = reader.readLine();
		}
		reader.close();
	}
	
	private static void exchangeApdu(Apdu apdu) throws IOException, CadTransportException {        
		cad.exchangeApdu(apdu);
		
		System.out.println("-----------------");
        System.out.println(apdu);
        System.out.println("-----------------\n");
	}
	
	private static Apdu createApplet() {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x80, (byte) 0xB8, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x14;
		apdu.dataIn = new byte[] {(byte) 0x0a, (byte) 0xa0, (byte) 0x0, (byte) 0x0, 
				(byte) 0x0, (byte) 0x62, (byte) 0x3, (byte) 0x1, 
				(byte) 0xc, (byte) 0x6, (byte) 0x1, (byte) 0x08, 
				(byte) 0x0, (byte) 0x0, (byte) 0x05, (byte) 0x01, 
				(byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05};
		
		apdu.Le = (byte) 0x0a;

		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		return apdu;
	}
	
	private static Apdu selectWallet() {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00};
		
		apdu.Lc = (byte) 0x0a;
		apdu.dataIn = new byte[] {(byte) 0xa0, (byte) 0x0, (byte) 0x0, 
				(byte) 0x0, (byte) 0x62, (byte) 0x3, (byte) 0x1, 
				(byte) 0xc, (byte) 0x6, (byte) 0x1};
		 	
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		return apdu;
	}
	
	private static Apdu verifyPIN() {
		Apdu apdu = new Apdu();

		apdu.command = new byte[] {(byte) 0x80, (byte) 0x20, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x05;
		apdu.dataIn = pin;
		 	
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		return apdu;
	}
	
	private static Apdu verifyEncryptedPIN() throws GeneralSecurityException {
		byte[] encryptedPIN = ecbEncryptPIN();
		Apdu apdu = new Apdu();

		apdu.command = new byte[] {(byte) 0x80, (byte) 0x10, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) encryptedPIN.length;
		apdu.dataIn = encryptedPIN;
		 	
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		
		apdu.Le = (byte) 0x05;
		
		return apdu;
	}
	
	 public static byte[] ecbEncryptPIN() throws GeneralSecurityException {
		byte[] initialValues = new byte[16];
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		
        SecretKey keyValueSpec = new SecretKeySpec(key, "AES");
		AlgorithmParameterSpec initialValuesSpec = new IvParameterSpec(initialValues);
        
        cipher.init(Cipher.ENCRYPT_MODE, keyValueSpec, initialValuesSpec);
        return cipher.doFinal(pin);
    }
	
	private static Apdu getBalance() {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x80, (byte) 0x50, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x01;
		apdu.dataIn = new byte[] {(byte) 0x01};
		
		apdu.Le = (byte) 0x02;
		 	
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		return apdu;
	}
}
