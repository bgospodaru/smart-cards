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
    
    private static byte TRANSACTION_DEBIT = 0x01;
    private static byte TRANSACTION_CREDIT = 0x02;
    
    private static byte[] balanceBytes = new byte[2];
    private static short balance = 0;
    
    private static byte[] cvmCodes = new byte[8];
    private static byte[] pinCorrect = new byte[] {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05};
    private static byte[] pinWrong = new byte[] {(byte) 0x02, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05};
    private static byte[] key = "ana_are_farfurii".getBytes(); // idk men ran out of ideas

	public static void main(String[] args) {
		System.out.println("Terminal starting...");
		
		Terminal terminal = new Terminal();
		Security.addProvider(new BouncyCastleProvider());
		
		// caseOne(terminal);
		caseTwo(terminal);
        
        System.out.println("Exiting...");
	}
	
	private static void caseOne(Terminal terminal) {
		try {
			establishConnection();
			powerUp();
			
			System.out.println("Executing cap file...");
			executeCap();
			
			System.out.println("Creating applet...");
			terminal.exchangeApdu(terminal.createApplet());
			System.out.println("Selecting wallet...");
			terminal.exchangeApdu(terminal.selectWallet());
			
			System.out.println("Verifying PIN plain text...");
			terminal.exchangeApdu(terminal.verifyPIN(pinCorrect));
			System.out.println("Verifying PIN encrypted...");
			terminal.exchangeApdu(terminal.verifyEncryptedPIN(pinCorrect));
			System.out.println("Getting balance...");
			terminal.exchangeApdu(terminal.getBalance());
			
			System.out.println("Getting CVM codes...");
			cvmCodes = terminal.exchangeApdu(terminal.getCVM());

			System.out.println("Debit 100$ (should fail)...");
			terminal.makeTransaction(TRANSACTION_DEBIT, (short) 100, pinCorrect);

			System.out.println("Verifying PIN plain text...");
			terminal.exchangeApdu(terminal.verifyPIN(pinCorrect));
			System.out.println("Credit 200$...");
			terminal.makeTransaction(TRANSACTION_CREDIT, (short) 200, pinCorrect);
			System.out.println("Getting balance...");
			balanceBytes = terminal.exchangeApdu(terminal.getBalance());
			balance = (short) ((balanceBytes[0] & 0xFF) << 8 | (balanceBytes[1] & 0xFF));
			System.out.println("Current balance: " + Short.toString(balance));

			System.out.println("Debit 100$...");
			terminal.makeTransaction(TRANSACTION_DEBIT, (short) 100, pinCorrect);
			System.out.println("Getting balance...");
			balanceBytes = terminal.exchangeApdu(terminal.getBalance());
			balance = (short) ((balanceBytes[0] & 0xFF) << 8 | (balanceBytes[1] & 0xFF));
			System.out.println("Current balance: " + Short.toString(balance));
			
			powerDown();
		} catch (Exception e) {
			System.out.println("Caught exception");
			System.out.println(e.getMessage());
		}
	}
	
	private static void caseTwo(Terminal terminal) {
		try {
			establishConnection();
			powerUp();
			
			////// Part 1
			
			System.out.println("Executing cap file...");
			executeCap();
			
			System.out.println("Creating applet...");
			terminal.exchangeApdu(terminal.createApplet());
			System.out.println("Selecting wallet...");
			terminal.exchangeApdu(terminal.selectWallet());
			
			System.out.println("Verifying PIN plain text...");
			terminal.exchangeApdu(terminal.verifyPIN(pinCorrect));
			System.out.println("Verifying PIN encrypted...");
			terminal.exchangeApdu(terminal.verifyEncryptedPIN(pinCorrect));
			
			System.out.println("Credit 300$...");
			terminal.makeTransaction(TRANSACTION_CREDIT, (short) 300, pinCorrect);
			
			System.out.println("Getting balance...");
			terminal.exchangeApdu(terminal.getBalance());
			
			System.out.println("Getting CVM codes...");
			cvmCodes = terminal.exchangeApdu(terminal.getCVM());
			
			////////////////////////////////////////////////////////////////////////////////////////
			
			////// Part 2
			
			System.out.println("Credit 25$...");
			terminal.makeTransaction(TRANSACTION_CREDIT, (short) 25, pinCorrect);
			
			System.out.println("Getting balance...");
			balanceBytes = terminal.exchangeApdu(terminal.getBalance());
			balance = (short) ((balanceBytes[0] & 0xFF) << 8 | (balanceBytes[1] & 0xFF));
			System.out.println("Current balance: " + Short.toString(balance));
			
			
			System.out.println("Debit 60$...");
			terminal.makeTransaction(TRANSACTION_DEBIT, (short) 60, pinCorrect);
			
			System.out.println("Getting balance...");
			balanceBytes = terminal.exchangeApdu(terminal.getBalance());
			balance = (short) ((balanceBytes[0] & 0xFF) << 8 | (balanceBytes[1] & 0xFF));
			System.out.println("Current balance: " + Short.toString(balance));
			
			
			System.out.println("Debit 60$...");
			terminal.makeTransaction(TRANSACTION_DEBIT, (short) 60, pinWrong);
			
			System.out.println("Getting balance...");
			balanceBytes = terminal.exchangeApdu(terminal.getBalance());
			balance = (short) ((balanceBytes[0] & 0xFF) << 8 | (balanceBytes[1] & 0xFF));
			System.out.println("Current balance: " + Short.toString(balance));
			
			////////////////////////////////////////////////////////////////////////////////////////
			
			////// Part 3
			
			System.out.println("Debit 120$...");
			terminal.makeTransaction(TRANSACTION_DEBIT, (short) 120, pinCorrect);
			
			System.out.println("Getting balance...");
			balanceBytes = terminal.exchangeApdu(terminal.getBalance());
			balance = (short) ((balanceBytes[0] & 0xFF) << 8 | (balanceBytes[1] & 0xFF));
			System.out.println("Current balance: " + Short.toString(balance));
			
			
			System.out.println("Debit 120$...");
			terminal.makeTransaction(TRANSACTION_DEBIT, (short) 120, pinWrong);
			
			System.out.println("Getting balance...");
			balanceBytes = terminal.exchangeApdu(terminal.getBalance());
			balance = (short) ((balanceBytes[0] & 0xFF) << 8 | (balanceBytes[1] & 0xFF));
			System.out.println("Current balance: " + Short.toString(balance));

			////////////////////////////////////////////////////////////////////////////////////////
			
			powerDown();
		} catch (Exception e) {
			System.out.println("Caught exception");
			System.out.println(e.getMessage());
		}
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
	
	private byte[] exchangeApdu(Apdu apdu) throws IOException, CadTransportException {        
		cad.exchangeApdu(apdu);
		
		System.out.println("-----------------");
        System.out.println(apdu);
        
        byte[] output = apdu.getDataOut();
        for (int i = 0; i < output.length; i++) {
        	System.out.print(output[i]);
        	System.out.print(" ");
        }
        
        System.out.println("\n-----------------\n");
        
        return output;
	}
	
	private Apdu createApplet() {
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
	
	private Apdu selectWallet() {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00};
		
		apdu.Lc = (byte) 0x0a;
		apdu.dataIn = new byte[] {(byte) 0xa0, (byte) 0x0, (byte) 0x0, 
				(byte) 0x0, (byte) 0x62, (byte) 0x3, (byte) 0x1, 
				(byte) 0xc, (byte) 0x6, (byte) 0x1};
		 	
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		return apdu;
	}
	
	private Apdu verifyPIN(byte[] pin) {
		Apdu apdu = new Apdu();

		apdu.command = new byte[] {(byte) 0x80, (byte) 0x20, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x05;
		apdu.dataIn = pin;
		
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		
		apdu.Le = (byte) 0x01;
		
		return apdu;
	}
	
	private Apdu verifyEncryptedPIN(byte[] pin) throws GeneralSecurityException {
		byte[] encryptedPIN = cbcEncryptPIN(pin);
		Apdu apdu = new Apdu();

		apdu.command = new byte[] {(byte) 0x80, (byte) 0x10, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) encryptedPIN.length;
		apdu.dataIn = encryptedPIN;
		 	
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		
		apdu.Le = (byte) 0x06;
		
		return apdu;
	}
	
	 public byte[] cbcEncryptPIN(byte[] pin) throws GeneralSecurityException {
		byte[] initialValues = new byte[16];
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		
        SecretKey keyValueSpec = new SecretKeySpec(key, "AES");
		AlgorithmParameterSpec initialValuesSpec = new IvParameterSpec(initialValues);
        
        cipher.init(Cipher.ENCRYPT_MODE, keyValueSpec, initialValuesSpec);
        return cipher.doFinal(pin);
    }
	
	private Apdu getBalance() {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x80, (byte) 0x50, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x00;
		apdu.Le = (byte) 0x02;
		return apdu;
	}
	
	private Apdu getCVM() {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x80, (byte) 0x60, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x00;
		apdu.Le = (byte) 0x08;
		return apdu;
	}
	
	private Apdu debit(short amount) {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x80, (byte) 0x40, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x02;
		
		byte[] data = new byte[2];
		data[0] = (byte)(amount >> 8);
		data[1] = (byte) amount;
		
		apdu.dataIn = data;
		 	
		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		return apdu;
	}
	
	private Apdu credit(short amount) {
		Apdu apdu = new Apdu();
		
		apdu.command = new byte[] {(byte) 0x80, (byte) 0x30, (byte) 0x00, (byte) 0x00};
		
		apdu.Lc = (byte) 0x02;
		
		byte[] data = new byte[2];
		data[0] = (byte)(amount >> 8);
		data[1] = (byte) amount;
		
		apdu.dataIn = data;

		apdu.setDataIn(apdu.dataIn, apdu.Lc);
		return apdu;
	}
	
	private byte[] makeTransaction(byte type, short amount, byte[] pin) throws CadTransportException, IOException, GeneralSecurityException {
		if (type == TRANSACTION_CREDIT) {
			return exchangeApdu(credit(amount));
		}
		
		byte rule = getRule(amount);
		byte[] output;
		
		switch (rule) {
		case 0x01:
			return exchangeApdu(debit(amount));
		case 0x02:
			exchangeApdu(verifyPIN(pin));
			return exchangeApdu(debit(amount));
		case 0x03:
			exchangeApdu(verifyEncryptedPIN(pin));
			return exchangeApdu(debit(amount));
		default:
			System.out.println("Something's wrong lol");	
		}
		return null;
	}
	
	private byte getRule(short amount) {
		byte rule = 0;
		for (int i = 0; i < cvmCodes.length; i += 3) {
			if (amount >= (short) cvmCodes[i + 1]) {
				if (cvmCodes[i] == 0x03) { // last rule
					rule = cvmCodes[i];
					break;
				}
				
				if (amount < (short) cvmCodes[i + 2]) {
					rule = cvmCodes[i];
					break; 
				}
			}
		}
		return rule;
	}
}
