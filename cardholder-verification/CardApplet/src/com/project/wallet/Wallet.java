/** 
 * Copyright (c) 1998, 2019, Oracle and/or its affiliates. All rights reserved.
 */

package com.project.wallet;

import javacard.framework.*;
import javacardx.annotations.*;

import static com.project.wallet.WalletStrings.*;

import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "com.project.wallet"),
	    @StringDef(name = "AppletName", value = "Wallet")},
	    // Insert your strings here 
	name = "WalletStrings")
public class Wallet extends Applet {

	/* constants declaration */

    // code of CLA byte in the command APDU header
    final static byte Wallet_CLA = (byte) 0x80;

    // codes of INS byte in the command APDU header
    final static byte VERIFY_ENC = (byte) 0x10;
    final static byte VERIFY = (byte) 0x20;
    final static byte CREDIT = (byte) 0x30;
    final static byte DEBIT = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte GET_CVM = (byte) 0x60;

    // maximum balance
    final static short MAX_BALANCE = 0x2710; // 10.000 RON
    // maximum transaction amount
    final static short MAX_TRANSACTION_AMOUNT = 0x258;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    // signal the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    
    final static short SW_DECRYPTION_FAILED = 0x6302;
    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_AMOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;
    // signal the the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    
    final static byte CONDITION1 = (byte) 0x01;
    final static byte C1_LOWER_LIMIT = (byte) 0x00;
    final static byte C1_UPPER_LIMIT = (byte) 0x32;
    
    final static byte CONDITION2 = (byte) 0x02;
    final static byte C2_LOWER_LIMIT = (byte) 0x32;
    final static byte C2_UPPER_LIMIT = (byte) 0x64;
    
    final static byte CONDITION3 = (byte) 0x03;
    final static byte C3_LOWER_LIMIT = (byte) 0x64;
    final static short C3_UPPER_LIMIT = MAX_TRANSACTION_AMOUNT;
    
    final static byte[] key = {97, 110, 97, 95, 97, 114, 101, 95, 102, 97, 114, 102, 117, 114, 105, 105};
    
    /* instance variables declaration */
    OwnerPIN pin;
    short balance;

    private Wallet(byte[] bArray, short bOffset, byte bLength) {
    	
        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        register();

    } // end of the constructor

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        new Wallet(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {

        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;

    }// end of select method

    @Override
    public void deselect() {

        // reset the pin value
        pin.reset();

    }

    @Override
    public void process(APDU apdu) {

        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command

        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            case VERIFY_ENC:
                verifyEncrypted(apdu);
                return;
            case GET_CVM:
                getCVM(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    } // end of process method

    private void credit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        // Lc byte denotes the number of bytes in the
        // data field of the command APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        if ((numBytes != 2) || (byteRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // get the credit amount ISO7816.OFFSET_CDATA
        short creditAmount = (short) ((buffer[ISO7816.OFFSET_CDATA] & 0xFF)<<8 | (buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF));

        // check the credit amount
        if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        // check the new balance
        if ((short) (balance + creditAmount) > MAX_BALANCE) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }

        // credit the amount
        balance = (short) (balance + creditAmount);

    } // end of deposit method
    
    private void debit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        pin.reset();

        byte[] buffer = apdu.getBuffer();

        byte numBytes = (buffer[ISO7816.OFFSET_LC]);

        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        if ((numBytes != 2) || (byteRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short debitAmount = (short) ((buffer[ISO7816.OFFSET_CDATA] & 0xFF)<<8 | (buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF));
        
        // check debit amount
        if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }
     
        if ((short) (balance - debitAmount) < (short) 0) {
            ISOException.throwIt(SW_NEGATIVE_BALANCE);
        }

        balance = (short) (balance - debitAmount);      
    } // end of debit method

    private void getBalance(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        
        // inform system that the applet has finished
        // processing the command and the system should
        // now prepare to construct a response APDU
        // which contains data field
        short le = apdu.setOutgoing();

        if (le < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // informs the CAD the actual number of bytes
        // returned
        apdu.setOutgoingLength((byte) 2);

        // move the balance data into the APDU buffer
        // starting at the offset 0
        
	    buffer[0] = (byte) (balance >> 8);
	    buffer[1] = (byte) (balance & 0xFF);
	    
        // send the 2-byte balance at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short) 0, (short) 2);

    } // end of getBalance method

    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        buffer[0] = 1;
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
            buffer[0] = 0;
        }

        apdu.setOutgoingAndSend((short) 0, (short) 1);
    } // end of validate method
    
    private void verifyEncrypted(APDU apdu) {

    	byte[] pin_iv = new byte[16];
        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());
        if (byteRead != 16) {
        	ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
        
        Key key = buildKey();
        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
       
        cipher.init(key, Cipher.MODE_DECRYPT, pin_iv, (short) 0, (short) 16);
        cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) 16, buffer, (short) 1);
        
        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        buffer[0] = 1;
        if (pin.check(buffer, (short) 1, (byte) 5) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
            buffer[0] = 0;
        }
        
        apdu.setOutgoingAndSend((short) 0, (short) 6);
        
    } // end of validate method
    

    private void getCVM(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	
    	short le = apdu.setOutgoing();

        if (le != 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        apdu.setOutgoingLength((byte) 8);

        buffer[0] = CONDITION1;
        buffer[1] = C1_LOWER_LIMIT;
        buffer[2] = C1_UPPER_LIMIT;
        
        buffer[3] = CONDITION2;
        buffer[4] = C2_LOWER_LIMIT;
        buffer[5] = C2_UPPER_LIMIT;
        
        buffer[6] = CONDITION3;
        buffer[7] = C3_LOWER_LIMIT;
        
        apdu.sendBytes((byte) 0, (byte) 8);
    }
    
    private Key buildKey() {
		Key builder = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
		((AESKey) builder).setKey(key, (short) 0);
		return builder;
	}
}
