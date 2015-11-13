/**
 * Applic_Reservations
 *
 * Copyright (C) 2012 Sh1fT
 *
 * This file is part of Applic_Reservations.
 *
 * Applic_Reservations is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3 of the License,
 * or (at your option) any later version.
 *
 * Applic_Reservations is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Applic_Reservations; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

package applic_reservations;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.Md5;
import utils.PropertiesLauncher;

/**
 * Manage an {@link Applic_Reservations}
 * @author Sh1fT
 */
public class Applic_Reservations {
    private PropertiesLauncher propertiesLauncher;
    private SecretKey secretKey;
    private KeyPair keyPair;

    /**
     * Create a new {@link Applic_Reservations} instance
     */
    public Applic_Reservations() {
        this.setPropertiesLauncher(new PropertiesLauncher(
                System.getProperty("file.separator") + "properties" +
                System.getProperty("file.separator") + "Applic_Reservations.properties"));
        this.setSecretKey(null);
        this.setKeyPair(null);
    }

    /**
     * Execute a Command
     * @param args
     * @return 
     */
    public Object sendCmd(String[] args) {
        try {
            Socket socket = new Socket(this.getServerAddress(), this.getServerPort());
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                    socket.getOutputStream()), true);
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            String assembledCmd = "";
            for (String arg : args)
                assembledCmd += arg + ":";
            pw.println(assembledCmd);
            Object response = ois.readObject();
            ois.close();
            pw.close();
            socket.close();
            return response;
        } catch (IOException | ClassNotFoundException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
        return null;
    }

    /**
     * Generate a secret key
     */
    public void genSecretKey() {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("Rijndael", "BC");
            keygen.init(256, new SecureRandom());
            this.setSecretKey(keygen.generateKey());
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
    }

    /**
     * Encrypt the client name
     * @param clientName
     * @return 
     */
    public String encryptClientName(String clientName) {
        try {
            Cipher cipher = Cipher.getInstance("Rijndael/CBC/PKCS5Padding", "BC");
            byte[] initVector = new byte[16];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(initVector);
            cipher.init(Cipher.ENCRYPT_MODE, this.getSecretKey(),
                    new IvParameterSpec(initVector));
            return Base64.encode(cipher.doFinal(clientName.getBytes())) +
                    "~" + Base64.encode(initVector) + "~";
        } catch (NoSuchAlgorithmException | NoSuchProviderException | 
                NoSuchPaddingException | IllegalBlockSizeException |
                BadPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
        return null;
    }

    /**
     * Decrypt the client name
     * @param clientName
     * @return 
     */
    public String decryptClientName(String clientName) {
        try {
            Cipher cipher = Cipher.getInstance("Rijndael/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, this.getSecretKey(),
                    new IvParameterSpec(Base64.decode(clientName.split("~")[1])));
            return new String(cipher.doFinal(Base64.decode(clientName.split("~")[0])));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | 
                NoSuchPaddingException | IllegalBlockSizeException |
                BadPaddingException | InvalidKeyException |
                Base64DecodingException | InvalidAlgorithmParameterException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
        return null;
    }

    /**
     * Generate a key pair
     */
    public void genKeyPair() {
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
            keygen.initialize(4096, new SecureRandom());
            this.setKeyPair(keygen.generateKeyPair());
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
    }

    /**
     * Generate a signature
     * @return 
     */
    public String genSignature(String text) {
        try {
            Signature sig = Signature.getInstance("MD5WithRSA");
            sig.initSign(this.getKeyPair().getPrivate());
            sig.update(text.getBytes());
            return Base64.encode(sig.sign());
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                SignatureException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
        return null;
    }

    public PropertiesLauncher getPropertiesLauncher() {
        return propertiesLauncher;
    }

    public void setPropertiesLauncher(PropertiesLauncher propertiesLauncher) {
        this.propertiesLauncher = propertiesLauncher;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public Properties getProperties() {
        return this.getPropertiesLauncher().getProperties();
    }

    public String getServerAddress() {
        return this.getProperties().getProperty("serverAddress");
    }

    public Integer getServerPort() {
        return Integer.parseInt(this.getProperties().getProperty("serverPort"));
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            Applic_Reservations ar = new Applic_Reservations();
            String cmd = ".4S&v";
            String cmdTemp = "";
            String response = "";
            String name = "";
            String password = "";
            String category = "";
            String type = "";
            String arrival = "";
            String nights = "";
            String signature = "";
            String clientName = "";
            String idRoom = "";
            String creditCard = "";
            String listRooms = "";
            Boolean logged = false;
            PublicKey serverPublicKey = null;
            ar.genSecretKey();
            ar.genKeyPair();
            serverPublicKey = (PublicKey) ar.sendCmd(new String[] {"EXCHKEY",
                Base64.encode(ar.getKeyPair().getPublic().getEncoded()).
                    replace("\n", "")});
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            ar.sendCmd(new String[] {"SENDKEY", Base64.encode(cipher.doFinal(
                ar.getSecretKey().getEncoded())).replace("\n", "")});
            InputStreamReader isr = new InputStreamReader(System.in);
            BufferedReader br = new BufferedReader(isr);
            do {
                if (cmd.equals(".4S&v")) {
                    System.out.println("Veuillez entrer une commande: ");
                    cmd = br.readLine();
                }
                if (!logged) {
                    cmdTemp = cmd;
                    cmd = "LOGIN";
                }
                switch (cmd) {
                    case "LOGIN":
                        System.out.println("~ Identification ~");
                        System.out.println("Name: ");
                        name = br.readLine();
                        System.out.println("Password: ");
                        password = Md5.encode(br.readLine());
                        response = (String) ar.sendCmd(new String[] {cmd, name, password});
                        switch (response) {
                            case "OK":
                                System.out.println("Login successfully executed :)");
                                logged = true;
                                if (!cmdTemp.equals(""))
                                    cmd = cmdTemp;
                                else
                                    cmd = ".4S&v";
                                break;
                            case "KO":
                                System.out.println("Login not successfully executed :(");
                                cmd = ".4S&v";
                                break;
                            default:
                                break;
                        }
                       break;
                    case "BROOM":
                        System.out.println("~ Booking Room ~");
                        System.out.println("Category: ");
                        category = br.readLine();
                        System.out.println("Type: ");
                        type = br.readLine();
                        System.out.println("Arrival (dd/mm/yyyy): ");
                        arrival = br.readLine();
                        System.out.println("Nights: ");
                        nights = br.readLine();
                        System.out.println("Client name: ");
                        clientName = ar.encryptClientName(br.readLine());
                        signature = ar.genSignature("BROOM_SIG").replace("\n", "");
                        response = (String) ar.sendCmd(new String[] {cmd, category, type,
                            arrival, nights, clientName, signature});
                        System.out.println("Room's id: " + response);
                        cmd = ".4S&v";
                        break;
                    case "PROOM":
                        System.out.println("~ Pay Room ~");
                        System.out.println("Room's id: ");
                        idRoom = br.readLine();
                        System.out.println("Client name: ");
                        clientName = ar.encryptClientName(br.readLine());
                        System.out.println("Credit card: ");
                        creditCard = br.readLine();
                        signature = ar.genSignature("PROOM_SIG").replace("\n", "");
                        response = (String) ar.sendCmd(new String[] {cmd, idRoom, clientName,
                            creditCard, signature});
                        switch (response) {
                            case "OK":
                                System.out.println("Pay successfully executed :)");
                                break;
                            case "KO":
                                System.out.println("Pay not successfully executed :(");
                                break;
                            default:
                                break;
                        }
                        cmd = ".4S&v";
                        break;
                    case "CROOM":
                        System.out.println("~ Cancel Room ~");
                        System.out.println("Room's id: ");
                        idRoom = br.readLine();
                        System.out.println("Client name: ");
                        clientName = ar.encryptClientName(br.readLine());
                        signature = ar.genSignature("CROOM_SIG").replace("\n", "");
                        response = (String) ar.sendCmd(new String[] {cmd, idRoom, clientName,
                            signature});
                        switch (response) {
                            case "OK":
                                System.out.println("Cancel successfully executed :)");
                                break;
                            case "KO":
                                System.out.println("Cancel not successfully executed :(");
                                break;
                            default:
                                break;
                        }
                        cmd = ".4S&v";
                        break;
                    case "LROOMS":
                        System.out.println("~ List of Rooms ~");
                        listRooms = (String) ar.sendCmd(new String[] {cmd});
                        String[] lrs = ar.decryptClientName(listRooms).split(":");
                        for (Integer i=0; i < lrs.length-1; i++) {
                            System.out.println("Room's id: " + lrs[i]);
                            System.out.println("Client's name: " + lrs[i+1]);
                        }
                        cmd = ".4S&v";
                        break;
                }
            } while (cmd != "");
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException |
                NoSuchPaddingException | NoSuchProviderException |
                IllegalBlockSizeException | BadPaddingException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }
    }
}