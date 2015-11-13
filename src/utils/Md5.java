/**
 * Md5
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

package utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Manage a {@link Md5}
 * @author Sh1fT
 */
public class Md5 {
    /**
     * Encode a String
     * @param password
     * @return 
     */
    public static String encode(String password) {
        byte[] uniqueKey = password.getBytes();
        byte[] hash = null;

        try {
            hash = MessageDigest.getInstance("MD5").digest(uniqueKey);
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Error: " + ex.getLocalizedMessage());
            System.exit(1);
        }

        StringBuilder hashString = new StringBuilder();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(hash[i]);
            if (hex.length() == 1) {
                hashString.append('0');
                hashString.append(hex.charAt(hex.length() - 1));
            }
            else
                hashString.append(hex.substring(hex.length() - 2));
        }
        return hashString.toString();
    }

    /**
     * 
     * @param args 
     */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Md5 <string_to_encode>");
            return;
        }

        String toEncode = args[0];

        System.out.println("Original string ... " + toEncode);
        System.out.println("String MD5 ........ " + encode(toEncode));
    }
}