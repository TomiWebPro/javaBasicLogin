import java.nio.charset.StandardCharsets;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileWriter;
import java.io.IOException;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import com.google.gson.Gson;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import com.google.gson.reflect.TypeToken;


public class Main {
    public static Map<Integer, Map<String, String>> loginDatabase = new HashMap<>();
    public static String globalKey;
    public static boolean loggedInStatus = false;

    public static void print(String toPrint) {
        System.out.print(toPrint);
    }

    public static void println(String toPrint) {
        System.out.println(toPrint);
    }

    public static String inputString(String toPrint) { //working
        System.out.print(toPrint);

        // Use a single Scanner instance
        Scanner scanner = new Scanner(System.in);
        String inputString;

        while (true) {
            inputString = scanner.nextLine().trim();

            // Check if the input is empty
            if (inputString.isEmpty()) {
                println("Input cannot be empty.");
                print("Do you really want to leave it empty? (y/n): ");

                String response = scanner.nextLine().trim().toLowerCase();

                if (response.equals("y")) {
                    return "";  // Return empty string if the user confirms
                } else if (response.equals("n")) {
                    print(toPrint);  // Prompt again for input
                } else {
                    println("Invalid input, please enter 'y' or 'n'.");
                }
            } else {
                // Check if the input is a valid integer
                try {
                    Integer.parseInt(inputString); // Try to parse input as an integer
                    println("Input is an integer. Please enter a valid string.");
                    print(toPrint); // Prompt again
                } catch (NumberFormatException e) {
                    break; // Valid non-integer input
                }
            }
        }

        return inputString;
    }

    public static boolean inputYN(String toPrint) {
        print(toPrint);

        // Use a single Scanner instance
        Scanner scanner = new Scanner(System.in);
        String inputString;

        while (true) {
            inputString = scanner.nextLine().trim();

            // Check if the input is empty
            if (inputString.isEmpty()) {
                System.out.println("Input cannot be empty.");
                continue; // Re-prompt if the input is empty
            }

            // Handle 'y' or 'n' input
            String response = inputString.toLowerCase();
            if (response.equals("y")) {
                return true;  // Return true if 'y' is input
            } else if (response.equals("n")) {
                return false;  // Return false if 'n' is input
            } else {
                println("Invalid input, please enter 'y' or 'n'.");
            }
        }
    }

    public static double inputDouble(String toPrint) {
        print(toPrint);

        // Use a single Scanner instance
        Scanner scanner = new Scanner(System.in);
        String inputString;

        while (true) {
            inputString = scanner.nextLine().trim();

            // Check if the input is empty
            if (inputString.isEmpty()) {
                println("Input cannot be empty.");
                print("Do you really want to leave it empty? (y/n): ");

                String response = scanner.nextLine().trim().toLowerCase();

                if (response.equals("y")) {
                    return Double.NaN;  // Return NaN (Not a Number) if the user confirms empty input
                } else if (response.equals("n")) {
                    print(toPrint);  // Prompt again for input
                } else {
                    println("Invalid input, please enter 'y' or 'n'.");
                }
            } else {
                // Check if the input is a valid double
                try {
                    return Double.parseDouble(inputString);  // Try to parse input as a double
                } catch (NumberFormatException e) {
                    println("Input is not a valid double. Please enter a valid number.");
                    print(toPrint);  // Prompt again for input
                }
            }
        }
    }

    public static int inputInt(String toPrint) {
        print(toPrint);
        Scanner scanner = new Scanner(System.in);
        int inputInt = 0;
        boolean validInput = false;

        while (!validInput) {
            try {
                inputInt = Integer.parseInt(scanner.nextLine().trim()); // Read entire line and parse it
                validInput = true;
            } catch (NumberFormatException e) {
                println("Wrong input! Whole Number expected! Please try again.");
                print(toPrint); // Prompt again
            }
        }
        return inputInt;
    }

    public static String hashThreeTimes(String input, String additionalChr) {
        try {
            // Create a MessageDigest instance for SHA-512
            MessageDigest md = MessageDigest.getInstance("SHA-512");

            // Convert the input string to bytes
            String toHashStr = input + additionalChr;
            for (int i = 0; i < 3; i++) {
                byte[] hashedBytes = toHashStr.getBytes();
                hashedBytes = md.digest(hashedBytes);

                // Convert the final byte array to a hexadecimal string
                StringBuilder hexString = new StringBuilder();
                for (byte b : hashedBytes) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) {
                        hexString.append('0');
                    }
                    hexString.append(hex);
                }

                toHashStr = hexString.toString();
                toHashStr += additionalChr;
            }
            // Return the result
            return toHashStr.replaceAll(".{2}$", "");

        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-512 algorithm not found!");
            return null;
        }
    }

    public static String encrypt(String plainText, String key) {
        try {
            // Create a new AES cipher instance with CBC mode and PKCS5 padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Convert the key to a SecretKeySpec
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            // Generate a random 16-byte IV
            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Initialize the cipher for encryption with the key and IV
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            // Perform encryption
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Return the IV and encrypted string encoded in Base64
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
            return ivBase64 + ":" + encryptedBase64;
        } catch (Exception e) {
            //e.printStackTrace();
            return null; // Return null in case of an error
        }
    }

    public static String decrypt(String encryptedText, String key) {
        try {
            // Split the encrypted text into IV and ciphertext
            String[] parts = encryptedText.split(":");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid encrypted text format");
            }

            // Decode the IV and ciphertext from Base64
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);

            // Convert the key to a SecretKeySpec
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

            // Create a new AES cipher instance with CBC mode and PKCS5 padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Initialize the cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            // Perform decryption
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Return the decrypted string
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            //e.printStackTrace();
            return null; // Return null in case of an error
        }
    }

    private static String getMacAddressOrDefault() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface network = interfaces.nextElement();

                if (network == null || network.isLoopback() || !network.isUp()) {
                    continue;
                }

                byte[] macBytes = network.getHardwareAddress();
                if (macBytes == null) {
                    continue;
                }

                StringBuilder macAddress = new StringBuilder();
                for (byte b : macBytes) {
                    macAddress.append(String.format("%02X:", b)); // Add each byte as hex
                }

                // Remove trailing colon
                if (!macAddress.isEmpty()) {
                    macAddress.setLength(macAddress.length() - 1);
                }

                return macAddress.toString(); // Return the first valid MAC address
            }
        } catch (SocketException e) {
            System.err.println("Error retrieving MAC address: " + e.getMessage());
        }

        // If no MAC address is found, return default value
        print("Error: Unable to retrieve MAC address of your machine, your saved credential may fail to work.");
        return "123";
    }

    public static void initializeGlobalKey() {
        globalKey = getMacAddressOrDefault();
        //println("Global Key is set to: " + globalKey);
    }

    public static void createNewUser() {
        boolean create = inputYN("To create a New User? (y/n) ");
        if (create) {
            HashMap<String, String> newUserCredential = new HashMap<>();
            String plainUsername;

            while (true) {
                plainUsername = inputString("Your username: ");
                String hashedUsername = hashThreeTimes(plainUsername, globalKey);

                boolean userFound = loginDatabase.values().stream()
                        .anyMatch(cred -> {
                            assert hashedUsername != null;
                            return hashedUsername.equals(cred.get("Username"));
                        });

                if (!userFound) {
                    if (inputYN("Username set as " + plainUsername + "? (y/n) ")) {
                        newUserCredential.put("Username", hashedUsername);
                        break;
                    }
                } else {
                    println("User name already taken.");
                }
            }

            while (true) {
                String plainPassword = inputString("Your Password: ");
                if (inputYN("Password set as " + plainPassword + "? (y/n) ")) {
                    newUserCredential.put("Password", hashThreeTimes(plainPassword, globalKey));
                    break;
                }
            }

            println("Account " + plainUsername + " is created!");
            loginDatabase.put(loginDatabase.size() + 1, newUserCredential);

            // Save database to file after creating a user
            saveDatabaseToFile("userDatabase.txt");
        }
    }

    public static void deleteUser() {
        boolean confirmDeleteAction = inputYN("To delete a user? (y/n) ");
        if (confirmDeleteAction) {
            String usernameToDelete = inputString("Enter the username to delete: ");
            String hashedUsername = hashThreeTimes(usernameToDelete, globalKey);
            boolean userFound = false;

            Iterator<Map.Entry<Integer, Map<String, String>>> iterator = loginDatabase.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<Integer, Map<String, String>> entry = iterator.next();
                if (entry.getValue().get("Username").equals(hashedUsername)) {
                    userFound = true;

                    String enteredPassword = inputString("Enter the password for " + usernameToDelete + ": ");
                    if (entry.getValue().get("Password").equals(hashThreeTimes(enteredPassword, globalKey))) {
                        iterator.remove();
                        println("User " + usernameToDelete + " has been deleted.");

                        // Save database to file after deleting a user
                        saveDatabaseToFile("userDatabase.txt");
                    } else {
                        println("Incorrect password. Deletion aborted.");
                    }
                    break;
                }
            }

            if (!userFound) {
                println("Username not found. No user was deleted.");
            }
        }
    }

    public static boolean checkLogIn() {
        String inputUsername = inputString("Your username: ");
        String hashedUsername = hashThreeTimes(inputUsername, globalKey);

        // Iterate through the loginDatabase to find the user
        for (Map.Entry<Integer, Map<String, String>> entry : loginDatabase.entrySet()) {
            Map<String, String> userCredentials = entry.getValue();
            String storedHashedUsername = userCredentials.get("Username");

            if (storedHashedUsername != null && storedHashedUsername.equals(hashedUsername)) {
                String storedHashedPassword = userCredentials.get("Password");

                if (storedHashedPassword != null) {
                    int loginAttempt = 3;

                    while (loginAttempt > 0) {
                        String inputPassword = inputString("Your password: ");
                        if (storedHashedPassword.equals(hashThreeTimes(inputPassword, globalKey))) {
                            println("Login Success!\n");
                            return true;
                        } else {
                            println("Wrong Password");
                            loginAttempt -= 1;
                        }
                    }

                    // If all attempts are used up, return false
                    println("Too many failed attempts. Login failed.");
                    return false;
                }
            }
        }

        // User not found after iterating through the database
        println("User not found");
        return false;
    }

    public static void saveToFile(String content, String relativePath) {
        try (FileWriter writer = new FileWriter(relativePath)) {
            writer.write(content);
            //println("File saved successfully at: " + relativePath);
        } catch (IOException e) {
            System.err.println("An error occurred while saving the file: " + e.getMessage());
        }
    }

    public static boolean createTxtFile(String relativePath) {
        File file = new File(relativePath);
        try {
            if (file.createNewFile()) {
                System.err.println("File created successfully at: " + relativePath);
                return true;
            } else {
                System.err.println("File already exists at: " + relativePath);
                return false;
            }
        } catch (IOException e) {
            System.err.println("An error occurred while creating the file: " + e.getMessage());
            return false;
        }
    }

    public static boolean checkFileExist(String relativePath) {
        File file = new File(relativePath);
        return file.exists();
    }

    public static String readFileIncAll(String relativePath) {
        try {
            return Files.readString(Paths.get(relativePath));
        } catch (IOException e) {
            System.err.println("An error occurred while reading the file: " + e.getMessage());
            return null;
        }
    }

    public static String mapToString(Map<Integer, Map<String, String>> map) {
        Gson gson = new Gson();
        return gson.toJson(map);  // Convert map to JSON string
    }

    public static Map<Integer, Map<String, String>> stringToMap(String str) {
        Gson gson = new Gson();
        TypeToken<Map<Integer, Map<String, String>>> typeToken = new TypeToken<>() {
        };
        return gson.fromJson(str, typeToken.getType());
    }

    public static void saveDatabaseToFile(String filePath) {
        String jsonString = mapToString(loginDatabase);  // Convert map to JSON string
        saveToFile(jsonString, filePath);               // Save JSON string to file
    }

    public static void loadDatabaseFromFile(String filePath) {
        if (checkFileExist(filePath)) {
            String jsonString = readFileIncAll(filePath);  // Read JSON string from file
            if (jsonString != null && !jsonString.isEmpty()) {
                Map<Integer, Map<String, String>> loadedData = stringToMap(jsonString);  // Convert JSON string back to map
                loginDatabase.clear();  // Clear current data to avoid merging
                loginDatabase.putAll(loadedData);  // Load the data into loginDatabase
            }
        } else {
            println("Database file does not exist. Starting with an empty database.");
        }
    }

    public static void loginPortal() {
        if (!loggedInStatus){
            int choice = inputInt("""
                    Welcome to login portal,\s
                    [1] Log In
                    [2] Create Account
                    [3] Delete account
                    >""");
            switch (choice) {
                case 1:
                    loggedInStatus = checkLogIn();
                    loginPortal();
                    break;
                case 2:
                    createNewUser();
                    loginPortal();
                    break;
                case 3:
                    deleteUser();
                    loginPortal();
                    break;
                default:
                    System.out.println("Invalid choice. Please choose one option. ");
                    break;
            }
        }else{
            int choice = inputInt("Welcome to App!\n"); //the code ends here. You can add functionalities yourself from here on, the current placeholder is an input int
        }
    }


    public static void main(String[] args) {
        initializeGlobalKey();
        String filePath = "userDatabase.txt";
        loadDatabaseFromFile(filePath);
        loginPortal();
        saveDatabaseToFile(filePath);
    }
}