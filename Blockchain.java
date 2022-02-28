/*--------------------------------------------------------

1. Name / Date: Vivekraju Vasudevaraju / 11/25/2021

2. Java version used (java -version), if not the official version for the class:

    build 11.0.10+9

3. Precise command-line compilation examples / instructions:

    > javac -cp "gson-2.8.2.jar:" Blockchain.java

4. Precise examples / instructions to run this program:

    In separate shell windows:

    > java -cp "gson-2.8.2.jar:" Blockchain 0
    > java -cp "gson-2.8.2.jar:" Blockchain 1
    > java -cp "gson-2.8.2.jar:" Blockchain 2

All acceptable commands are displayed on the various consoles.

5. List of files needed for running the program.

    a. Blockchain.java

5. Notes:

    The ":" delimiter in  "gson-2.8.2.jar:" for -cp is for MAC. 
    I'm not sure about windows, I guess it's ":;gson-2.8.2.jar" or ".;gson-2.8.2.jar" (unsure).
    
----------------------------------------------------------*/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**********************************  PRIORITY QUEUE **********************************/

/**
 * Class holder for items added to priority queue
 */
class PriorityQueueHolder {

    /**
     * Function to compare item Timestamps and re-order it. 
     * Priority to first added item 
     */
    private static Comparator < BlockRecord > BlockTSComparator = new Comparator < BlockRecord > () {
        @Override
        public int compare(BlockRecord b1, BlockRecord b2) {
            String s1 = b1.getTimestamp();
            String s2 = b2.getTimestamp();
            if (s1 == s2) {
                return 0;
            }
            if (s1 == null) {
                return -1;
            }
            if (s2 == null) {
                return 1;
            }
            return s1.compareTo(s2);
        }
    };

    // Declare priority queue for threads to use
    final static PriorityBlockingQueue < BlockRecord > ourPriorityQueue = new PriorityBlockingQueue < BlockRecord > (100, BlockTSComparator);
    static BlockingQueue < BlockRecord > queue = ourPriorityQueue;

    // Reset queue
    static void clearQueue() { queue.clear(); }

    // Check if queue is empty
    static boolean isEmptyQueue(){ return queue.isEmpty(); }

    // Fetch record from the queue
    static BlockRecord fetchFromQueue(){ 
        BlockRecord currentBlock = new BlockRecord();
        try {
            currentBlock = queue.take(); 
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error fetching from queue!");
        }
        return currentBlock;
    }

    // Add item to the queue
    static void addToQueue(BlockRecord blockRecord) { 
        try {
            queue.put(blockRecord); 
        } catch (Exception e) {
            System.out.println("Error adding to blocking queue!");
            e.printStackTrace();
        }
    }

    // Get full queue
    static BlockingQueue < BlockRecord > getQueue() { return queue; }
    
}

/**********************************  SOLVED PROCESS DATA **********************************/

/**
 * Class to keep track of solved blocks
 */
class SolvedBlocks {
    static ArrayList<String> SolvedBlockedID = new ArrayList<String>();

    public static ArrayList<String> getSolvedBlockedID() { return SolvedBlockedID; }
    public static void setSolvedBlockedID(String SolvedBlockedID) { SolvedBlocks.SolvedBlockedID.add(SolvedBlockedID); }
};

/**********************************  PROCESS DATA **********************************/

/**
 * Class to hold the data and it's digital signature by the process
 */
class ProcessDataHolder {
    String Process;
    String Data;
    byte[] DigitalSignature;

    public String getProcess() { return Process; }
    public void setProcess(String Process) { this.Process = Process; }

    public String getData() { return Data; }
    public void setData(String Data) { this.Data = Data; }

    public byte[] getDigitalSignature() { return DigitalSignature; }
    public void setDigitalSignature(byte[] DigitalSignature) { this.DigitalSignature = DigitalSignature; }
};

/**********************************  BLOCK DATA **********************************/

/**
 * Class to keep track of the input file 
 */
class BlockRecord {
    String BlockID;
    String solvedByProcess;
    String PreviousHash;
    UUID uuid; 
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String WinningHash;
    String Timestamp;

    public String getBlockID() { return BlockID; }
    public void setBlockID(String BID) { this.BlockID = BID; }

    public String getsolvedByProcess() { return solvedByProcess; }
    public void setsolvedByProcess(String solvedByProcess) { this.solvedByProcess = solvedByProcess; }

    public String getPreviousHash() { return this.PreviousHash; }
    public void setPreviousHash(String PH) { this.PreviousHash = PH; }

    public UUID getUUID() { return uuid; }
    public void setUUID(UUID ud) { this.uuid = ud; }

    public String getLname() { return Lname; }
    public void setLname(String LN) { this.Lname = LN; }

    public String getFname() { return Fname; }
    public void setFname(String FN) { this.Fname = FN; }

    public String getSSNum() { return SSNum; }
    public void setSSNum(String SS) { this.SSNum = SS; }

    public String getDOB() { return DOB; }
    public void setDOB(String RS) { this.DOB = RS; }

    public String getDiag() { return Diag; }
    public void setDiag(String D) { this.Diag = D; }

    public String getTreat() { return Treat; }
    public void setTreat(String Tr) { this.Treat = Tr; }

    public String getWinningHash() { return WinningHash; }
    public void setWinningHash(String WH) { this.WinningHash = WH; }

    public String getTimestamp() { return Timestamp; }
    public void setTimestamp(String Timestamp) { this.Timestamp = Timestamp; }

}

/**********************************  PUBLIC KEY DATA HOLDER **********************************/

/**
 * Class to keep track of public key 
 */
class PublicKeyRecord {
    /* Examples of block fields. You should pick, and justify, your own set: */
    String processName;
    String encoded_public_key;
    String public_key;

    public String getProcessName() { return processName; }
    public void setProcessName(String processName) { this.processName = processName; }

    public String getEncodedPublicKey() { return encoded_public_key; }
    public void setEncodedPublicKey(String encoded_public_key) { this.encoded_public_key = encoded_public_key; }

    public String getPublicKey() { return public_key; }
    public void setPublicKey(String public_key) { this.public_key = public_key; }
}
  
/**********************************  PUBLIC KEY  **********************************/

/**
 * Public key server
 */
class PublicKeyServerWorker extends Thread { 
    Socket sock;
    PublicKeyServerWorker(Socket s) { this.sock = s; }

    public void run() { 
        BufferedReader receiveFromClient;
        PrintStream sendToClient;
        String messageFromClient = "";

        try {
            receiveFromClient = new BufferedReader(new InputStreamReader(this.sock.getInputStream())); 
            sendToClient =  new PrintStream(this.sock.getOutputStream()); 

            // Read incoming text
            String publicKeyText;
            while((publicKeyText=receiveFromClient.readLine())!=null && publicKeyText.length()!=0) {
                messageFromClient += publicKeyText;
            }
            
            // Use GSON to parse JSON to Java PublicKeyRecord class
            Gson gson = new Gson();
            PublicKeyRecord publicRecord = gson.fromJson(messageFromClient, PublicKeyRecord.class);

            System.out.println("Received " + publicRecord.getProcessName() + " Public Key");

            // Add processes's respective public key to Hashmap
            Blockchain.keys.put(publicRecord.getProcessName(), publicRecord.getEncodedPublicKey());

            receiveFromClient.close();
            sendToClient.close();
            this.sock.close(); // Close socket
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/**
 * Looper to keep Public Key Server running
 */
class PublicKeyServerLooper implements Runnable {
    int publicKeyServerPort;
    PublicKeyServerLooper(int port) { this.publicKeyServerPort = port; }

    public void run() {
        int queueLength = 6;
        Socket PublicKeySocket;

        try {
            ServerSocket PublicKeyServerSocket = new ServerSocket(this.publicKeyServerPort, queueLength);

            while (true) {
                PublicKeySocket = PublicKeyServerSocket.accept(); // server is waiting for a new admin connection
                new PublicKeyServerWorker(PublicKeySocket).start(); //admin worker thread is crated to handle the new admin connection
            }
        } catch (IOException e) {
            System.out.println("Public Key Server Socket connection error!");
            e.printStackTrace();
        }
    }
}

/**
 * Public Key Client
 */
class PublicKeyServerClient {
    String serverName;
    int port;

    PublicKeyServerClient(String serverName, int port) {
        this.serverName = serverName;
        this.port = port;
    }

    public void connectToServer(String message) {
        Socket socket;
        BufferedReader receiveFromServer;
        PrintStream sendToServer;
        String textFromServer;

        try {
            socket = new Socket(this.serverName, this.port); 
            receiveFromServer = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
            sendToServer =  new PrintStream(socket.getOutputStream()); 
            
            sendToServer.println(message); 
            sendToServer.flush(); 
            
            socket.close(); 
        } catch (Exception e) {
            System.out.println("Public Key Client Socket error. Server might be down!\nShutting down...\n");
            // e.printStackTrace();
            System.exit(0);
        }
    }
}

/**********************************  UNVERIFIED BLOCK  **********************************/

class UnverifiedBlockServerWorker extends Thread { 
    Socket sock;
    UnverifiedBlockServerWorker(Socket s) { this.sock = s; }

    public void run() { 
        BufferedReader receiveFromClient;
        PrintStream sendToClient;
        String textFromClient = "";
        int randomSeedLength = 8;
        final String alphaNumericString = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        SecureRandom secureRandomNumber = new SecureRandom();

        try {
            receiveFromClient = new BufferedReader(new InputStreamReader(this.sock.getInputStream())); 
            sendToClient =  new PrintStream(this.sock.getOutputStream()); 
            
            String blockChain;
            while((blockChain=receiveFromClient.readLine())!=null && blockChain.length()!=0) {
                textFromClient += blockChain;
            }

            if (textFromClient.equals("start_solving_blockchain")) {

                // Shutdown server is there is no more records to solve
                if (PriorityQueueHolder.getQueue().size() == 0) {
                    Thread.sleep(30000);
                    System.out.println("Blockchain fully solved.\nShutting down...\nPrinted output to BlockchainLedger.json");
                    System.exit(0);
                }

                // Fetch item from Priority queue
                BlockRecord block = PriorityQueueHolder.fetchFromQueue();

                // Combine fields to create concatenated string
                String concatRecord = // "Get a string of the block so we can hash it.
                                    block.getBlockID() +
                                    block.getFname() +
                                    block.getLname() +
                                    block.getSSNum() +
                                    block.getDOB() +
                                    block.getDiag() +
                                    block.getTreat();

                System.out.println("Solving blockchain");

                do {
                    try {
                        Thread.sleep(1000);
                        
                        // Get random 8 character AlphaNumeric value
                        String randomSeed = Blockchain.generateRandomSeed(alphaNumericString, secureRandomNumber, randomSeedLength);
                        // Add seed to concatenated string
                        concatRecord += randomSeed;
        
                        /**
                         * Apply SHA-256 algorithm to the above string and convert to HEX string 
                         */
                        MessageDigest SHA256 = MessageDigest.getInstance("SHA-256"); // Start SHA-256
                        byte[] input2byte = concatRecord.getBytes("UTF-8"); // Convert input string to bytes
                        byte[] bytesHash = SHA256.digest(input2byte); // Apply SHA-256 hash on bytes 
                        String bytesHash2Hex = convertBytesToHex(bytesHash); // Convert hash bytes to hex
        
                        // Take first 4 characters of the HEX string
                        int workNumber = Integer.parseInt(bytesHash2Hex.substring(0, 4), 16);

                        // If number is less than 5000 then puzzle is solved
                        if (workNumber < 5000) {
                            block.setWinningHash(bytesHash2Hex); // Update winning Hash value
                            block.setsolvedByProcess(Blockchain.process); // Update solved process
                            upateSolvedBlockChain(block); // Send solved blockchain to other processes's
                            break;
                        }
        
                        block.setPreviousHash(bytesHash2Hex); // Update previous Hash
        
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } while(true); // Infiite loop

            } else {
                // Convert JSON string to Java class
                Gson gson = new Gson();
                ProcessDataHolder BR = gson.fromJson(textFromClient, ProcessDataHolder.class);

                // Fetch Base 64 encoded public from the "keys" Hashmap 
                String encoded_PK = Blockchain.keys.get(BR.getProcess());
                byte[] publicBytes = Base64.getDecoder().decode(encoded_PK);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey pubKey = keyFactory.generatePublic(keySpec);

                String Data = BR.getData();

                // Verify signature
                boolean verified = Blockchain.verifySig(Data.getBytes(), pubKey, BR.getDigitalSignature());

                // If no damage to text
                if (verified) {
                    BlockRecord[] blockRecordIn = gson.fromJson(Data, BlockRecord[].class);
                    for (BlockRecord blockRecord : blockRecordIn) {
                        Blockchain.blocks.add(blockRecord);
                        PriorityQueueHolder.addToQueue(blockRecord);
                        System.out.println("Adding block record from " + BR.getProcess() + " to priority queue");
                    }
                }
            }

            receiveFromClient.close();
            sendToClient.close();
            this.sock.close(); // Close socket connection
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Send solved Blockchain to Process 0 
     */
    private static void upateSolvedBlockChain(BlockRecord block) {
        int process0UpdatePort = Blockchain.hmap.get("Process 0 UpdatedBlockchainPort");
        UpdatedBlockServerClient updateBlockClient = new UpdatedBlockServerClient("localhost", process0UpdatePort);
        updateBlockClient.connectToServer(block);
    }

    /**
     * Convert Bytes to Hex String
     * @param bytesHash
     * @return
     */
    private static String convertBytesToHex(byte[] bytesHash) {
        String hexResult = "";
        for (byte b : bytesHash) {
            hexResult += Integer.toHexString(b);
        }
        return hexResult;
    }

}

class UnverifiedBlockServerLooper implements Runnable {
    int unverifiedBlockServerPort;
    UnverifiedBlockServerLooper(int port) { this.unverifiedBlockServerPort = port; }

    public void run() {
        int queueLength = 6;
        Socket UnverifiedBlockSocket;

        try {
            ServerSocket UnverifiedBlockServerSocket = new ServerSocket(this.unverifiedBlockServerPort, queueLength);

            while (true) {
                UnverifiedBlockSocket = UnverifiedBlockServerSocket.accept(); // server is waiting for a new admin connection
                new UnverifiedBlockServerWorker(UnverifiedBlockSocket).start(); //admin worker thread is crated to handle the new admin connection
            }
        } catch (IOException e) {
            System.out.println("Unverified Block Server Socket connection error!");
            e.printStackTrace();
        }
    }
}

class UnverifiedBlockServerClient {
    String serverName;
    int port;

    UnverifiedBlockServerClient(String serverName, int port) {
        this.serverName = serverName;
        this.port = port;
    }

    public void connectToServer(String message) {
        Socket socket;
        BufferedReader receiveFromServer;
        PrintStream sendToServer;
        String textFromServer;

        try {
            socket = new Socket(this.serverName, this.port); 
            receiveFromServer = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
            sendToServer =  new PrintStream(socket.getOutputStream()); 
            
            sendToServer.println(message); 
            sendToServer.flush(); 
            
            socket.close(); 
        } catch (Exception e) {
            System.out.println("Updated Block Client Socket error. Server might be down!\nShutting down...\n");
            // e.printStackTrace();
            System.exit(0);
        }
    }
}

/**********************************  UPDATED BLOCK  **********************************/

class UpdatedBlockServerWorker extends Thread { 
    Socket sock;
    UpdatedBlockServerWorker(Socket s) { this.sock = s; }

    public void run() { 
        BufferedReader receiveFromClient;
        PrintStream sendToClient;
        String messageFromClient = "";

        try {
            receiveFromClient = new BufferedReader(new InputStreamReader(this.sock.getInputStream())); 
            sendToClient =  new PrintStream(this.sock.getOutputStream()); 
            
            String broadCastText;
            while((broadCastText=receiveFromClient.readLine())!=null && broadCastText.length()!=0) {
                if (broadCastText != null) {
                    messageFromClient += broadCastText;
                }
            }

            // Convert JSON stirng to Java class
            Gson gson = new Gson();
            BlockRecord blockRecordOutput = gson.fromJson(messageFromClient, BlockRecord.class);
            boolean isRecordPresent = false;

            // Check if record is already solved
            for (String blockID : SolvedBlocks.getSolvedBlockedID()) {
                if (blockID.equals(blockRecordOutput.getBlockID())) {
                    isRecordPresent = true;
                    break;
                } 
            }   
            
            // If record is not present write to file
            if (isRecordPresent == false) {
                // Update solved blockchain to class
                SolvedBlocks.setSolvedBlockedID(blockRecordOutput.getBlockID());
                // System.out.println(blockRecordOutput.getFname() + " " + blockRecordOutput.getLname() + " " + blockRecordOutput.getsolvedByProcess() + " " + blockRecordOutput.getBlockID());
                System.out.println(blockRecordOutput.getFname() + " " + blockRecordOutput.getLname() + " -> " + blockRecordOutput.getsolvedByProcess() + " solved a block. Adding to BlockchainLedger.json");

                Gson gsonq = new GsonBuilder().setPrettyPrinting().create();
                // Convert the Java object to a JSON String:
                String json = gsonq.toJson(blockRecordOutput);

                Path fileName = Path.of("BlockchainLedger.json");
                String fileContent = Files.readString(fileName); // Get file contents
                String content;

                // If empty file add []
                if (fileContent.length() == 0) {
                    content = "[" + json + "]"; 
                } else {
                    // Update file contents
                    fileContent = fileContent.substring(1, fileContent.length() - 1); 
                    content = "[" + fileContent + "," + json + "]"; 
                }
                Files.writeString(fileName, content);
            }

            // Continue to solve next block
            Blockchain.blockChainMultiCast("start_solving_blockchain");

            receiveFromClient.close();
            sendToClient.close();
            this.sock.close(); // Close socket
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class UpdatedBlockServerLooper implements Runnable {
    int updatedBlockServerPort;
    UpdatedBlockServerLooper(int port) { this.updatedBlockServerPort = port; }

    public void run() {
        int queueLength = 6;
        Socket UpdatedBlockSocket;

        try {
            ServerSocket UpdatedBlockServerSocket = new ServerSocket(this.updatedBlockServerPort, queueLength);

            while (true) {
                UpdatedBlockSocket = UpdatedBlockServerSocket.accept(); // server is waiting for a new admin connection
                new UpdatedBlockServerWorker(UpdatedBlockSocket).start(); //admin worker thread is crated to handle the new admin connection
            }
        } catch (IOException e) {
            System.out.println("Updated Block Server Socket connection error!");
            e.printStackTrace();
        }
    }
}

class UpdatedBlockServerClient {
    String serverName;
    int port;

    UpdatedBlockServerClient(String serverName, int port) {
        this.serverName = serverName;
        this.port = port;
    }

    public void connectToServer(BlockRecord block) {
        Socket socket;
        BufferedReader receiveFromServer;
        PrintStream sendToServer;
        String textFromServer;

        try {
            socket = new Socket(this.serverName, this.port); 
            receiveFromServer = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
            sendToServer =  new PrintStream(socket.getOutputStream()); 
            
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String json = gson.toJson(block);

            sendToServer.println(json); 
            sendToServer.flush(); 

            // textFromServer = receiveFromServer.readLine();

            // // Print joke to console client
            // if (textFromServer != null){
            //     System.out.println(textFromServer);     
            //     System.out.flush();   
            // }
            
            socket.close(); 
        } catch (Exception e) {
            System.out.println("Updated Block Client Socket error.\nShutting down...\n");
            // e.printStackTrace();
            System.exit(0);
        }
    }
}

/**********************************  BROADCAST  **********************************/

/**
 * Broadcast server to send message to otehr processes
 */
class BroadCastServerWorker extends Thread { 
    Socket sock;
    BroadCastServerWorker(Socket s) { this.sock = s; }

    public void run() { 
        BufferedReader receiveFromClient;
        PrintStream sendToClient;
        String textFromServer = "";

        try {
            receiveFromClient = new BufferedReader(new InputStreamReader(this.sock.getInputStream())); 
            sendToClient =  new PrintStream(this.sock.getOutputStream()); 

            String broadCastText;
            while((broadCastText=receiveFromClient.readLine())!=null && broadCastText.length()!=0) {
                if (broadCastText != null) {
                    textFromServer += broadCastText;
                }
            }

            // Send to process based on the message
            if (textFromServer.equals("process2_connected")) {
                Blockchain.broadcastPublicKeys();
            } else if (textFromServer.equals("blockchain")) {
                Blockchain.blockChainMultiCast(Blockchain.BlockJSONData);
            } else {
                Blockchain.publicKeysMultiCast(textFromServer);
            }

            receiveFromClient.close();
            sendToClient.close();
            this.sock.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class BroadCastLooper implements Runnable {
    int broadCastServerPort;
    BroadCastLooper(int port) { this.broadCastServerPort = port; }

    public void run() {
        int queueLength = 6;
        Socket broadCastSocket;

        try {
            ServerSocket broadCastServerSocket = new ServerSocket(this.broadCastServerPort, queueLength);

            while (true) {
                broadCastSocket = broadCastServerSocket.accept(); // server is waiting for a new admin connection
                new BroadCastServerWorker(broadCastSocket).start(); //admin worker thread is crated to handle the new admin connection
            }
        } catch (IOException e) {
            System.out.println("Broadcast Server Socket connection error!");
            e.printStackTrace();
        }
    }
}

class BroadCastServerClient {
    String serverName;
    int port;

    BroadCastServerClient(String serverName, int port) {
        this.serverName = serverName;
        this.port = port;
    }

    public void connectToServer(String message, String additional_message) {
        Socket socket;
        BufferedReader receiveFromServer;
        PrintStream sendToServer;
        String textFromServer;

        try {
            socket = new Socket(this.serverName, this.port); 
            receiveFromServer = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
            sendToServer =  new PrintStream(socket.getOutputStream()); 

            // Send message appropriately based on the input
            if (additional_message.equals("process2_connected")) {
                sendToServer.println(message); 
                sendToServer.flush(); 
            } else if (additional_message.equals("public_key")) {
                sendToServer.println(message);   
                sendToServer.flush(); 
            } else if (additional_message.equals("blockchain")) {
                sendToServer.println(message);   
                sendToServer.flush();
            }
            
            socket.close(); 
        } catch (Exception e) {
            System.out.println("Broadcast Client Socket error. Server might be down!\nShutting down...\n");
            // e.printStackTrace();
            System.exit(0);
        }
    }
}

/**********************************  MAIN BLOCK  **********************************/

public class Blockchain {
    static String process = "Process 0";
    static HashMap<String, Integer> hmap = new HashMap<String, Integer>();
    static HashMap<String, String> keys = new HashMap<String, String>();
    static List<BlockRecord> blocks = new ArrayList<BlockRecord>();
    static String publicKeyData;
    static String BlockJSONData;
    static PublicKey publicKeyProcess;
    static PrivateKey privateKeyProcess;

    public static void main(String[] args) {
        final int queueLength = 6;
        int PublicKeyPort = 4710;
        int UnverifiedBlockPort = 4820;
        int UpdatedBlockchainPort = 4930;
        int BroadcastPort = 4200;
        final int randomSeedLength = 8;
        final String alphaNumericString = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        SecureRandom secureRandomNumber = new SecureRandom();
        String randomSeed = generateRandomSeed(alphaNumericString, secureRandomNumber, randomSeedLength);

        // Add all available ports to Hashmap
        updateProcessPorts();

        Socket PublicKeySocket;
        Socket UnverifiedBlockSocket;
        Socket UpdatedBlockSocket;

        // Select port based on running process
        if (args.length > 0) {
            switch (args[0]) {
                case "0":
                    process = "Process 0";
                    PublicKeyPort = 4710;
                    UnverifiedBlockPort = 4820;
                    UpdatedBlockchainPort = 4930;
                    BroadcastPort = 4200;
                    break;
                case "1":
                    process = "Process 1";
                    PublicKeyPort = 4711;
                    UnverifiedBlockPort = 4821;
                    UpdatedBlockchainPort = 4931;
                    BroadcastPort = 4201;
                    break;
                case "2":
                    process = "Process 2";
                    PublicKeyPort = 4712;
                    UnverifiedBlockPort = 4822;
                    UpdatedBlockchainPort = 4932;
                    BroadcastPort = 4202;
                    break;
                default:
                    break;
            }
        }

        try {

            // Generate public and private keys
            KeyPair keyPair = generateKeyPair(randomSeed.getBytes());
            Blockchain.publicKeyProcess  = keyPair.getPublic();
            Blockchain.privateKeyProcess = keyPair.getPrivate();
            String publicK = Base64.getEncoder().encodeToString(publicKeyProcess.getEncoded());
            String privateK = Base64.getEncoder().encodeToString(privateKeyProcess.getEncoded());

            // Start servers
            PublicKeyServerLooper publicKey = new PublicKeyServerLooper(PublicKeyPort);
            new Thread(publicKey).start();
            System.out.println("Started Public Key Server running on port " + PublicKeyPort);

            UnverifiedBlockServerLooper unverifiedBlock = new UnverifiedBlockServerLooper(UnverifiedBlockPort);
            new Thread(unverifiedBlock).start();
            System.out.println("Started Unverified Block Server running on port " + UnverifiedBlockPort);

            UpdatedBlockServerLooper updatedBlock = new UpdatedBlockServerLooper(UpdatedBlockchainPort);
            new Thread(updatedBlock).start();
            System.out.println("Started Updated Blockchain Server running on port " + UpdatedBlockchainPort);


            PublicKeyRecord pkRecord = new PublicKeyRecord();
            pkRecord.setProcessName(process);
            pkRecord.setPublicKey(Blockchain.publicKeyProcess.getEncoded().toString());
            pkRecord.setEncodedPublicKey(publicK);

            BroadCastLooper broadCast = new BroadCastLooper(BroadcastPort);
            new Thread(broadCast).start();
            System.out.println("Started Broadcast Server running on port " + BroadcastPort);

            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            Blockchain.publicKeyData = gson.toJson(pkRecord); // Convert the Java object to a JSON String

            readInputTextFile();

            // On Process 2 connection start broadcast
            if (process.equals("Process 2")) {

                PrintWriter writer = new PrintWriter("BlockchainLedger.json");
                writer.print("");
                writer.close();

                broadcastProcess2Connection();
                publicKeysMultiCast(Blockchain.publicKeyData);

                Thread.sleep(2500);

                broadcastStartOfBlockchain();

                blockChainMultiCast(Blockchain.BlockJSONData);

                Thread.sleep(2500);

                blockChainMultiCast("start_solving_blockchain");

                
                // System.out.println("Process 0 Public Key : " + MulticastPublicKeys.keys.get("Process 0"));
                // System.out.println("Process 1 Public Key : " + MulticastPublicKeys.keys.get("Process 1"));
                // System.out.println("Process 2 Public Key : " + MulticastPublicKeys.keys.get("Process 2"));
            }

            System.out.flush();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate random Alphanumeric seed
     */
    public static String generateRandomSeed(String AlphaNumeric, SecureRandom random, int randomSeedLength) {
        StringBuilder seed = new StringBuilder(randomSeedLength);
        for (int i = 0; i < randomSeedLength; i++) {
            seed.append(AlphaNumeric.charAt(random.nextInt(AlphaNumeric.length())));
        }
        return seed.toString();
    }

    /**
     * Sign document with private key
     * @param data
     * @param key
     * @return byte[]
     * @throws Exception
     */
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    /**
     * Verify the authenticity of the signed document with public key
     */
    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);
        return (signer.verify(sig));
    }

    /**
     * Update the process ports
     */
    private static void updateProcessPorts() {
        hmap.put("Process 0 PublicKeyPort", 4710);
        hmap.put("Process 0 UnverifiedBlockPort", 4820);
        hmap.put("Process 0 UpdatedBlockchainPort", 4930);
        hmap.put("Process 0 BroadcastPort", 4200);
        hmap.put("Process 1 PublicKeyPort", 4711);
        hmap.put("Process 1 UnverifiedBlockPort", 4821);
        hmap.put("Process 1 UpdatedBlockchainPort", 4931);
        hmap.put("Process 1 BroadcastPort", 4201);
        hmap.put("Process 2 PublicKeyPort", 4712);
        hmap.put("Process 2 UnverifiedBlockPort", 4822);
        hmap.put("Process 2 UpdatedBlockchainPort", 4932);
        hmap.put("Process 2 BroadcastPort", 4202);
    }

    /**
     * Generate Public and Private keys 
     * @param seed
     * @return KeyPair
     * @throws Exception
     */
    public static KeyPair generateKeyPair(byte[] seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
    }

    /**
     * Start the bockchain solving process
     */
    public static void broadcastStartOfBlockchain() {
        BroadCastServerClient broadCastClient0 = new BroadCastServerClient("localhost", Blockchain.hmap.get("Process 0 BroadcastPort"));
        broadCastClient0.connectToServer("blockchain", "blockchain");

        BroadCastServerClient broadCastClient1 = new BroadCastServerClient("localhost", Blockchain.hmap.get("Process 1 BroadcastPort"));
        broadCastClient1.connectToServer("blockchain", "blockchain");
    }

    /**
     * Tell other process that process 2 connected
     */
    public static void broadcastProcess2Connection() {
        BroadCastServerClient broadCastClient0 = new BroadCastServerClient("localhost", Blockchain.hmap.get("Process 0 BroadcastPort"));
        broadCastClient0.connectToServer("process2_connected", "process2_connected");

        BroadCastServerClient broadCastClient1 = new BroadCastServerClient("localhost", Blockchain.hmap.get("Process 1 BroadcastPort"));
        broadCastClient1.connectToServer("process2_connected", "process2_connected");
    }

    /**
     * Send public keys to all processess
     */
    public static void broadcastPublicKeys() {
        switch (Blockchain.process) {
            case "Process 0":
                BroadCastServerClient broadCastClient0 = new BroadCastServerClient("localhost", Blockchain.hmap.get("Process 0 BroadcastPort"));
                broadCastClient0.connectToServer(Blockchain.publicKeyData, "public_key");
                break;
            case "Process 1":
                BroadCastServerClient broadCastClient1 = new BroadCastServerClient("localhost", Blockchain.hmap.get("Process 1 BroadcastPort"));
                broadCastClient1.connectToServer(Blockchain.publicKeyData, "public_key");
                break;
            case "Process 2":
                BroadCastServerClient broadCastClient2 = new BroadCastServerClient("localhost", Blockchain.hmap.get("Process 2 BroadcastPort"));
                broadCastClient2.connectToServer(Blockchain.publicKeyData, "public_key");
                break;
            default:
                break;
        }
    }

    /**
     * Send blockchain to all processess
     * @param message
     */
    public static void blockChainMultiCast(String message) {

        int process0Port = Blockchain.hmap.get("Process 0 UnverifiedBlockPort");
        int process1Port = Blockchain.hmap.get("Process 1 UnverifiedBlockPort");
        int process2Port = Blockchain.hmap.get("Process 2 UnverifiedBlockPort");

        switch (Blockchain.process) {
            case "Process 0":
                UnverifiedBlockServerClient unverifiedBlockClientProcess0FromProcess0 = new UnverifiedBlockServerClient("localhost", process0Port);
                unverifiedBlockClientProcess0FromProcess0.connectToServer(message);
                UnverifiedBlockServerClient unverifiedBlockClientProcess1FromProcess0 = new UnverifiedBlockServerClient("localhost", process1Port);
                unverifiedBlockClientProcess1FromProcess0.connectToServer(message);
                UnverifiedBlockServerClient unverifiedBlockClientProcess2FromProcess0 = new UnverifiedBlockServerClient("localhost", process2Port);
                unverifiedBlockClientProcess2FromProcess0.connectToServer(message);
                break;
            case "Process 1":
                UnverifiedBlockServerClient unverifiedBlockClientProcess0FromProcess1 = new UnverifiedBlockServerClient("localhost", process0Port);
                unverifiedBlockClientProcess0FromProcess1.connectToServer(message);
                UnverifiedBlockServerClient unverifiedBlockClientProcess1FromProcess1 = new UnverifiedBlockServerClient("localhost", process1Port);
                unverifiedBlockClientProcess1FromProcess1.connectToServer(message);
                UnverifiedBlockServerClient unverifiedBlockClientProcess2FromProcess1 = new UnverifiedBlockServerClient("localhost", process2Port);
                unverifiedBlockClientProcess2FromProcess1.connectToServer(message);
                break;
            case "Process 2":
                UnverifiedBlockServerClient unverifiedBlockClientProcess0FromProcess2 = new UnverifiedBlockServerClient("localhost", process0Port);
                unverifiedBlockClientProcess0FromProcess2.connectToServer(message);
                UnverifiedBlockServerClient unverifiedBlockClientProcess1FromProcess2 = new UnverifiedBlockServerClient("localhost", process1Port);
                unverifiedBlockClientProcess1FromProcess2.connectToServer(message);
                UnverifiedBlockServerClient unverifiedBlockClientProcess2FromProcess2 = new UnverifiedBlockServerClient("localhost", process2Port);
                unverifiedBlockClientProcess2FromProcess2.connectToServer(message);
                break;
            default:
                break;
        }
    }

    /**
     * Multicast public keys
     * @param message
     */
    public static void publicKeysMultiCast(String message) {
        int process0Port = Blockchain.hmap.get("Process 0 PublicKeyPort");
        int process1Port = Blockchain.hmap.get("Process 1 PublicKeyPort");
        int process2Port = Blockchain.hmap.get("Process 2 PublicKeyPort");

        // PublicKeyRecord
        switch (Blockchain.process) {
            case "Process 0":
                PublicKeyServerClient publicKeyClientProcess0FromProcess0 = new PublicKeyServerClient("localhost", process0Port);
                publicKeyClientProcess0FromProcess0.connectToServer(message);
                PublicKeyServerClient publicKeyClientProcess1FromProcess0 = new PublicKeyServerClient("localhost", process1Port);
                publicKeyClientProcess1FromProcess0.connectToServer(message);
                PublicKeyServerClient publicKeyClientProcess2FromProcess0 = new PublicKeyServerClient("localhost", process2Port);
                publicKeyClientProcess2FromProcess0.connectToServer(message);
                break;
            case "Process 1":
                PublicKeyServerClient publicKeyClientProcess0FromProcess1 = new PublicKeyServerClient("localhost", process0Port);
                publicKeyClientProcess0FromProcess1.connectToServer(message);
                PublicKeyServerClient publicKeyClientProcess1FromProcess1 = new PublicKeyServerClient("localhost", process1Port);
                publicKeyClientProcess1FromProcess1.connectToServer(message);
                PublicKeyServerClient publicKeyClientProcess2FromProcess1 = new PublicKeyServerClient("localhost", process2Port);
                publicKeyClientProcess2FromProcess1.connectToServer(message);
                break;
            case "Process 2":
                PublicKeyServerClient publicKeyClientProcess0FromProcess2 = new PublicKeyServerClient("localhost", process0Port);
                publicKeyClientProcess0FromProcess2.connectToServer(message);
                PublicKeyServerClient publicKeyClientProcess1FromProcess2 = new PublicKeyServerClient("localhost", process1Port);
                publicKeyClientProcess1FromProcess2.connectToServer(message);
                PublicKeyServerClient publicKeyClientProcess2FromProcess2 = new PublicKeyServerClient("localhost", process2Port);
                publicKeyClientProcess2FromProcess2.connectToServer(message);
                break;
            default:
                break;
        }
    }

    /**
     * Read input file
     */
    public static void readInputTextFile() {
        String fileName;
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        List<BlockRecord> listOfRecords = new ArrayList<BlockRecord>();

        // Select file based on Process
        switch (Blockchain.process) {
            case "Process 0":
                fileName = "BlockInput0.txt";
                break;
            case "Process 1":
                fileName = "BlockInput1.txt";
                break;
            case "Process 2":
                fileName = "BlockInput2.txt";
                break;
            default:
                fileName = "BlockInput0.txt";
                break;
        }
        
        String Fname;
        String Lname;
        String SSNum;
        String DOB;
        String Diag;
        String Treat;

        try {
            File file = new File(fileName);
            BufferedReader readFile = new BufferedReader(new FileReader(file));
            
            String currentLine;
            while ((currentLine = readFile.readLine()) != null) {
                String fields[] = currentLine.split(" ");

                Fname = fields[0];
                Lname = fields[1];
                DOB = fields[2];
                SSNum = fields[3];
                Diag = fields[4];
                Treat = fields[5] + " " + fields[6];

                UUID UniqueUID = UUID.randomUUID();
                String BlockID = UniqueUID.toString();
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date); // Create the TimeStamp string.
                String TimeStamp = T1 + "." + Blockchain.process.split(" ")[1]; // Use process num extension. No timestamp collisions!

                BlockRecord newBlock = new BlockRecord();
                newBlock.setBlockID(BlockID);
                newBlock.setUUID(UniqueUID); // Later will show JSON translation from binary to string form.
                newBlock.setFname(Fname);
                newBlock.setLname(Lname);
                newBlock.setDOB(DOB);
                newBlock.setSSNum(SSNum);
                newBlock.setDiag(Diag);
                newBlock.setTreat(Treat);
                newBlock.setTimestamp(TimeStamp);

                listOfRecords.add(newBlock);
            }

            // Convert the Java object to a JSON String:
            String jsonData = gson.toJson(listOfRecords);
            byte[] digitalSignature = signData(jsonData.getBytes(), Blockchain.privateKeyProcess);

            ProcessDataHolder PD = new ProcessDataHolder();
            PD.setProcess(Blockchain.process);
            PD.setData(jsonData);
            PD.setDigitalSignature(digitalSignature);

            String json = gson.toJson(PD);

            Blockchain.BlockJSONData = json;

        } catch (Exception e) {
            System.out.println("Error reading file");
            e.printStackTrace();
        }

    }
}
