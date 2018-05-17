import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.security.*;
import java.util.Arrays;

/** Klassen tar en krypterad fil som input och letar efter en blob.
 * Om en blob hittas läggs datat i bloben i angiven outputfil.
 * Den kan dekryptera med AES-CTR och AES-ECB
 * Created by mikaelnorberg on 2017-05-17.
 */
class Hiddec {
    private final int BLOCK_SIZE = 16;

    private byte[] key;
    private byte[] keyHash;

    private byte[] ctr;

    private byte[] decryptedData;

    private String keyInput;
    private String ctrInput;
    private String inputFile;
    private String outputFile;


    private Hiddec(String[] args) {
        boolean CTR_MODE = processFlags(args);
        this.key = stringToHex(this.keyInput);
        this.keyHash = hashData(this.key);
        byte[] encryptedInput = readFile(inputFile);
        validateInputLength(encryptedInput);
        boolean validData;
        if(CTR_MODE) {
            validData = ctr(encryptedInput);
        } else {
            validData = ecb(encryptedInput);
        }
        if(validData){
            writeFile(this.decryptedData, this.outputFile);
            System.out.println("Data har skrivits till filen " + this.outputFile);
            System.out.println("Programmet avslutas.");
        } else {
            System.out.println("Datat stämmer inte överrens med hashvärdet i blobben.");
            System.out.println("Försök igen. Programmet avslutas.");
        }
    }

    private void validateInputLength(byte[] encryptedInput) {
        if(encryptedInput.length % 16 != 0){
            printMessage(9);
        }
    }


    private boolean ecb(byte[] encryptedInput) {
        byte[] decryptedData = decryptECB(encryptedInput, this.key);
        byte[] blob = findStartOfDataECB(decryptedData);
        validateBlobStart(blob);
        blob = extractBlob(blob);
        validateBlobEndKeyHash(blob);
        byte[] dataHashBlock = getDataHash(blob);
        this.decryptedData = getData(blob);
        byte[] decryptedDataHash = hashData(this.decryptedData);
        return validateData(dataHashBlock, decryptedDataHash);
    }
    private boolean ctr(byte[] encryptedInput){
        this.ctr = stringToHex(this.ctrInput);
        byte[] blob = findStartOfDataCTR(encryptedInput);
        validateBlobStart(blob);
        blob = extractBlob(blob);
        validateBlobEndKeyHash(blob);
        byte[] dataHashBlock = getDataHash(blob);
        this.decryptedData = getData(blob);
        byte[] decryptedDataHash = hashData(this.decryptedData);
        return validateData(dataHashBlock, decryptedDataHash);
    }

    private void validateBlobEndKeyHash(byte[] blob) {
        if (blob == null){
            printMessage(4);
        }
    }


    private byte[] extractBlob(byte[] blob) {
        byte[] block;
        byte[] data = null;
        int index = 0;
        for (int i = 0; i < blob.length / this.BLOCK_SIZE; i++) {
            block = Arrays.copyOfRange(blob, index, index + this.BLOCK_SIZE);
            if (Arrays.equals(block, this.keyHash)) {
                if (i == 0){
                    printMessage(0);
                }
                if (blob.length < (index + this.BLOCK_SIZE * 2)){
                    printMessage(1);
                } else {
                    data = Arrays.copyOfRange(blob, 0, index + this.BLOCK_SIZE * 2);
                    break;
                }
            }
            index = index + this.BLOCK_SIZE;
        }
        return data;
    }


    private void validateBlobStart(byte[] blob) {
        if (blob == null){
            printMessage(3);
        }
    }

    private byte[] getData(byte[] blob) {
        return Arrays.copyOfRange(blob, 0, blob.length - 2 * this.BLOCK_SIZE);
    }

    private byte[] getDataHash(byte[] blob){
        return Arrays.copyOfRange(blob, blob.length - this.BLOCK_SIZE, blob.length);
    }

    private byte[] findStartOfDataECB(byte[] decryptedInput) {
        int index = 0;
        byte[] block;
        byte[] blob = null;
        for (int i = 0; i < decryptedInput.length / this.BLOCK_SIZE; i++) {
            if(decryptedInput.length <= (index + this.BLOCK_SIZE)) {
                printMessage(2);
            }
            block = Arrays.copyOfRange(decryptedInput, index, index + this.BLOCK_SIZE);
            if(Arrays.equals(block, this.keyHash)) {
                blob = Arrays.copyOfRange(decryptedInput, index + this.BLOCK_SIZE, decryptedInput.length);
                break;
            }
            index = index + this.BLOCK_SIZE;
        }
        return blob;
    }



    private boolean validateData(byte[] extractedDataHash, byte[] decryptedDataHash) {
        return Arrays.equals(decryptedDataHash, extractedDataHash);
    }

    private byte[] findStartOfDataCTR(byte[] encryptedInput) {
        int index = 0;
        byte[] encryptedBlock;
        byte[] decryptedBlock;
        byte[] decryptedData = null;
        for (int i = 0; i < encryptedInput.length / this.BLOCK_SIZE; i++) {
            encryptedBlock = Arrays.copyOfRange(encryptedInput, index, index + this.BLOCK_SIZE);
            decryptedBlock = decryptCTR(encryptedBlock, this.key, this.ctr);
            if(Arrays.equals(decryptedBlock, this.keyHash)){
                byte[] encryptedData = Arrays.copyOfRange(encryptedInput, index, encryptedInput.length);
                decryptedData = decryptCTR(encryptedData, this.key, this.ctr);
                decryptedData = Arrays.copyOfRange(decryptedData, this.BLOCK_SIZE, decryptedData.length);
                break;
            }
            index = index + this.BLOCK_SIZE;
        }
        return decryptedData;
    }


    private byte[] decryptCTR(byte[] data, byte[] key, byte[] CTR) {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(CTR);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return this.keyHash;
    }

    private byte[] decryptECB(byte[] data, byte[] key){
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] decrypted = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            decrypted = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return decrypted;
    }



    private byte[] stringToHex(String hexString){
        byte[] result = null;
        try {
            result = DatatypeConverter.parseHexBinary(hexString);
        } catch (IllegalArgumentException e) {
            printMessage(13);
        }
        return result;
    }


    private void writeFile(byte[] data, String outputFile) {
        try (FileOutputStream fos = new FileOutputStream(outputFile)){
            DataOutputStream output = new DataOutputStream(fos);
            output.write(data);
            output.close();
        } catch (FileNotFoundException e) {
            System.out.println("Kontrollera skrivrättigheter för " + outputFile + " och försök igen.");
            System.out.println("Dekryptering avbruten. Programmet avslutas.");
            System.exit(0);
        } catch (IOException f) {
            System.out.println("Något gick fel när encryptedInput skrevs till " + outputFile);
            System.out.println("Dekryptering avbruten. Programmet avslutas.");
            System.exit(0);
        }
    }

    private byte[] readFile(String fileName){
        byte[] plainText = null;
        try (FileInputStream fis = new FileInputStream(fileName)){
            final int FILESIZE = (int) fis.getChannel().size();
            if(FILESIZE == 0){
                System.out.println("Filen innehåller ingen encryptedInput att kryptera.");
                System.out.println();
                System.out.println("Kryptering avbruten. programmet avslutas");
                System.exit(0);
            }
            plainText = new byte[FILESIZE];
            DataInputStream input  = new DataInputStream(fis);
            for(int i = 0; i < plainText.length; i++) {
                plainText[i] = input.readByte();
            }
        } catch (FileNotFoundException e) {
            System.out.println("Filen " + fileName + " gick inte att öppna.");
            System.out.println("Kontrollera att filen finns och försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        } catch (EOFException e) {
            System.out.println("Något gick fel vid läsning av " + fileName + ". Försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        }catch (IOException e) {
            System.out.println("Något gick fel med filen " + fileName + ". Försök igen.");
            System.out.println();
            System.out.println("Programmet avslutas");
            System.exit(0);
        }
        if(plainText.length == 0) {
            System.out.println("Filen " + fileName + " innehåller ingen data. Programmet avslutas");
            System.out.println("Programmet avslutas");
            System.exit(0);
        }
        return plainText;
    }


    private byte[] hashData(byte[] data){
        MessageDigest MD;
        final String ALGORITHM = "MD5";
        try {
            MD = MessageDigest.getInstance(ALGORITHM);
            MD.update(data);
            return MD.digest();

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm \"" + ALGORITHM + "\" is not available");
        }
        return null;
    }

    private boolean processFlags(String[] args) {
        boolean CTR;
        final String KEY_FLAG = "--key=";
        final String CTR_FLAG = "--ctr=";
        final String INPUT_FLAG = "--input=";
        final String OUTPUT_FLAG = "--output=";
        for (String arg : args) {
            if(arg.contains(KEY_FLAG)){
                this.keyInput = arg.substring(KEY_FLAG.length());
                if(this.keyInput.length() != 32) {
                    printMessage(12);
                }
            }else if(arg.contains(CTR_FLAG)){
                this.ctrInput = arg.substring(CTR_FLAG.length());
                if(this.ctrInput.length() != 32) {
                    printMessage(12);
                }
            }else if(arg.contains(INPUT_FLAG)){
                this.inputFile = arg.substring(INPUT_FLAG.length());
            }else if(arg.contains(OUTPUT_FLAG)){
                this.outputFile = arg.substring(OUTPUT_FLAG.length());
            } else {
                System.out.println("Programmet kan inte anropas med argumentet " + arg + ".");
                System.out.println("Programmet avslutas");
                System.exit(0);
            }
        }
        if(args.length == 4) {
            CTR = validateArgs(true);
        } else {
            CTR = validateArgs(false);
        }
        return CTR;
    }


    private void printMessage(int message) {
        if (message == 0){
            System.out.println("Blobben innehåller ingen hemlig data.");
        } else if (message == 1) {
            System.out.println("Det går inte att validera datat. Datavalideringsdelen av blobben saknas.");
        } else if (message == 2) {
            System.out.println("Det finns inte tillräckligt med data kvar av filen för att innehålla en komplett blobb.");
        } else if (message == 3) {
            System.out.println("Det finns ingen blob som matchar inmatad data.");
        } else if (message == 4) {
            System.out.println("Den andra hashningen av nyckeln finns inte i blobben.");
        } else if (message == 5) {
            System.out.println("Den inmatade nyckeln är 33 byte. Den 33e byten tas bort. Det är troligtvis en lineFeed.");
        } else if (message == 6) {
            System.out.println("Nyckel-input måste vara 32 eller 33 byte. om 33 så tas den sista byten bort.");
        } else if (message == 7) {
            System.out.println("Den inmatade CTR är 33 byte. Den 33e byten tas bort. Det är troligtvis en lineFeed.");
        } else if (message == 8) {
            System.out.println("CTR-input måste vara 32 eller 33 byte. om 33 så tas den sista byten bort.");
        } else if (message == 9) {
            System.out.println("datafilen måste vara en multipel av blockstorleken 128 bitar.");
        } else if (message == 10) {
            System.out.println("input får endast innehålla a-f, A-F och 0-9");
        } else if (message == 11) {
            System.out.println("Programmet har anropats med felaktiga argument.");
        } else if (message == 12) {
            System.out.println("Nyckel och ctr måste vara 32 tecken.");
        } else if (message == 13) {
            System.out.println("Nyckel och Ctr får endast innehålla tecken 0-9 och a-f.");
        }
        if(message != 5 && message != 7) {
            System.out.println("Försök igen. Programmet avslutas.");
            System.exit(0);
        }
    }
    private boolean validateArgs(boolean CTR){
    if(!((inputFile != null && inputFile.length() != 0) &&
         (outputFile != null && outputFile.length() != 0))) {
        printMessage(11);
    }
    return CTR;
    }

    public static void main(String[] args) {
        if(args.length == 3 || args.length == 4){
            new Hiddec(args);
        } else {
            System.out.println("Programmet måste startas med tre eller fyra argument.");
            System.out.println("Försök igen. Programmet avslutas.");
        }
    }
}
