
import java.io.PrintStream;
import java.math.BigInteger;

/*****************************************************************************/
/* Authors:                                                                  */
/* Kartsaki Evgenia  00850045                                                */
/* Souris Efstathios 00698116                                                */
/* Description:                                                              */
/* This program was developed fot the purposes of the Cryptography course    */
/* of FIB UPC Barcelona.                                                     */
/* Implementation of AES specification                                       */
/*****************************************************************************/
public class aes {

     private static byte[] IV  = {
        (byte)0x3d, (byte)0xaf, (byte)0xba, (byte)0x42,
        (byte)0x9d, (byte)0x9e, (byte)0xb4, (byte)0x30,
        (byte)0xB4, (byte)0x22, (byte)0xda, (byte)0x80,
        (byte)0x2c, (byte)0x9f, (byte)0xac, (byte)0x41
    };

    // sBox is pre-computed multiplicative inverse in GF(2^8)
    // used in subBytes and keyExpansion [§5.1.1]
    public static final char[] sBox = {
        /*0*//*1*//*2*//*3*//*4*//*5*//*6*//*7*//*8*//*9*//*a*//*b*//*c*//*d*//*e*//*f*/
        /*00*/0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        /*10*/0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        /*20*/ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        /*30*/ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        /*40*/ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        /*50*/ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        /*60*/ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        /*70*/ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        /*80*/ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        /*90*/ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        /*a0*/ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        /*b0*/ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        /*c0*/ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        /*d0*/ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        /*e0*/ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        /*f0*/ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    public static final char[] INVsBox = {
        /*0*//*1*//*2*//*3*//*4*//*5*//*6*//*7*//*8*//*9*//*a*//*b*//*c*//*d*//*e*//*f*/
        /*00*/0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        /*10*/ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        /*20*/ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        /*30*/ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        /*40*/ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        /*50*/ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        /*60*/ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        /*70*/ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        /*80*/ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        /*90*/ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        /*a0*/ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        /*b0*/ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        /*c0*/ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        /*d0*/ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        /*e0*/ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        /*f0*/ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    // rCon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]
    public static final int[][] rCon = {
        {0x00, 0x00, 0x00, 0x00},
        {0x01, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00},
        {0x10, 0x00, 0x00, 0x00},
        {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00},
        {0x80, 0x00, 0x00, 0x00},
        {0x1b, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00}
    };

    public static byte[][][] invKeyExpansion(BigInteger K, int Nk, int Nr) {
        byte[][][] retVal = keyExpansion(K, Nk, Nr);

        for (int i = 1; i < retVal.length -1 ; i++) {
            byte[][] currentKey = retVal[i];
            byte[][] estat = new byte[4][4];
            for (int c = 0; c < estat.length; c++) {
                estat[c] = currentKey[c];
            }

            estat = invMixColumn(estat);

            for (int c = 0; c < estat.length; c++) {
                currentKey[c] = estat[c];
            }

        }

        return retVal;
    }

    /**
     * input :  K is an integer representing the key,
     *          Nk is the number of columns of the key and Nr is the number of rounds;
     *
     * output: list of the Nr + 1 enciphering subkeys, first index refers to
     *          subkey, second one to the subkey row and the last one to the
     *          subkey column.
     */
    public static byte[][][] keyExpansion(BigInteger K, int Nk, int Nr) {  // generate Key Schedule (byte-array Nr+1 x Nb) from Key [§5.2]
        System.out.println("hash    : "+sha256.toHexString((K)));
        byte subkeys[][][] = new byte[Nr+1][4][4];

        int Nb = 4;     // block size (in words): no of columns in state (fixed at 4 for AES)
        int _Nk = Nk; // key length (in words): 4/6/8 for 128/192/256-bit keys

        byte[] key = K.toByteArray();

        byte[][] w = new byte[4*(Nr+1)][4];
        byte[] temp = new byte[4];


        for (int j = 0; j < Nk; j++) {
            byte[] r = {key[4*j], key[4*j+1], key[4*j+2], key[4*j+3]};
            w[j] = r;
            // System.out.println("w["+(j)+"]="+sha256.toHexString(w[j]));
        }

        for (int i = Nk; i < (4 * (Nr + 1)); i++) {
            //System.out.println(i);
            for (int j = 0; j < 4; j++) {
                temp[j] = w[i-1][j];
            }

           //System.out.println("w["+(i)+"]"+sha256.toHexString(temp));

            if (i % Nk == 0) {
                // temp = ByteSub(RotByte(temp)) XOR RCON(i/Nk)
                temp = subWord(rotWord(temp));
                for (int t = 0; t < 4; t++) {
                    temp[t] ^=
                            rCon[i / Nk][t];
                }
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
           //System.out.println("\tw[i - Nk][t]="+sha256.toHexString(w[i - Nk]));
            for (int t = 0; t < 4; t++) {

                w[i][t] = (byte) (w[i - Nk][t] ^ temp[t]);
            }
           //System.out.println("\tw[i]="+sha256.toHexString(w[i]));
        }

        for (int i = 0; i < Nr + 1; i++) {

           for (int col = i*Nb; col < i*Nb + Nb; ++col) {
                for (int row = 0; row < 4; ++row) {
                    // System.out.println(i+" "+row+" "+(col));
                    subkeys[i][row][col%Nb] =
                            w[col][row];
                }
            }
        }

        return subkeys;
    }

    private static byte[] subWord(byte[] w) {    // apply SBox to 4-byte word w
        for (int i = 0; i < 4; i++) {
            w[i] = (byte) sBox[0xff & w[i]];
        }
        return w;
    }

    private static byte[] rotWord(byte[] w) {    // rotate 4-byte word w left by one byte
        byte tmp = w[0];
        for (int i = 0; i < 3; i++) {
            w[i] = w[i + 1];
        }
        w[3] = tmp;
        return w;
    }




    /**
     *  input : subestat is a byte;
     *  output: a byte, obtained applying ByteSub to subestat.
     *
     */
    public static byte byteSub(byte subestat) {
        return ((byte) sBox[0xff&subestat]);
    }

    /**
     * input : subestat is a byte;
     * output: a byte, obtained applying InvByteSub to subestat.
     */
    public static byte invByteSub(byte subestat) {
        return ((byte) INVsBox[0xff&subestat]);
    }

    private static void byte2hex(byte b, PrintStream buf) {
        char[] hexChars = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    private static void printToHex(String msg, byte[][] state) {
        System.out.println(msg);
        for (int i = 0; i < state.length; i++) {
            System.out.println("["+i+"]="+sha256.toHexString(state[i]));

        }
    }

    /*
    input : estat is a 4 × 4 byte matrix;
    output: a 4 × 4 byte matrix, obtained applying ShiftRow to estat.
     */
    public static byte[][] shiftRow(byte[][] estat) {

        byte[] t = new byte[4];
        for (int r=1; r<4; r++) {
            for (int c=0; c<4; c++) t[c] = estat[r][(c+r)%4];  // shift into temp copy
            for (int c=0; c<4; c++) estat[r][c] = t[c];         // and copy back
        }// note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):

        // printToHex("Shift Row", estat);

        return estat;  // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
    }

    /**
     * intput: estat is a 4 × 4 byte matrix;
     * output: a 4 × 4 byte matrix, obtained applying InvShiftRow to estat.
     */
    public static byte[][] invShiftRow(byte[][] estat) {

        byte t[] = new byte[4];
        for(int row = 1; row < 4; ++row)
        {

            t[(row + 0) % 4] = estat[row][0];
            t[(row + 1) % 4] = estat[row][1];
            t[(row + 2) % 4] = estat[row][2];
            t[(row + 3) % 4] = estat[row][3];
            estat[row][0] = t[0];
            estat[row][1] = t[1];
            estat[row][2] = t[2];
            estat[row][3] = t[3];
        }
        return estat;
    }

    /**
     * input : estat is a 4 × 4 byte matrix;
     * output: a 4 × 4 byte matrix, obtained applying MixColumn to estat.
     */
    public static byte[][] mixColumn(byte[][] estat) {
        int colSize = estat[0].length;
        byte[][] retVal = new byte[4][colSize];

        for (int c=0; c<4; c++) {
            byte[] a = new byte[4];  // 'a' is a copy of the current column from 's'
            byte[] b = new byte[4];  // 'b' is a•{02} in GF(2^8)
            for (int i=0; i<4; i++) {
                a[i] = estat[i][c];
                b[i] = (byte) ((estat[i][c] & 0x80) ==  0 ?
                    estat[i][c] << 1 ^ 0x011b :
                    estat[i][c] << 1);

            }
            // a[n] ^ b[n] is a•{03} in GF(2^8)
            estat[0][c] = (byte) (b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]); // 2*a0 + 3*a1 + a2 + a3
            estat[1][c] = (byte) (a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]); // a0 * 2*a1 + 3*a2 + a3
            estat[2][c] = (byte) (a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]); // a0 + a1 + 2*a2 + 3*a3
            estat[3][c] = (byte) (a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]); // 3*a0 + a1 + a2 + 2*a3
      }
      // printToHex("Mix Column", estat);

        byte aa = 0 , bb  = 0, r = 0, t;
        while (aa != 0) {
            if ((aa & 1) != 0)
                r = (byte) (r ^ bb);
            t = (byte) (bb & 0x80);
            bb = (byte) (bb << 1);
            if (t != 0)
                 bb = (byte) (bb ^ 0x1b); // the bit of field polynomial (0x11b) is not
             // not needed here since bb is an 8 bit value
             aa = (byte) (aa >> 1);
        }

      return estat;


        //return retVal;
    }

    private static byte FFmul(byte a, byte b) {
        byte aa = a, bb = b, r = 0, t;
        while (aa != 0) {
            if ((aa & 1) != 0)
                r = (byte) (r ^ bb);
            t = (byte) (bb & 0x80);
            bb = (byte) (bb << 1);
            if (t != 0)
                 bb = (byte) (bb ^ 0x1b); // the bit of field polynomial (0x11b) is not
             // not needed here since bb is an 8 bit value
             aa = (byte) (aa >> 1);
        }
        return r;
    }

    /**
     * intput: estat is a 4 × 4 byte matrix;
     * output: a 4 × 4 byte matrix, obtained applying InvMixColumn to estat.
     */
    public static byte[][] invMixColumn(byte[][] estat) {
        byte t[] = new byte[4];

        for (int c = 0; c < 4; ++c) {
            for (int r = 0; r < 4; r++) {
                t[r] = estat[r][c];
            }
            for (int r = 0; r < 4; r++) {
                estat[r][c] =
                    (byte) (
                    FFmul((byte) 0x0e, t[r]) ^
                    FFmul((byte) 0x0b, t[(r + 1) % 4]) ^
                    FFmul((byte) 0x0d, t[(r + 2) % 4]) ^
                    FFmul((byte) 0x09, t[(r + 3) % 4]));
            }
        }
        return estat;
    }

    /**
     * intput: estat and Ki are 4 × 4 byte matrices;
     * output: a 4 × 4 byte matrix, obtained adding matrices estat and Ki bit to bit.
     *
     * -------- implemented
     * --------  not tested
     * * The input for the AddRoundKey function are two 4 × 4
     * * matrices and then it performs XOR to their coefficients
     */
    public static byte[][] addRoundKey(byte[][] estat, byte[][] Ki) {
        byte[][] retVal = new byte[estat.length][estat[0].length];
        for (int i = 0; i < retVal.length; i++) {
            for (int j = 0; j < retVal[i].length; j++) {
                retVal[i][j] = (byte) ((byte) estat[i][j] ^ Ki[i][j]);
            }
        }
        //printToHex("add Round Key", retVal);
        return retVal;
    }

    /**
     * input : estat is a 4 × 4 byte matrix,
     *          Nk is the key length divided by 32,
     *          Nr is the number of rounds and
     *          W is the matrix storing the enciphering subkeys; a 4 × 4
     * output: byte matrix, obtained applying the enciphering algorithm to estat.
     */
    public static byte[][] rijndael(byte[][] estat, byte[][][] W, int Nk, int Nr) {

        estat = addRoundKey(estat, W[0]);
        /*for (int i = 0; i < state.length; i++) {
            System.out.println("state["+i+"]="+sha256.toHexString(state[i]));

        }*/

        for (int round=1; round<Nr; round++) {
            estat = subBytes(estat);
            estat = shiftRow(estat);
            estat = mixColumn(estat);
            estat = addRoundKey(estat, W[round]);
          }

          estat = subBytes(estat);
          estat = shiftRow(estat);
          estat = addRoundKey(estat, W[Nr]);
/*
        byte[] output = new byte[4 * 4];  // convert state to 1-d array before returning [§3.4]
        for (int i = 0; i < 4 * 4; i++) {
            output[i] = estat[i % 4][(i / 4)];
        }*/
        return estat;
    }

    /**
     * input:   estat is a 4 × 4 byte matrix,
     *          Nk is the key length divided by 32,
     *          Nr is the number of rounds and InvW is the matrix storing the deciphering subkeys;
     * output: a 4 × 4 byte matrix, obtained applying the deciphering algorithm to
     */
    public static byte[][] invRijndael(byte[][] estat, byte[][][] InvW, int Nk, int Nr) {
        estat = addRoundKey(estat, InvW[0]);
        /*for (int i = 0; i < state.length; i++) {
            System.out.println("state["+i+"]="+sha256.toHexString(state[i]));

        }*/

        for (int round=1; round<Nr; round++) {
            estat = invSubBytes(estat);
            estat = invShiftRow(estat);
            estat = invMixColumn(estat);
            estat = addRoundKey(estat, InvW[round]);
          }

          estat = invSubBytes(estat);
          estat = invShiftRow(estat);
          estat = addRoundKey(estat, InvW[Nr]);
/*
        byte[] output = new byte[4 * 4];  // convert state to 1-d array before returning [§3.4]
        for (int i = 0; i < 4 * 4; i++) {
            output[i] = estat[i % 4][(i / 4)];
        }*/
        return estat;
    }

    public static final byte[] intToByteArray(int value) {
        return new byte[] {
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value};
    }

    private static byte[] XORed(byte[] a, byte[] b) {
        if (a.length != b.length)
            return null;

        byte[] retVal = new byte[a.length];
        for (int i = 0; i < b.length; i++) {
            byte c = b[i];
            retVal[i] = (byte) (a[i] ^ b[i]);
        }

        return retVal;
    }

    /**
     * SHA padding like algorithm for 128 bit block
     * @param M
     * @param blockSize
     * @return
     */
    private static byte[] padMessage(byte[] M, int blockSize) {
        Integer initialMsgBits = M.length*8;
        // k 0's to reach 448 bits length
        int k = (blockSize-64) - (initialMsgBits%(blockSize)) - 1;
        int addedBits = 1+k+64;
        if (k< 0) addedBits+= blockSize;

        int fullLength = initialMsgBits + addedBits;
        byte[] paddedMsg = new byte[fullLength/8];
        for (int i = 0; i < M.length; i++) {
            paddedMsg[i] = M[i];
        }
        // 0x80 -> 1000 0000
        paddedMsg[M.length] = (byte) (0x80);
        // pad (k-7) 0s in bits
        for (int i = M.length+1; i < paddedMsg.length - 8; i++) {
             paddedMsg[i] = 0x00;
        }

        /* this is not right! In this implementation the message bits number */
        /* cannot be a 64-bit integer as is it mentioned in the assignment   */
        /* is is 32-bit so we zero the first 32-bits and write the length    */
        /* int the next 32 bits                                              */
        for (int i = paddedMsg.length - 8; i < paddedMsg.length - 4; i++) {
            paddedMsg[i] = 0x00;
        }

        byte[] inteGer = intToByteArray(initialMsgBits);
        paddedMsg[paddedMsg.length - 4] = inteGer[0];
        paddedMsg[paddedMsg.length - 3] = inteGer[1];
        paddedMsg[paddedMsg.length - 2] = inteGer[2];
        paddedMsg[paddedMsg.length - 1] = inteGer[3];
        return paddedMsg;
    }

    /**
     * intput:  M is a byte list representing the message to encipher,
     *          K is an integer representing the key and
     *          Lk is the key length (128, 192 or 256);
     * output: byte list representing the cryptogram obtained by enciphering the
     *          message M (with added padding) in CBC mode with key K.
     */
    /* encrypt */
    public static byte[] xifrarAES(byte[] M, BigInteger K, int Lk) {
        assert (Lk == 128 || Lk == 192 || Lk == 256);

        int Nb = 4;               // block size (in words): no of columns in state (fixed at 4 for AES)
        int Nr = 0; // no of rounds: 10/12/14 for 128/192/256-bit keys
        int Nk = 0;
        switch (Lk) {
            case 128:
                Nk = 4;
                Nr = 10;
                break;
            case 192:
                Nk = 6;
                Nr = 12;
                break;
            case 256:
                Nk = 8;
                Nr = 14;
                break;
            default:
                assert (false);
        }

        int blockSize = 128;
        byte[] paddedMsg = padMessage(M, blockSize);

        // separate padded message into blocks
        int nBlocks = (paddedMsg.length*8)/blockSize;
        byte[][] pt = new byte[nBlocks][blockSize/8];
        for (int b=0; b<nBlocks; b++) {
            for (int i = 0; i < blockSize/8; i++) {
                pt[b][i] = paddedMsg[b*(blockSize/8)+i];
            }
            // System.out.println(sha256.toHexString(ct[b]));
        }

        byte[][][] keySchedule = keyExpansion(K, Nk, Nr);

        byte[] ciphertext = null;
        byte[][] ciphertexts = new byte[nBlocks][nBlocks*(blockSize/8)];


        for (int i = 0; i < nBlocks; i++) {

            if (i == 0)
                ciphertext = IV;
            else
                ciphertext = ciphertexts[i-1];

            ciphertext = XORed(ciphertext, pt[i]);

            byte[][] state = new byte[4][Nb];
                    // initialise 4xNb byte-array 'state' with input [§3.4]
            for (int ii = 0; ii < 4 * Nb; ii++) {
                state[ii % 4][ii / 4] = ciphertext[ii];
                // state[ii % 4][ii / 4] = M[ii];
            }

           //printToHex("BEFORE", state);
            state = rijndael(state, keySchedule, Nk, Nr);
           // printToHex("AFTER ", state);

            for (int ii = 0; ii < 4 * 4; ii++) {
                ciphertext[ii] = state[ii % 4][(ii / 4)];
                // M[ii] = state[ii % 4][(ii / 4)];
            }
            ciphertexts[i] = ciphertext;
        }
        byte[] retVal = new byte[ciphertexts.length*ciphertexts[0].length];
        for (int i = 0; i < ciphertexts.length; i++) {
            for (int j = 0; j < ciphertexts[i].length; j++) {
                retVal[i*ciphertexts.length +j] = ciphertexts[i][j];

            }

        }
        return retVal;
    }

    /**
     * intput:  C is a byte list representing the cryptogram,
     *          K is an integer representing the key and
     *          Lk is the key length (128, 192 or 256);
     *
     * output: byte list representing the message obtained after deciphering and
     *          padding removal.
     */
    /** decrypt **/
    public static byte[] desxifrarAES(byte[] C, BigInteger K, int Lk) {
        assert (Lk == 128 || Lk == 192 || Lk == 256);

        int Nb = 4;// block size (in words): no of columns in state (fixed at 4 for AES)
        int Nr = 0;// no of rounds: 10/12/14 for 128/192/256-bit keys
        int Nk = 0;
        switch (Lk) {
            case 128:
                Nk = 4;
                Nr = 10;
                break;
            case 192:
                Nk = 6;
                Nr = 12;
                break;
            case 256:
                Nk = 8;
                Nr = 14;
                break;
            default:
                assert (false);
        }


        int blockSize = 128;

        // separate padded message into blocks
        int nBlocks = (C.length*8)/blockSize;
        byte[][] ct = new byte[nBlocks][blockSize/8];
        for (int b=0; b<nBlocks; b++) {
            for (int i = 0; i < blockSize/8; i++) {
                // System.out.println((b*(blockSize/8)+i)+" ("+b+","+i+")"+
                ct[b][i] = C[b*(blockSize/8)+i];
            }
            // System.out.println(sha256.toHexString(ct[b]));
        }
        byte[][][] keySchedule = invKeyExpansion(K, Nk, Nr);

        byte[][] plaintexts = new byte[nBlocks][(blockSize/8)];
        byte[] plaintext = new byte[(blockSize/8)];

        for (int i = 0; i < nBlocks; i++) {


            byte[][] state = new byte[4][Nb];
                    // initialise 4xNb byte-array 'state' with input [§3.4]
            for (int ii = 0; ii < 4 * Nb; ii++) {
                state[ii % 4][ii / 4] = ct[i][ii];
                // state[ii % 4][ii / 4] = M[ii];
            }

           // printToHex("MMM BEFORE", state);
            state = invRijndael(state, keySchedule, Nk, Nr);
// printToHex("MMM AFTER", state);

            for (int ii = 0; ii < 4 * 4; ii++) {
                plaintext[ii] = state[ii % 4][(ii / 4)];
                // M[ii] = state[ii % 4][(ii / 4)];
            }
            byte[] tmp = null;
            if (i == 0) tmp = IV;
            else        tmp = ct[i-1];

            plaintext = XORed(tmp, plaintext);

            plaintexts[i] = plaintext;
           // printToHex("AFTER ", state);
        }

        byte[] retVal = new byte[plaintexts.length*plaintexts[0].length];
        for (int i = 0; i < plaintexts.length; i++) {
            for (int j = 0; j < plaintexts[i].length; j++) {
                retVal[i*plaintexts.length +j] = plaintexts[i][j];
            }

        }
        return retVal;
    }

    private static byte[][] subBytes(byte[][] state) {
        for (int i = 0; i < state.length; i++) {
            byte[] bs = state[i];
            for (int j = 0; j < bs.length; j++) {
                state[i][j] = byteSub(state[i][j]);

            }
        }
        // printToHex("Sub Bytes", state);
        return state;
    }

    private static byte[][] invSubBytes(byte[][] state) {
        for (int r = 0; r < state.length; r++) {
            byte[] bs = state[r];
            for (int c = 0; c < bs.length; c++) {
                state[r][c] = invByteSub(state[r][c]);

            }
        }
        // printToHex("Inv Sub Bytes", state);

        return state;
    }

    public static void main(String[] args) {

        byte[] key3 = {
          (byte)0x06, (byte)0xa9, (byte)0x21, (byte)0x40,
          (byte)0x36, (byte)0xb8, (byte)0xa1, (byte)0x5b,
          (byte)0x51, (byte)0x2e, (byte)0x03, (byte)0xd5,
          (byte)0x34, (byte)0x12, (byte)0x00, (byte)0x06

        };

        System.out.println("input = Single block msg ->"+sha256.toHexString("Single block msg".getBytes()));
        System.out.println("key = "+sha256.toHexString(key3));
        System.out.println("IV : "+sha256.toHexString(IV));
        // byte[] r = xifrarAES(inputTestVal1.toByteArray(), key2, 128);
        byte[] C = xifrarAES("Single block msg".getBytes(), new BigInteger(key3), 128);

        System.out.println("encrypted = "+sha256.toHexString(C));

        byte[] pt = desxifrarAES(C, new BigInteger(key3), 128);
        System.out.println("encrypted = "+new String(pt));
        ;
/*
        byte[] key4 = {
          (byte)0xcb, (byte)0xC6, (byte)0x18, (byte)0xEF,
          (byte)0x40, (byte)0x13, (byte)0x0B, (byte)0x29,
          (byte)0xBC, (byte)0x46, (byte)0x94, (byte)0x0A,
          (byte)0x72, (byte)0x3A, (byte)0x5C, (byte)0x1B
        };*/
        /*byte[] key4 = {
            (byte)0xB0, (byte)0x0D, (byte)0xDF, (byte)0x9D,
            (byte)0x93, (byte)0xE1, (byte)0x99, (byte)0xEF,
            (byte)0xEA, (byte)0xE9, (byte)0x67, (byte)0x80,
            (byte)0x5E, (byte)0x0A, (byte)0x52, (byte)0x28
        };

        byte[] M = "CBC Mode Test".getBytes();*//*{
            (byte)0xE6, (byte)0xF1, (byte)0x40, (byte)0x9A,
            (byte)0xBA, (byte)0x89, (byte)0x0A, (byte)0xC3,
            (byte)0xA5, (byte)0x0F, (byte)0xC4, (byte)0xAA,
            (byte)0xD8, (byte)0x2E, (byte)0x18, (byte)0x72
        };*/
        /*System.out.println("PT = E6F1409ABA890AC3A50FC4AAD82E1872 ");
        System.out.println("key = "+sha256.toHexString(key4));
        // byte[] r = xifrarAES(inputTestVal1.toByteArray(), key2, 128);
        byte[] r = xifrarAES(M, new BigInteger(key4), 128);

        System.out.println("encrypted = "+sha256.toHexString(r));
        */
        System.exit(0);

    }

}
