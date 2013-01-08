/*****************************************************************************/
/* Authors:                                                                  */
/* Kartsaki Evgenia  00850045                                                */
/* Souris Efstathios 00698116                                                */
/* Description:                                                              */
/* This program was developed fot the purposes of the Cryptography course    */
/* of FIB UPC Barcelona.                                                     */
/* SHA256 hash function implementation                                       */
/*****************************************************************************/
import java.math.BigInteger;

/**
 *
 * @author Kartsaki Evgenia, Souris Efstathios
 */
public class sha256 {

    /**
     * constants
     */
    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    /**
     * initial hash value
     */
    private static int[] H = {
        0x6a09e667, /* 0 */
        0xbb67ae85, /* 1 */
        0x3c6ef372, /* 2 */
        0xa54ff53a, /* 3 */
        0x510e527f, /* 4 */
        0x9b05688c, /* 5 */
        0x1f83d9ab, /* 6 */
        0x5be0cd19  /* 7 */
    };

    /**
     * numeric constant for 1 so as not to cunfuse it with 'l'
     * 1 -> this is one   (the number)
     * l -> this is lamda (the letter)
     */
    private static final int one = 1;

    /**
     * Converts a byte array to hex string
     */
    public static String toHexString(byte[] block) {
       StringBuffer buf = new StringBuffer();
       int len = block.length;
       for (int i = 0; i < len; i++)
       {
            byte2hex(block[i], buf);
            //if (i < len-1)
            //    buf.append(":");
       }
       return buf.toString();
    }

    public static String toHexString(byte b) {
       StringBuffer buf = new StringBuffer();
        byte2hex(b, buf);
       return buf.toString();
    }

    /**
     * converts integer to hex string
     */
    public static String toHexString(int block) {
       return toHexString(intToByteArray(block));
    }

    /**
     * converts BigInteger to hex string
     */
    public static String toHexString(BigInteger block) {
       return toHexString(block.toByteArray());
    }

    /**
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
       char[] hexChars = {
           '0', '1', '2', '3', '4', '5', '6', '7',
           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
       };
       int high = ((b & 0xf0) >> 4);
       int low = (b & 0x0f);
       buf.append(hexChars[high]);
       buf.append(hexChars[low]);
    }

    public static final byte[] intToByteArray(int value) {
        return new byte[] {
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value};
    }

    public static final int ByteArrayToInt( byte value0,
                                            byte value1,
                                            byte value2,
                                            byte value3) {
        // assert(value.length == 4);
        return ((value0 << 24) &0xFF000000 |
                (value1 << 16) &0x00FF0000 |
                (value2 << 8 ) &0x0000FF00 |
                (value3      ) &0x000000FF
               );
    }



    /**
     * <tr>
     *  <td>input: </td>
     *  <td>M is a chain of bytes of arbitrary length;</td>
     * </tr>
     * <tr>
     *  <td>output:</td>
     *  <td> a positive integer in the interval [0, 2^256),
     *       the value of the hash of M
     *  </td>
     * </tr>
     * @param M
     * @return
     */
    
    public static BigInteger hash(byte[] M) {
        byte[] initialMsgBytes = M;
        
        Integer initialMsgBits = initialMsgBytes.length*8;
        // k 0's to reach 448 bits length
        int k = 448 - (initialMsgBits%512) - one;
        int addedBits = one+k+64;
        if (k< 0) addedBits+= 512;
        
        int fullLength = initialMsgBits + addedBits;
        byte[] paddedMsg = new byte[fullLength/8];
        for (int i = 0; i < initialMsgBytes.length; i++) {
            paddedMsg[i] = initialMsgBytes[i];
        }
        // 0x80 -> 1000 0000
        paddedMsg[initialMsgBytes.length] = (byte) (0x80);
        // pad (k-7) 0s in bits
        for (int i = initialMsgBytes.length+1; i < paddedMsg.length - 8; i++) {
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
        
        // to integer array
        Integer[][] MESSAGE_INTEGER_ARRAY = new Integer[(paddedMsg.length/4)/16][];
        for (int i = 0; i < MESSAGE_INTEGER_ARRAY.length; i++) {
            MESSAGE_INTEGER_ARRAY[i] = new Integer[16];
            for (int j = 0; j < 16; j++) {
                MESSAGE_INTEGER_ARRAY[i][j] = ByteArrayToInt(
                                    paddedMsg[i*64+j*4  ],
                                    paddedMsg[i*64+j*4+1],
                                    paddedMsg[i*64+j*4+2],
                                    paddedMsg[i*64+j*4+3]
                                );
            }
        }
        
        // System.out.println(toHexString(paddedMsg));
        
        // HASH COMPUTATION
        int[] W = new int[64];
        int a, b, c, d, e, f, g, h;
        
        for (int i=0; i<MESSAGE_INTEGER_ARRAY.length; i++) {
            // 1 - prepare message schedule 'W'
            for (int t=0;  t<16; t++) W[t] = MESSAGE_INTEGER_ARRAY[i][t];
            for (int t=16; t<64; t++) W[t] =
                    (sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]) & 0xffffffff;

            // 2 - initialise working variables a, b, c, d, e, f, g, h with previous hash value
            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            f = H[5];
            g = H[6];
            h = H[7];

            // 3 - main loop (note 'addition modulo 2^32')
            for (int t=0; t<64; t++) {
                int T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
                int T2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = (d + T1) & 0xffffffff;
                d = c;
                c = b;
                b = a;
                a = (T1 + T2) & 0xffffffff;

                /*System.out.println(
                        "t="+t+":"+"\t"+
                        toHexString(a)+"\t"
                              +toHexString(b)+"\t"
                              +toHexString(c)+"\t"
                              +toHexString(d)+"\t"
                              +toHexString(e)+"\t"
                              +toHexString(f)+"\t"
                              +toHexString(g)+"\t"
                              +toHexString(h)+"\t");*/
            }
            // 4 - compute the new intermediate hash value (note 'addition modulo 2^32')
            H[0] = (H[0]+a) & 0xffffffff;
            H[1] = (H[1]+b) & 0xffffffff;
            H[2] = (H[2]+c) & 0xffffffff;
            H[3] = (H[3]+d) & 0xffffffff;
            H[4] = (H[4]+e) & 0xffffffff;
            H[5] = (H[5]+f) & 0xffffffff;
            H[6] = (H[6]+g) & 0xffffffff;
            H[7] = (H[7]+h) & 0xffffffff;
            
        }


        /*
         String hexNumber =
                  toHexString(H[0])
                + toHexString(H[1])
                + toHexString(H[2])
                + toHexString(H[3])
                + toHexString(H[4])
                + toHexString(H[5])
                + toHexString(H[6])
                + toHexString(H[7]);
         System.out.println(hexNumber);
        */
        byte[] num = new byte[H.length*4];
        for (int i = 0; i < H.length; i++) {
            byte[] H_i_bytes  = intToByteArray(H[i]);
            num[i*4] = H_i_bytes[0];
            num[i*4+1] = H_i_bytes[1];
            num[i*4+2] = H_i_bytes[2];
            num[i*4+3] = H_i_bytes[3];


        }
        //System.out.println(toHexString(bi));
        return (new BigInteger(num));

    }

    public static int ROTR(int n, int x) { 
        return (x >>> n) | (x << (32-n));
    }

    public static int Sigma0(int x) {
        return ROTR(2,  x) ^ ROTR(13, x) ^ ROTR(22, x);
    }

    public static int Sigma1(int x) { 
        return ROTR(6,  x) ^ ROTR(11, x) ^ ROTR(25, x);
    }
    
    public static int sigma0(int x) { 
        return ROTR(7,  x) ^ ROTR(18, x) ^ (x>>>3);
    }

    public static int sigma1(int x) {
        return ROTR(17, x) ^ ROTR(19, x) ^ (x>>>10);
    }

    public static int Ch(int x, int y, int z)  {
        return (x & y) ^ (~x & z);
    }

    public static int Maj(int x, int y, int z) { 
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
}
