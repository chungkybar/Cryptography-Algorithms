
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/*****************************************************************************/
/* Authors:                                                                  */
/* Kartsaki Evgenia  00850045                                                */
/* Souris Efstathios 00698116                                                */
/* Description:                                                              */
/* This program was developed fot the purposes of the Cryptography course    */
/* of FIB UPC Barcelona.                                                     */
/*                                                                           */
/*****************************************************************************/
public class sistemaCriptografic {
    /**
     * input :  M is the message to be signed, given by a list of bytes,
     *          clauFirma is the private key of the sender,
     *          clauPrivadaECC is an integer,
     *          clauPublicaECC={Px,Py} (different from the point at infinity)
     *          parametresECC={n, Gx, Gy, a, b, p}, G = (Gx, Gy) point of order
     *          n in the curve y2 = x3 + ax + b mod p (obviously,
     *          G is not the point at infinity);
     * output:  a list of bytes representing KSE∥E(M∥F).
     */
    public static byte[] enviarMissatge(byte[] M,
                                        BigInteger clauDeFirma,
                                        BigInteger clauPrivadaECC,
                                        BigInteger[] clauPublicaECC,
                                        BigInteger[] parametresECC) {

    byte[] message = firmarECCDSA(M, clauDeFirma, parametresECC);
    byte[] KSE = new byte[32];
    new Random().nextBytes(KSE);
    BigInteger key = ECCDHKT(KSE, clauPrivadaECC, clauPublicaECC, parametresECC);
    byte[] encrypted = xifrarAES(message, key, 256);
    byte[] result = new byte[KSE.length+ encrypted.length];
    System.arraycopy(KSE,0,result,0, KSE.length);
    System.arraycopy(encrypted,0,result,KSE.length, encrypted.length);

    return result;
    }

    /**
     * input:  C is the received cryptogram, given as a list of bytes,
     *          clauDeVerificacioDeFirma public key of the sender for signature
     *          verification, clauPrivadaECC private key corresponding to the
     *          public key used to encrypt the message, clauPublicaECC public
     *          key corresponding to the private key used to encrypt the
     *          message, parametresECC={n, Gx, Gy, a, b, p}, G = (Gx, Gy)
     *          point of order n in the curve y2 = x3 + ax + b mod p
     *          (obviously, G is not the point at infinity);
     * output: a list of bytes M∥F∥ver where M is the decrypted message, F is
     *          the signature and ver is a byte with value 0x00 if the
     *          signature has been successfully verified and 0xff is the
     *          signature has not been verified.
     */
     public static byte[] rebreMissatge(byte[] C,
                                        BigInteger[] clauDeVerificacioDeFirma,
                                        BigInteger clauPrivadaECC,
                                        BigInteger[] clauPublicaECC,
                                        BigInteger[] parametresECC) {


      byte[] KSE = new byte[32];
      byte[] encrypted = new byte[C.length-32];

      System.arraycopy(C, 0, KSE, 0, 32);
      System.arraycopy(C, 32, encrypted, 0, encrypted.length);
      BigInteger KS = ECCDHKT(KSE, clauPrivadaECC, clauPublicaECC, parametresECC);

      byte[] message = desxifrarAES(encrypted, KS, 256);


      byte[] result = new byte[message.length+1];
      byte[] M = new byte[message.length -64];
      byte[] F = new byte[64];
      boolean ver = verificarECCDSA(F, clauDeVerificacioDeFirma, parametresECC);
      if(ver == true){
          System.arraycopy(result, 0, message, 0, message.length);
          result[message.length] = 0x00 & 0xff;
      }
      else
      {
          System.arraycopy(result, 0, message, 0, message.length);
          result[message.length] = (byte) (0xff & 0xff);
      }
      return result;
    }


     //ecc

    final static BigInteger TWO = new BigInteger("2");
    final static BigInteger THREE = new BigInteger("3");


    public static final BigInteger COEFA = new BigInteger("4");
    public static final BigInteger COEFB = new BigInteger("27");


    /**
     * input: P point of the curve given by 3 coordinates (x, y, z), (if z = 0,
     *          it’s the point at infinity), ParametresCorba={a, b, p},
     *          are the parameters of the curve y2 = x3 + ax + b mod p ;
     * output: a list {Rx,Ry,Rz} representing the inverse of P, R = −P
     *          (if Rz = 0, it’s the point at infinity).
     *
     */
    public static BigInteger[] invers(  BigInteger[] P,
                                        BigInteger[] ParametresCorba) {
        BigInteger a = ParametresCorba[0];
        BigInteger b = ParametresCorba[1];
        BigInteger p = ParametresCorba[2];

        BigInteger x = P[0];
        BigInteger y = P[1];
        BigInteger z = P[2];

        BigInteger[] R = new BigInteger[2];

        BigInteger x_R = x;
        BigInteger y_R = (y.negate()).mod(p);

        R[0] = x_R;
        R[1] = y_R;
        R[2] = z;

        return R;
    }

    /**
     * input: P and Q points of the curve given by 3 coordinates (x,y,z),
     *          (if z = 0, it’s the point at infinity),
     *          ParametresCorba={a, b, p} are the parameters of the curve
     *          y2 = x3 + ax + b mod p ;
     * output: a list {Rx,Ry,Rz} representing
     *          the point R = P +Q (if Rz = 0, it’s the point at infinity).
     *
     */
     public static BigInteger[] suma(BigInteger[] P,
                                    BigInteger[] Q,
                                    BigInteger[] ParametresCorba) {
        BigInteger a = ParametresCorba[0];
        BigInteger b = ParametresCorba[1];
        BigInteger p = ParametresCorba[2];

        if (P[2].compareTo(BigInteger.ZERO) == 0)
            return Q;
        else if (Q[2].compareTo(BigInteger.ZERO) == 0)
            return P;

        BigInteger y1 = P[1];
        BigInteger y2 = Q[1];
        BigInteger x1 = P[0];
        BigInteger x2 = Q[0];

        BigInteger alpha = BigInteger.ZERO;

        if (x2.compareTo(x1) == 0) {

            if (!(y2.compareTo(y1) == 0)) {
                BigInteger[] retVal = {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO};
                return retVal;
            }
            else {
                alpha = ((x1.modPow(TWO,p)).multiply(THREE)).add(a);
                alpha = (alpha.multiply((TWO.multiply(y1)).modInverse(p))).mod(p);
            }

        } else {
            alpha = ((y2.subtract(y1)).multiply((x2.subtract(x1)).modInverse(p))).mod(p);
        }

        BigInteger x3,y3;
        x3 = (((alpha.modPow(TWO,p)).subtract(x2)).subtract(x1)).mod(p);
        y3 = ((alpha.multiply(x1.subtract(x3))).subtract(y1)).mod(p);

        BigInteger[] retVal = {
          x3, y3, BigInteger.ONE
        };

        return retVal;

    }
    private static BigInteger[][] fastcache = null;

    public static void fastCache(BigInteger[] point,BigInteger[] ParametresCorba) {
        if(fastcache == null) {
            fastcache = new BigInteger[256][3];
            BigInteger[] temp = {BigInteger.ZERO,BigInteger.ZERO,BigInteger.ZERO};
            fastcache[0]= temp;
            for(int i = 1; i < fastcache.length; i++) {
                fastcache[i] = suma(fastcache[i-1],point,ParametresCorba);
            }
        }
    }
    private static BigInteger[] times256(BigInteger[] point,BigInteger[] ParametresCorba) {
	try {
	    BigInteger[] result = point;
	    for(int i = 0; i < 8; i++) {
		result = suma(result,point,ParametresCorba);
	    }
	    return result;
	} catch (Exception e) {
	    System.out.println("times256: error!");
	    return null;
	}
    }
     /**
     * input: k integer, P point of the curve given by 3 coordinates (x, y, z),
     *          (if z = 0, it’s the point at infinity), ParametresCorba={a, b, p}
     *          are the parameters of the curve y2 = x3 + ax + b mod p ;
     * output: a list {Rx,Ry,Rz} representing the point R=P+···+P =k·P (if Rz =0,
     *          it’s the point at infinity.
     *
     */
    public static BigInteger[] multiple(BigInteger k,
                                        BigInteger[] P,
                                        BigInteger[] ParametresCorba)
    {
        BigInteger[] result = {BigInteger.ZERO,BigInteger.ZERO,BigInteger.ZERO};
        byte[] coefb = k.toByteArray();
        fastCache(P,ParametresCorba);
            for(int i = 0; i < coefb.length; i++) {
                result = suma(times256(P,ParametresCorba),fastcache[coefb[i]&255],ParametresCorba);
            }
         return result;
    }

    /**
     * input: parametresECC={n, Gx, Gy, a, b, p}, G=(Gx, Gy) is a point of order
     *        n in the curve y2 = x3 + ax + b mod p (obviously, G is not the
     *          point at infinity);
     * output: a list {r,Px,Py}, r is the private key, and (Px,Py) is the point
     *        (different from the point at infinity) that is the public key.
     *
     */
    public static BigInteger[] clausECC(BigInteger[] parametresECC) {

        BigInteger n = parametresECC[0];
        BigInteger Gx = parametresECC[1];
        BigInteger Gy = parametresECC[2];
        BigInteger a = parametresECC[3];
        BigInteger b = parametresECC[4];
        BigInteger p = parametresECC[5];


        // private key
        BigInteger prk = new BigInteger(p.bitLength() + 17,new SecureRandom());
        if (n != null)
            prk=prk.mod(n);

        BigInteger[] pointGenerator = {Gx, Gy, BigInteger.ONE};
        BigInteger[] ParametresCorba = {a, b, p};
        BigInteger[] pk = multiple(prk, pointGenerator, ParametresCorba);
        BigInteger[] result = {prk,pk[0],pk[1]};

        return result;
    }

    /**
     * intput: bytesAleatoris is a list of random bytes,
     * clauPrivadaECC is an integer,
     * clauPublicaECC={Px,Py} (different of the point at infinity)
     * parametresECC={n,Gx,Gy,a,b,p},
     * G = (Gx,Gy) is a point of order n of the curve y2 = x3 + ax + b mod p
     *      (obviously, G is not the point at infinity);
     *
     * output: a 256-bit secret key to be used in AES: With clauPrivadaECC and
     *         clauPublicaECC a key DH with components (x,y) is computed.
     *         The secret key k is given by k=sha256(bytesAleatoris∥x), x
     *         in bytes (without two’s complement).
     */
    public static BigInteger ECCDHKT(   byte[] bytesAleatoris,
                                        BigInteger clauPrivadaECC,
                                        BigInteger[] clauPublicaECC,
                                        BigInteger[] parametresECC) {

        BigInteger n = parametresECC[0];
        BigInteger Gx = parametresECC[1];
        BigInteger Gy = parametresECC[2];
        BigInteger a = parametresECC[3];
        BigInteger b = parametresECC[4];
        BigInteger p = parametresECC[5];


        BigInteger[] ParametresCorba = {a, b, p};
        BigInteger[] DH = multiple( clauPrivadaECC,
                                    clauPublicaECC,
                                    ParametresCorba);


// concat arrays
        byte[] s = bytesAleatoris;
        byte[] x = DH[0].toByteArray();
        byte[] K = new byte[s.length+x.length];
        System.arraycopy(s,0,K,0, s.length);
        System.arraycopy(x,0,K,s.length, x.length);

        return SHA256(K);
    }

    /**
     * input: M is an arbitraryly long array of bytes, the message to be signed,
     *          clauFirma is an integer, the private key of the sender
     *          parametresECC={n,Gx,Gy,a,b,p}, G = (Gx,Gy) is a point of order
     *          n in the curve y2 = x3 + ax + b mod p (obviously, G is not the
     *          point at infinity); an array of bytes, the signed message;
     * output: it is the concatenation of the array M with an array of exactly
     *          64 bytes representing the signature.
     *
     */
    public static byte[] firmarECCDSA(  byte[] M,
                                        BigInteger clauFirma,
                                        BigInteger[] parametresECC) {
        BigInteger n = parametresECC[0];
        BigInteger Gx = parametresECC[1];
        BigInteger Gy = parametresECC[2];
        BigInteger a = parametresECC[3];
        BigInteger b = parametresECC[4];
        BigInteger p = parametresECC[5];
        BigInteger[] ParametresCorba = {a, b, p};
        BigInteger f1 ;
        BigInteger f2;
        do{
            BigInteger k = new BigInteger(p.bitLength() + 17,new SecureRandom());
            if (n != null)
                k=k.mod(n);


            BigInteger[] G = {Gx,Gy,BigInteger.ONE};
            BigInteger[] temp = multiple(k,G,ParametresCorba);
            f1 = temp[0].mod(n);
            f2 = ((f1.multiply(clauFirma).add(SHA256(M))).divide(k)).mod(n);
        }while (f1.compareTo(BigInteger.ZERO) == 0 || f2.compareTo(BigInteger.ZERO) == 0);

        byte[] f1_bytes = f1.toByteArray();
        byte[] f2_bytes = f2.toByteArray();
        byte[] sign = new byte[64];
        for(int i=0; i<64; i++)
            sign[i] = (byte) 0;

        System.arraycopy(f1_bytes, 0, sign, 0, f1_bytes.length);
        System.arraycopy(f2_bytes, 0, sign, 32, f2_bytes.length);

        byte[] result = new byte[sign.length+ M.length];
        System.arraycopy(M,0,result,0, M.length);
        System.arraycopy(sign,0,result,M.length, sign.length);


        return result;

    }

    /**
     * input: MS is a message (allegedly) signed by the system ECCDSA with
     *          parameters parametresECC using the private key corresponding
     *          to the public key clauVer;
     * output: a boolean indicating whether the
     *          signature is authentic or not.
     *
     */
    public static boolean verificarECCDSA(  byte[] MS,
                                            BigInteger[] clauVer,
                                            BigInteger[] parametresECC) {
        BigInteger n = parametresECC[0];
        BigInteger Gx = parametresECC[1];
        BigInteger Gy = parametresECC[2];
        BigInteger a = parametresECC[3];
        BigInteger b = parametresECC[4];
        BigInteger p = parametresECC[5];
        BigInteger[] ParametresCorba = {a, b, p};

        BigInteger w1 = BigInteger.ZERO;
        BigInteger w2 = BigInteger.ZERO;

        byte[] f1_bytes = new byte[32];
        byte[] f2_bytes = new byte[32];

        System.arraycopy(MS, MS.length-64, f1_bytes, 0, 32);
        System.arraycopy(MS, MS.length-32, f2_bytes, 0, 32);

        BigInteger f1 = new BigInteger(f1_bytes);
        BigInteger f2 = new BigInteger(f2_bytes);

        w1 = (SHA256(MS).divide(f2)).mod(n);
        w2 = (f1.divide(f2)).mod(n);

        BigInteger[] G = {Gx,Gy,BigInteger.ONE};
        BigInteger[] w = suma(multiple(w1,G,ParametresCorba),multiple(w2,clauVer,ParametresCorba),ParametresCorba);
        if(w[0].mod(n).compareTo(f1) == 0)
            return true;
        else
            return false;
    }

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

    public static BigInteger SHA256(byte[] M) {
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

//aes

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
        byte[] paddedMsg = M;// padMessage(M, blockSize);

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

           printToHex("Encrypt after XOR ", state);
            state = rijndael(state, keySchedule, Nk, Nr);
           printToHex("AFTER ", state);

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

            printToHex("MMM BEFORE", state);
            state = invRijndael(state, keySchedule, Nk, Nr);


            for (int ii = 0; ii < 4 * 4; ii++) {
                plaintext[ii] = state[ii % 4][(ii / 4)];
                // M[ii] = state[ii % 4][(ii / 4)];
            }
            byte[] tmp = null;
            if (i == 0) tmp = IV;
            else        tmp = ct[i-1];

            plaintext = XORed(tmp, plaintext);
            System.out.println("AFTER "+sha256.toHexString(plaintext));
            // printToHex("MMM AFTER", state);

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

        System.exit(0);

    }

}



