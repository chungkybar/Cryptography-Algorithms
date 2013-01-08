public class test {
    

  public static void main1(String[] args) {

        String message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

        char[] a = {'a'};
        char[] msg = {(char)0x61 ,(char)0x62 ,(char)0x63 ,(char)0x64 ,
                        (char)0x62 ,(char)0x63 ,(char)0x64 ,(char)0x65 ,
                        (char)0x63 ,(char)0x64 ,(char)0x65 ,(char)0x66,
                        (char)0x64 ,(char)0x65 ,(char)0x66 ,(char)0x67 ,
                        (char)0x65 ,(char)0x66 ,(char)0x67 ,(char)0x68 ,
                        (char)0x66 ,(char)0x67 ,(char)0x68 ,(char)0x69 ,
                        (char)0x67 ,(char)0x68 ,(char)0x69 ,(char)0x6a ,
                        (char)0x68 ,(char)0x69 ,(char)0x6a ,(char)0x6b ,
                        (char)0x69 ,(char)0x6a ,(char)0x6b ,(char)0x6c ,
                        (char)0x6a ,(char)0x6b ,(char)0x6c ,(char)0x6d ,
                        (char)0x6b ,(char)0x6c ,(char)0x6d ,(char)0x6e ,
                        (char)0x6c ,(char)0x6d ,(char)0x6e ,(char)0x6f ,
                        (char)0x6d ,(char)0x6e ,(char)0x6f ,(char)0x70 ,
                        (char)0x6e ,(char)0x6f ,(char)0x70 ,(char)0x71
                    };


        String[] messages = {
            "",
            "Test vector from febooti.com",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "abc",
            "message digest",
            "secure hash algorithm",
            "SHA256 is considered to be safe",
            "For this sample, this 63-byte string will be used as input data",
            "This is exactly 64 bytes long, not counting the terminating byte"
         };
        for (String string : messages) {
            System.out.println(string.length());
            System.out.println(string);
            System.out.println(sha256.hash(string.toString().getBytes()));
        }

    }

}
