------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

with Saatana.Crypto.Stream_Tools;

package Saatana.Crypto.Phelix.Test_Vectors with
  SPARK_Mode => Off
is

   pragma Annotate (GNATcheck, Exempt_On, "Visible_Components",
                    "Public access to components is intentional for test subroutines(s).");
   type Test_Vector is
      record
         Key       : Stream_Tools.Key_Stream_Access;
         Nonce     : Stream_Tools.Nonce_Stream_Access;
         Aad       : Stream_Tools.Plaintext_Stream_Access;
         Plaintext : Stream_Tools.Plaintext_Stream_Access;
         --  expected results
         Cipher    : Stream_Tools.Ciphertext_Stream_Access;
         MAC       : Stream_Tools.MAC_Stream_Access;
      end record;
   pragma Annotate (GNATcheck, Exempt_Off, "Visible_Components");

   function "+" (Value : in String) return Stream_Tools.Ciphertext_Stream_Access renames Stream_Tools.To_Stream;
   function "+" (Value : in String) return Stream_Tools.Key_Stream_Access        renames Stream_Tools.To_Stream;
   function "+" (Value : in String) return Stream_Tools.MAC_Stream_Access        renames Stream_Tools.To_Stream;
   function "+" (Value : in String) return Stream_Tools.Nonce_Stream_Access      renames Stream_Tools.To_Stream;
   function "+" (Value : in String) return Stream_Tools.Plaintext_Stream_Access  renames Stream_Tools.To_Stream;

   type Test_Vectors is array (Positive range <>) of Test_Vector;

   --  Known answer tests.
   KAT           : constant Test_Vectors
     :=
       (001 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80818283",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E69FE0A",
                MAC       => +"A188070F2B69B995F5764390551ED14D"),
        --  /* ---------- KAT vector #  1 ------------- */
        --  {256,  36,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80818283}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E69FE0A}, /* cText */
        --  {A188070F2B69B995F5764390551ED14D}  /* mac */
        002 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E69FE",
                MAC       => +"01C9AA04CB13BC860C506D6D87183C23"),
        --  /* ---------- KAT vector #  2 ------------- */
        --  { 256,  35,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E69FE}, /* cText */
        --  {01C9AA04CB13BC860C506D6D87183C23}  /* mac */
        003 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E69",
                MAC       => +"DBD13C2B97447B3E0E462C690CADAEAD"),
        --  /* ---------- KAT vector #  3 ------------- */
        --  { 256,  34,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {0x202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E69}, /* cText */
        --  {DBD13C2B97447B3E0E462C690CADAEAD}  /* mac */
        004 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E",
                MAC       => +"7B58408F2F04B98EA6DA1EFAACD1A03C"),
        --  /* ---------- KAT vector #  4 ------------- */
        --  { 256,  33,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F80}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF41E}, /* cText */
        --  {7B58408F2F04B98EA6DA1EFAACD1A03C}  /* mac */
        005 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF4",
                MAC       => +"0857F64C5711B02557DE55FB6C90BA7A"),
        --  /* ---------- KAT vector #  5 ------------- */
        --  { 256,  32,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54BF4}, /* cText */
        --  {0857F64C5711B02557DE55FB6C90BA7A}  /* mac */
        006 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54B",
                MAC       => +"3C11893784C1FE79D5EBC22310F85C26"),
        --  /* ---------- KAT vector #  6 ------------- */
        --  { 256,  31,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE54B}, /* cText */
        --  {3C11893784C1FE79D5EBC22310F85C26}  /* mac */
        007 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE5",
                MAC       => +"7C2C141DCE45F0742A8F1271B3529B1E"),
        --  /* ---------- KAT vector #  7 ------------- */
        --  { 256,  30,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9CE5}, /* cText */
        --  {7C2C141DCE45F0742A8F1271B3529B1E}  /* mac */
        008 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9C",
                MAC       => +"9228BA422B7EEB1C9C61006FD0878E30"),
        --  /* ---------- KAT vector #  8 ------------- */
        --  { 256,  29,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F9C}, /* cText */
        --  {9228BA422B7EEB1C9C61006FD0878E30}  /* mac */
        009 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A7B",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F",
                MAC       => +"D8B3CDC65D380C92099F80918470543E"),
        --  /* ---------- KAT vector #  9 ------------- */
        --  { 256,  28,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A7B}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493765F}, /* cText */
        --  {D8B3CDC65D380C92099F80918470543E}  /* mac */
        010 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778797A",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F9149376",
                MAC       => +"0D77A916B9C86DDDCDE3E2B9ED7C9A34"),
        --  /* ---------- KAT vector # 10 ------------- */
        --  {256,  27,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778797A}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F9149376}, /* cText */
        --  {0D77A916B9C86DDDCDE3E2B9ED7C9A34}  /* mac */
        011 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F70717273747576777879",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493",
                MAC       => +"AC8BAC91BAA96E5ECCA2E6A4607C7A6D"),
        --  /* ---------- KAT vector # 11 ------------- */
        --  {256,  26,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F70717273747576777879}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F91493}, /* cText */
        --  {AC8BAC91BAA96E5ECCA2E6A4607C7A6D}  /* mac */
        012 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475767778",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F914",
                MAC       => +"787AD5B9F1414FD57D424557CA3A2B16"),
        --  /* ---------- KAT vector # 12 ------------- */
        --  { 256,  25,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475767778}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F914}, /* cText */
        --  {787AD5B9F1414FD57D424557CA3A2B16}  /* mac */
        013 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F7071727374757677",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F9",
                MAC       => +"697E436812FC7E4BE3866081D519DAAE"),
        --  /* ---------- KAT vector # 13 ------------- */
        --  { 256,  24,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F7071727374757677}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4F9}, /* cText */
        --  {697E436812FC7E4BE3866081D519DAAE}  /* mac */
        014 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F70717273747576",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4",
                MAC       => +"18F4115DE3C7DE3E7A6B98DD5530BFA3"),
        --  /* ---------- KAT vector # 14 ------------- */
        --  { 256,  23,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F70717273747576}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020D4}, /* cText */
        --  {18F4115DE3C7DE3E7A6B98DD5530BFA3}  /* mac */
        015 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172737475",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020",
                MAC       => +"2137BBEFF74F39E1F20AABC61B0A5308"),
        --  /* ---------- KAT vector # 15 ------------- */
        --  { 256,  22,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172737475}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD95020}, /* cText */
        --  {2137BBEFF74F39E1F20AABC61B0A5308}  /* mac */
        016 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F7071727374",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD950",
                MAC       => +"EEAEDE8E0E77AAB793019E3A63C7CDE1"),
        --  /* ---------- KAT vector # 16 ------------- */
        --  { 256,  21,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F7071727374}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD950}, /* cText */
        --  {EEAEDE8E0E77AAB793019E3A63C7CDE1}  /* mac */
        017 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F70717273",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0AD9",
                MAC       => +"92FDD321FC124816F6682BF541AA9199"),
        --  /* ---------- KAT vector # 17 ------------- */
        --  { 256,  20,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F70717273}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0AD9}, /* cText */
        --  {92FDD321FC124816F6682BF541AA9199}  /* mac */
        018 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F707172",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E0A",
                MAC       => +"8581CC38476DB6D6885996DDA266424A"),
        --  /* ---------- KAT vector # 18 ------------- */
        --  { 256,  19,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F707172}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3094E0A}, /* cText */
        --  {8581CC38476DB6D6885996DDA266424A}  /* mac */
        019 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F7071",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3094E",
                MAC       => +"5DD5C5ACA328524AB6FEF1E1F2339190"),
        --  /* ---------- KAT vector # 19 ------------- */
        --  { 256,  18,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --     {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --     {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --     {}, /* aad */
        --     {606162636465666768696A6B6C6D6E6F7071}, /* pText */
        --     {20C5D60E0287BC91FD9261409FBE0AE3094E}, /* cText */
        --     {5DD5C5ACA328524AB6FEF1E1F2339190}  /* mac */
        020 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F70",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE309",
                MAC       => +"8114A28F9E36305B2A9FEBA4C6CF3AA4"),
        --  /* ---------- KAT vector # 20 ------------- */
        --  { 256,  17,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F70}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE309}, /* cText */
        --  {8114A28F9E36305B2A9FEBA4C6CF3AA4}  /* mac */
        021 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E6F",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0AE3",
                MAC       => +"DBC830FB616AD45E6D232E2235ACBC17"),
        --  /* ---------- KAT vector # 21 ------------- */
        --  { 256,  16,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E6F}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0AE3}, /* cText */
        --  {DBC830FB616AD45E6D232E2235ACBC17}  /* mac */
        022 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D6E",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE0A",
                MAC       => +"D660E8281792E5D008D7B2549E31A6EC"),
        --  /* ---------- KAT vector # 22 ------------- */
        --  { 256,  15,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D6E}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE0A}, /* cText */
        --  {D660E8281792E5D008D7B2549E31A6EC}  /* mac */
        023 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C6D",
                Cipher    => +"20C5D60E0287BC91FD9261409FBE",
                MAC       => +"9EE7D62BD0010503DBFAB06349D4E5DE"),
        --  /* ---------- KAT vector # 23 ------------- */
        --  { 256,  14,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C6D}, /* pText */
        --  {20C5D60E0287BC91FD9261409FBE}, /* cText */
        --  {9EE7D62BD0010503DBFAB06349D4E5DE}  /* mac */
        024 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B6C",
                Cipher    => +"20C5D60E0287BC91FD9261409F",
                MAC       => +"C27FDD27582E3B1308ADB01591B158BF"),
        --  /* ---------- KAT vector # 24 ------------- */
        --  { 256,  13,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B6C}, /* pText */
        --  {20C5D60E0287BC91FD9261409F}, /* cText */
        --  {C27FDD27582E3B1308ADB01591B158BF}  /* mac */
        025 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A6B",
                Cipher    => +"20C5D60E0287BC91FD926140",
                MAC       => +"03CA735B83A44A4E482AF94E4277021F"),
        --  /* ---------- KAT vector # 25 ------------- */
        --  { 256,  12,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A6B}, /* pText */
        --  {20C5D60E0287BC91FD926140}, /* cText */
        --  {03CA735B83A44A4E482AF94E4277021F}  /* mac */
        026 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768696A",
                Cipher    => +"20C5D60E0287BC91FD9261",
                MAC       => +"BA1260791F0C07D841485E5F4EE0E7C4"),
        --  /* ---------- KAT vector # 26 ------------- */
        --  { 256,  11,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768696A}, /* pText */
        --  {20C5D60E0287BC91FD9261}, /* cText */
        --  {BA1260791F0C07D841485E5F4EE0E7C4}  /* mac */
        027 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"60616263646566676869",
                Cipher    => +"20C5D60E0287BC91FD92",
                MAC       => +"2678FFF0B35B8469C76AD9C31C498EFB"),
        --  /* ---------- KAT vector # 27 ------------- */
        --  { 256,  10,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {60616263646566676869}, /* pText */
        --  {20C5D60E0287BC91FD92}, /* cText */
        --  {2678FFF0B35B8469C76AD9C31C498EFB}  /* mac */
        028 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465666768",
                Cipher    => +"20C5D60E0287BC91FD",
                MAC       => +"0BB6A12BB92131600C1CA2A5E7F96E56"),
        --  /* ---------- KAT vector # 28 ------------- */
        --  { 256,   9,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465666768}, /* pText */
        --  {20C5D60E0287BC91FD}, /* cText */
        --  {0BB6A12BB92131600C1CA2A5E7F96E56}  /* mac */
        029 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"6061626364656667",
                Cipher    => +"20C5D60E0287BC91",
                MAC       => +"6E8D2E17DED7DA7046E56E2B896CC1D2"),
        --  /* ---------- KAT vector # 29 ------------- */
        --  { 256,   8,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {6061626364656667}, /* pText */
        --  {20C5D60E0287BC91}, /* cText */
        --  {6E8D2E17DED7DA7046E56E2B896CC1D2}  /* mac */
        030 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"60616263646566",
                Cipher    => +"20C5D60E0287BC",
                MAC       => +"1061841DA0172EF1C227B3F8AD3ACEEE"),
        --  /* ---------- KAT vector # 30 ------------- */
        --  { 256,   7,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {60616263646566}, /* pText */
        --  {20C5D60E0287BC}, /* cText */
        --  {1061841DA0172EF1C227B3F8AD3ACEEE}  /* mac */
        031 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162636465",
                Cipher    => +"20C5D60E0287",
                MAC       => +"71E9CF92E95B8A98B1221085BA5C3326"),
        --  /* ---------- KAT vector # 31 ------------- */
        --  { 256,   6,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162636465}, /* pText */
        --  {20C5D60E0287}, /* cText */
        --  {71E9CF92E95B8A98B1221085BA5C3326}  /* mac */
        032 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"6061626364",
                Cipher    => +"20C5D60E02",
                MAC       => +"0799D896DCA82A8172DCD3AA4315A83D"),
        --  /* ---------- KAT vector # 32 ------------- */
        --  { 256,   5,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {6061626364}, /* pText */
        --  {20C5D60E02}, /* cText */
        --  {0799D896DCA82A8172DCD3AA4315A83D}  /* mac */
        033 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"60616263",
                Cipher    => +"20C5D60E",
                MAC       => +"2A1E8FFB14DE38E9A21675FA7BC993E1"),
        --  /* ---------- KAT vector # 33 ------------- */
        --  { 256,   4,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {60616263}, /* pText */
        --  {20C5D60E}, /* cText */
        --  {2A1E8FFB14DE38E9A21675FA7BC993E1}  /* mac */
        034 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"606162",
                Cipher    => +"20C5D6",
                MAC       => +"AF97E2AAB403A268C86609B62DF89B1C"),
        --  /* ---------- KAT vector # 34 ------------- */
        --  { 256,   3,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {606162}, /* pText */
        --  {20C5D6}, /* cText */
        --  {AF97E2AAB403A268C86609B62DF89B1C}  /* mac */
        035 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"6061",
                Cipher    => +"20C5",
                MAC       => +"6E18FF3D1895F6E228508CF01CC3CA86"),
        --  /* ---------- KAT vector # 35 ------------- */
        --  { 256,   2,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F}, /* key */
        --  {202122232425262728292A2B2C2D2E2F}, /* nonce */
        --  {}, /* aad */
        --  {6061}, /* pText */
        --  {20C5}, /* cText */
        --  {6E18FF3D1895F6E228508CF01CC3CA86}  /* mac */
        036 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"60",
                Cipher    => +"20",
                MAC       => +"0151407CD97566073BACF241EA168646"),
        037 => (Key       => +"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                Nonce     => +"202122232425262728292A2B2C2D2E2F",
                Aad       => +"",
                Plaintext => +"",
                Cipher    => +"",
                MAC       => +"A63B5824F2928A854604F62D7AC2B529"),
        038 => (Key       => +"CAD665FE4DD1905CF7E41608515E0B81",
                Nonce     => +"40301FEF8AE13F6039F451CBCC15483D",
                Aad       => +"",
                Plaintext => +"0A2434C1C0729B06BCA40E16F5C72079F5B52CD5BB1BCB5243E2A8F6040543D6E3E8E699",
                Cipher    => +"B65C49EF113013BAEE91821DBFD22A2D812DF9C0B0E04752C10B38F34EF00C051868DD72",
                MAC       => +"0B63B0D9B3EF8F63ECF0757B5C6375A7"),
        --  /* ---------- KAT vector # 38 ------------- */
        --  { 128,  36,   0, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {CAD665FE4DD1905CF7E41608515E0B81}, /* key */
        --  {40301FEF8AE13F6039F451CBCC15483D}, /* nonce */
        --  {}, /* aad */
        --  {0A2434C1C0729B06BCA40E16F5C72079F5B52CD5BB1BCB5243E2A8F6040543D6E3E8E699}, /* pText */
        --  {B65C49EF113013BAEE91821DBFD22A2D812DF9C0B0E04752C10B38F34EF00C051868DD72}, /* cText */
        --  {0B63B0D9B3EF8F63ECF0757B5C6375A7}  /* mac */
        039 => (Key       => +"2F0B1B9D8E8C91086EE48383B3C205040E0EB5CF4D4D9369",
                Nonce     => +"27A9ACED3B9F80650F657A7C64A2747F",
                Aad       => +"A7",
                Plaintext => +"5C94A0A0EDD908296DC11AEA6F8D26007623F547757143856BA1C57424E2A216DA8158",
                Cipher    => +"DF75D9FFF2E2147E035FF0AF3CFCFD4D194B111F0CFAD45479A89D67D1442A152AD66C",
                MAC       => +"E944166503502DDB44A9839EFA76AD64"),
        --  /* ---------- KAT vector # 39 ------------- */
        --  { 192,  35,   1, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {2F0B1B9D8E8C91086EE48383B3C205040E0EB5CF4D4D9369}, /* key */
        --  {27A9ACED3B9F80650F657A7C64A2747F}, /* nonce */
        --  {A7}, /* aad */
        --  {5C94A0A0EDD908296DC11AEA6F8D26007623F547757143856BA1C57424E2A216DA8158}, /* pText */
        --  {DF75D9FFF2E2147E035FF0AF3CFCFD4D194B111F0CFAD45479A89D67D1442A152AD66C}, /* cText */
        --  {E944166503502DDB44A9839EFA76AD64}  /* mac */
        040 => (Key       => +"979C012EC130C0DD7C38E8ED747F39F9B710776C6C5A90189590CF3CD8B95359",
                Nonce     => +"CE2A62BF0C462E23485A4AB1AE9156B8",
                Aad       => +"DC41",
                Plaintext => +"B7A56A3863EF45B7D7A5601659523F98B65DE71AD93DCDD5C03378B62B77E4086126",
                Cipher    => +"F1D514267A7FBF2418E9118027CE8A455C9CC5CD54529120FE215CA7C04B11633076",
                MAC       => +"BA8AC98823B01022F754C64F8E2E0B04"),
        --  /* ---------- KAT vector # 40 ------------- */
        --  { 256,  34,   2, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {979C012EC130C0DD7C38E8ED747F39F9B710776C6C5A90189590CF3CD8B95359}, /* key */
        --  {CE2A62BF0C462E23485A4AB1AE9156B8}, /* nonce */
        --  {DC41}, /* aad */
        --  {B7A56A3863EF45B7D7A5601659523F98B65DE71AD93DCDD5C03378B62B77E4086126}, /* pText */
        --  {F1D514267A7FBF2418E9118027CE8A455C9CC5CD54529120FE215CA7C04B11633076}, /* cText */
        --  {BA8AC98823B01022F754C64F8E2E0B04}  /* mac */
        041 => (Key       => +"5C74EBC835C3F58119810AD910C6640D",
                Nonce     => +"E66E7E059238872EF0080BB04B96632B",
                Aad       => +"F59AA3",
                Plaintext => +"7FB503E20B59B7007FD8A093B645BE8A9E8CE62CC3E1089EA4FE03F464502F3F69",
                Cipher    => +"41928BEE2AF444D2B422134119F9E5DB76699082CC05709E49B40DCEB31D76C81E",
                MAC       => +"FCC09E213EF002CDA036C5F9"),
        --  /* ---------- KAT vector # 41 ------------- */
        --  { 128,  33,   3,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {5C74EBC835C3F58119810AD910C6640D}, /* key */
        --  {E66E7E059238872EF0080BB04B96632B}, /* nonce */
        --  {F59AA3}, /* aad */
        --  {7FB503E20B59B7007FD8A093B645BE8A9E8CE62CC3E1089EA4FE03F464502F3F69}, /* pText */
        --  {41928BEE2AF444D2B422134119F9E5DB76699082CC05709E49B40DCEB31D76C81E}, /* cText */
        --  {FCC09E213EF002CDA036C5F9}  /* mac */
        042 => (Key       => +"9E78A4B3F15CE1EB7E76D4F28460ADD871DF18DD5CE8B0D1",
                Nonce     => +"C683A20D0B2DFE82FE1F5D5C36811FC5",
                Aad       => +"00F7DE03",
                Plaintext => +"93AB391674C257E8319668A6C12A86D20809606B0D247C2540D64EE2C6C5E000",
                Cipher    => +"A84EEA0CA24D1421D60966C7BFDAAD1A2EA26808456B3BC6CCB26B703E6B7FDE",
                MAC       => +"F29EB37887801206"),
        --  /* ---------- KAT vector # 42 ------------- */
        --  { 192,  32,   4,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {9E78A4B3F15CE1EB7E76D4F28460ADD871DF18DD5CE8B0D1}, /* key */
        --  {C683A20D0B2DFE82FE1F5D5C36811FC5}, /* nonce */
        --  {00F7DE03}, /* aad */
        --  {93AB391674C257E8319668A6C12A86D20809606B0D247C2540D64EE2C6C5E000}, /* pText */
        --  {A84EEA0CA24D1421D60966C7BFDAAD1A2EA26808456B3BC6CCB26B703E6B7FDE}, /* cText */
        --  {F29EB37887801206}  /* mac */
        043 => (Key       => +"C11A9E69BC1F08E0C126455F90C78345F7A8FB2D69099A78A741ED9AD3946F95",
                Nonce     => +"6B030789CD2E23134525E688704888AC",
                Aad       => +"F7DBC4EBC5",
                Plaintext => +"BB65D112C512CC0A514B1B5B56BD18518AD7945E1D0B639CA72433A650ECD3",
                Cipher    => +"8A6F3C6FDC7E56790151E21B5D9C7F71E72A154095F38547ED31D9DA175DDB",
                MAC       => +"56F6548C7C643F4258A63968"),
        --  /* ---------- KAT vector # 43 ------------- */
        --  { 256,  31,   5,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {C11A9E69BC1F08E0C126455F90C78345F7A8FB2D69099A78A741ED9AD3946F95}, /* key */
        --  {6B030789CD2E23134525E688704888AC}, /* nonce */
        --  {F7DBC4EBC5}, /* aad */
        --  {BB65D112C512CC0A514B1B5B56BD18518AD7945E1D0B639CA72433A650ECD3}, /* pText */
        --  {8A6F3C6FDC7E56790151E21B5D9C7F71E72A154095F38547ED31D9DA175DDB}, /* cText */
        --  {56F6548C7C643F4258A63968}  /* mac */
        044 => (Key       => +"EFE9A9B32EE03F50B40AEAA2DE4BAD31",
                Nonce     => +"BC526359357018B13A8814E7D82E5E13",
                Aad       => +"E97C6C9F0D83",
                Plaintext => +"EE71D44302D458A4BDC3BF4364CE163276C1781EB9A97592C7977751EC0F",
                Cipher    => +"7AFB106FF445909551487ABEB2C04E2E26CAECF435BB38B0907E0A748708",
                MAC       => +"06FD214B44E3C7000210078A4DCB81AA"),
        --  /* ---------- KAT vector # 44 ------------- */
        --  { 128,  30,   6, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {EFE9A9B32EE03F50B40AEAA2DE4BAD31}, /* key */
        --  {BC526359357018B13A8814E7D82E5E13}, /* nonce */
        --  {E97C6C9F0D83}, /* aad */
        --  {EE71D44302D458A4BDC3BF4364CE163276C1781EB9A97592C7977751EC0F}, /* pText */
        --  {7AFB106FF445909551487ABEB2C04E2E26CAECF435BB38B0907E0A748708}, /* cText */
        --  {06FD214B44E3C7000210078A4DCB81AA}  /* mac */
        045 => (Key       => +"11A0AAF1EBB80D3578C65AA3377D917296B40AC4A98522F1",
                Nonce     => +"3B1D9B2AC2C26EBD598BABDB379BE1E3",
                Aad       => +"39F1B87CC41079",
                Plaintext => +"615A96E0AE8CB5E8A52BF9C08014D6C265B2DBF6B0D1FC5D690E068447",
                Cipher    => +"F6AAD42EE65CED822F773BBF92140F145690C9EEA49AB058FC1FA7739B",
                MAC       => +"2F5E0226FC6C9B32"),
        --  /* ---------- KAT vector # 45 ------------- */
        --  { 192,  29,   7,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {11A0AAF1EBB80D3578C65AA3377D917296B40AC4A98522F1}, /* key */
        --  {3B1D9B2AC2C26EBD598BABDB379BE1E3}, /* nonce */
        --  {39F1B87CC41079}, /* aad */
        --  {615A96E0AE8CB5E8A52BF9C08014D6C265B2DBF6B0D1FC5D690E068447}, /* pText */
        --  {F6AAD42EE65CED822F773BBF92140F145690C9EEA49AB058FC1FA7739B}, /* cText */
        --  {2F5E0226FC6C9B32}  /* mac */
        046 => (Key       => +"BFCB302D2D580DDB0836CE63783DF76DA9CAD386618F64502A2F7A6DA776EB8E",
                Nonce     => +"000AA0F8F74B7AB8B5D74A997E54DF5E",
                Aad       => +"8F5E1AF0B2C3F54F",
                Plaintext => +"D5846764BFD39A86B1CABDA57ABC98AF6BFBA1C3F8D920CB506C6E14",
                Cipher    => +"24F44F614AB8AB98BAAA7A81D59A21626DC1501AA2919D5E9E53C77D",
                MAC       => +"1E4BA9A1633B537864DE131F3C4225DE"),
        --  /* ---------- KAT vector # 46 ------------- */
        --  { 256,  28,   8, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {BFCB302D2D580DDB0836CE63783DF76DA9CAD386618F64502A2F7A6DA776EB8E}, /* key */
        --  {000AA0F8F74B7AB8B5D74A997E54DF5E}, /* nonce */
        --  {8F5E1AF0B2C3F54F}, /* aad */
        --  {D5846764BFD39A86B1CABDA57ABC98AF6BFBA1C3F8D920CB506C6E14}, /* pText */
        --  {24F44F614AB8AB98BAAA7A81D59A21626DC1501AA2919D5E9E53C77D}, /* cText */
        --  {1E4BA9A1633B537864DE131F3C4225DE}  /* mac */
        047 => (Key       => +"94CBFA07E7B46708A84942F527EB4D4B",
                Nonce     => +"05695412AD514C25A6EAC7140E1B3B2B",
                Aad       => +"0047486AD51C6BDBB6",
                Plaintext => +"90F849D66AF81AC97C1010F480B17001819262E8ADFB3B2774B5D0",
                Cipher    => +"4724CC7155ABB297439A2335F1FB8943C3D6AADDCE600318FCD95A",
                MAC       => +"B7DB6B512B30C824"),
        --  /* ---------- KAT vector # 47 ------------- */
        --  { 128,  27,   9,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {94CBFA07E7B46708A84942F527EB4D4B}, /* key */
        --  {05695412AD514C25A6EAC7140E1B3B2B}, /* nonce */
        --  {0047486AD51C6BDBB6}, /* aad */
        --  {90F849D66AF81AC97C1010F480B17001819262E8ADFB3B2774B5D0}, /* pText */
        --  {4724CC7155ABB297439A2335F1FB8943C3D6AADDCE600318FCD95A}, /* cText */
        --  {B7DB6B512B30C824}  /* mac */
        048 => (Key       => +"FF88E0985FF81163B0DA56629B808031BC36C3B6E30F29D2",
                Nonce     => +"FF1EA04D07A7C794216EC3DBCFBDEE21",
                Aad       => +"CC88BB893E3CD44EF606",
                Plaintext => +"9105C74E8701143717AB2464416A77492CB5EDCCAD1FD1AF620A",
                Cipher    => +"59C04639ED3E4F96F7C1DDEB8D23344CDBC4929A072F70F0CB0A",
                MAC       => +"1B0A29AA4572AD59042F11784F4C8E5C"),
        --  /* ---------- KAT vector # 48 ------------- */
        --  { 192,  26,  10, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {FF88E0985FF81163B0DA56629B808031BC36C3B6E30F29D2}, /* key */
        --  {FF1EA04D07A7C794216EC3DBCFBDEE21}, /* nonce */
        --  {CC88BB893E3CD44EF606}, /* aad */
        --  {9105C74E8701143717AB2464416A77492CB5EDCCAD1FD1AF620A}, /* pText */
        --  {59C04639ED3E4F96F7C1DDEB8D23344CDBC4929A072F70F0CB0A}, /* cText */
        --  {1B0A29AA4572AD59042F11784F4C8E5C}  /* mac */
        049 => (Key       => +"F4D9369F9FAD2E63AD92EED15CB15C335E2959EF647CCDEDFA1B3C77FE71AEED",
                Nonce     => +"5E44089D19F57EB7BD1DD996415B47AA",
                Aad       => +"6221DEF630DDA090315BE3",
                Plaintext => +"C8A1AC1B7D108F6CCCD2FC88317E61E053C1E8340F58CB1511",
                Cipher    => +"809D39D108F3981D4EF467CB73B409AEC1AF77A74D536DD3A8",
                MAC       => +"07554D89229C4E4E"),
        --  /* ---------- KAT vector # 49 ------------- */
        --  { 256,  25,  11,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {F4D9369F9FAD2E63AD92EED15CB15C335E2959EF647CCDEDFA1B3C77FE71AEED}, /* key */
        --  {5E44089D19F57EB7BD1DD996415B47AA}, /* nonce */
        --  {6221DEF630DDA090315BE3}, /* aad */
        --  {C8A1AC1B7D108F6CCCD2FC88317E61E053C1E8340F58CB1511}, /* pText */
        --  {809D39D108F3981D4EF467CB73B409AEC1AF77A74D536DD3A8}, /* cText */
        --  {07554D89229C4E4E}  /* mac */
        050 => (Key       => +"CE7CB710DEA4AB44C47AFCBEE69D876C",
                Nonce     => +"3419114D2BEC788C0E1826A9DAB42333",
                Aad       => +"90B110399E8F07324F9B1F36",
                Plaintext => +"74FDF6671882D815FC55E9477B72ADF5A461B1EB2C8DC576",
                Cipher    => +"42AC9CDC57307C41E813BF600F552CAEB9CF20EF87A16B56",
                MAC       => +"7F2B6106A1371CC44A61211C40DC3C4D"),
        --  /* ---------- KAT vector # 50 ------------- */
        --  { 128,  24,  12, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {CE7CB710DEA4AB44C47AFCBEE69D876C}, /* key */
        --  {3419114D2BEC788C0E1826A9DAB42333}, /* nonce */
        --  {90B110399E8F07324F9B1F36}, /* aad */
        --  {74FDF6671882D815FC55E9477B72ADF5A461B1EB2C8DC576}, /* pText */
        --  {42AC9CDC57307C41E813BF600F552CAEB9CF20EF87A16B56}, /* cText */
        --  {7F2B6106A1371CC44A61211C40DC3C4D}  /* mac */
        051 => (Key       => +"E8FE49880AD2BCECC48FCDAE4F699576DFC4ED6F8BD1DF46",
                Nonce     => +"DBDA8F8979D7136847AA0B9AD8A15E24",
                Aad       => +"79B1746EAC6BA4BAB456461282",
                Plaintext => +"653E893160C57A96BC2537A412EAC471DAE44C4E596383",
                Cipher    => +"770CCEA8FFAEFE0E91668B10F0F8EBE2AEEC73A2EB92AE",
                MAC       => +"1D87EAEE31AEC018C986DC80620E3D60"),
        --  /* ---------- KAT vector # 51 ------------- */
        --  { 192,  23,  13, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {E8FE49880AD2BCECC48FCDAE4F699576DFC4ED6F8BD1DF46}, /* key */
        --  {DBDA8F8979D7136847AA0B9AD8A15E24}, /* nonce */
        --  {79B1746EAC6BA4BAB456461282}, /* aad */
        --  {653E893160C57A96BC2537A412EAC471DAE44C4E596383}, /* pText */
        --  {770CCEA8FFAEFE0E91668B10F0F8EBE2AEEC73A2EB92AE}, /* cText */
        --  {1D87EAEE31AEC018C986DC80620E3D60}  /* mac */
        052 => (Key       => +"B805C17742FD53437859160467BD8A34D01E89B1F9E5DC07AB5E1854207E10C0",
                Nonce     => +"37402051153C470EA11C0B96DA5D4539",
                Aad       => +"1918A67153602A27AA31D81982F3",
                Plaintext => +"7BFFE633C4EC9361C0B35C4BACB4A691B73554517461",
                Cipher    => +"A12EE5A547E10054031E3694BF55EA7307E5A73B37E6",
                MAC       => +"3FA0ACD7FB3FBA91EC21CA47E6DFFBB9"),
        --  /* ---------- KAT vector # 52 ------------- */
        --  { 256,  22,  14, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {B805C17742FD53437859160467BD8A34D01E89B1F9E5DC07AB5E1854207E10C0}, /* key */
        --  {37402051153C470EA11C0B96DA5D4539}, /* nonce */
        --  {1918A67153602A27AA31D81982F3}, /* aad */
        --  {7BFFE633C4EC9361C0B35C4BACB4A691B73554517461}, /* pText */
        --  {A12EE5A547E10054031E3694BF55EA7307E5A73B37E6}, /* cText */
        --  {3FA0ACD7FB3FBA91EC21CA47E6DFFBB9}  /* mac */
        053 => (Key       => +"DF14A02D3E679D50F01EA16414D357AF",
                Nonce     => +"6A56B2606441C161E31CDADD3C958D39",
                Aad       => +"21C2F382B97296A1FBED9A12E9A078",
                Plaintext => +"696EF038447963619192890D1F8E48BCA44B051B85",
                Cipher    => +"A422C08F25A15873E6C9AD4538B638DF9DD3772663",
                MAC       => +"C9980795C56B0AAD"),
        --  /* ---------- KAT vector # 53 ------------- */
        --  { 128,  21,  15,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {DF14A02D3E679D50F01EA16414D357AF}, /* key */
        --  {6A56B2606441C161E31CDADD3C958D39}, /* nonce */
        --  {21C2F382B97296A1FBED9A12E9A078}, /* aad */
        --  {696EF038447963619192890D1F8E48BCA44B051B85}, /* pText */
        --  {A422C08F25A15873E6C9AD4538B638DF9DD3772663}, /* cText */
        --  {C9980795C56B0AAD}  /* mac */
        054 => (Key       => +"B28EE554E32607CDF7435636AB96A0FB37AD3F53976B10C9",
                Nonce     => +"8AC44394CECE48421C7A9C38D0BFB582",
                Aad       => +"241E68A6ACB5FF5DACAA7D50DE9AC19F",
                Plaintext => +"9235966AFE1433E5EA500D0551DC68BE52DB82AD",
                Cipher    => +"305F06EDD1570C9527314E543AD16F9AD2E989BF",
                MAC       => +"4BCE082044CB1B8779A33310"),
        --  /* ---------- KAT vector # 54 ------------- */
        --  { 192,  20,  16,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {B28EE554E32607CDF7435636AB96A0FB37AD3F53976B10C9}, /* key */
        --  {8AC44394CECE48421C7A9C38D0BFB582}, /* nonce */
        --  {241E68A6ACB5FF5DACAA7D50DE9AC19F}, /* aad */
        --  {9235966AFE1433E5EA500D0551DC68BE52DB82AD}, /* pText */
        --  {305F06EDD1570C9527314E543AD16F9AD2E989BF}, /* cText */
        --  {4BCE082044CB1B8779A33310}  /* mac */
        055 => (Key       => +"6920F2CE5E449ABB598BE96EAFD4EB6ADC76D8B41A4A3CF5C5CCC02F829C9AE8",
                Nonce     => +"66E4B5125E54821574D6B2BE8FAB7621",
                Aad       => +"3115DD76E555BCFF1681A5B6850D7A56B2",
                Plaintext => +"02E7C4B90725BC192E85B58088EBDD30263A2E",
                Cipher    => +"B783D5DBB12CF52F4414FCBBB15D17CD89BA19",
                MAC       => +"CB28D7C2671A4227F06D04F9B2ED416E"),
        --  /* ---------- KAT vector # 55 ------------- */
        --  { 256,  19,  17, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {6920F2CE5E449ABB598BE96EAFD4EB6ADC76D8B41A4A3CF5C5CCC02F829C9AE8}, /* key */
        --  {66E4B5125E54821574D6B2BE8FAB7621}, /* nonce */
        --  {3115DD76E555BCFF1681A5B6850D7A56B2}, /* aad */
        --  {02E7C4B90725BC192E85B58088EBDD30263A2E}, /* pText */
        --  {B783D5DBB12CF52F4414FCBBB15D17CD89BA19}, /* cText */
        --  {CB28D7C2671A4227F06D04F9B2ED416E}  /* mac */
        056 => (Key       => +"AB61E72C6CDFE2FAD7A36A1E8E156A88",
                Nonce     => +"BEF50FD830080BD8BC208A1F2EF267B0",
                Aad       => +"3E9A72D855DCE6036FDDB630655BDB63C43C",
                Plaintext => +"FD873131F8BA8F3F813E1EEB24370B9C6CD9",
                Cipher    => +"75C2B9A49D41A8ED693C707882DD8622EE14",
                MAC       => +"307E220C6C866FEB6E23F606"),
        --  /* ---------- KAT vector # 56 ------------- */
        --  { 128,  18,  18,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {AB61E72C6CDFE2FAD7A36A1E8E156A88}, /* key */
        --  {BEF50FD830080BD8BC208A1F2EF267B0}, /* nonce */
        --  {3E9A72D855DCE6036FDDB630655BDB63C43C}, /* aad */
        --  {FD873131F8BA8F3F813E1EEB24370B9C6CD9}, /* pText */
        --  {75C2B9A49D41A8ED693C707882DD8622EE14}, /* cText */
        --  {307E220C6C866FEB6E23F606}  /* mac */
        057 => (Key       => +"C7B421DABC8C9428CBCB3481758A8BFC93CB22292AD2D956",
                Nonce     => +"95DBE5ED54BC278C6AB6327072A7F593",
                Aad       => +"210E8B127D9FC61D0E3469E2D628EDA118D134",
                Plaintext => +"4021DFAAB71EA6D28A7DBCBD9334D104BB",
                Cipher    => +"D932150CD465FC86DF60DAED09D25B36AC",
                MAC       => +"F8C555974AEB108B1DAFB788"),
        --  /* ---------- KAT vector # 57 ------------- */
        --  { 192,  17,  19,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {C7B421DABC8C9428CBCB3481758A8BFC93CB22292AD2D956}, /* key */
        --  {95DBE5ED54BC278C6AB6327072A7F593}, /* nonce */
        --  {210E8B127D9FC61D0E3469E2D628EDA118D134}, /* aad */
        --  {4021DFAAB71EA6D28A7DBCBD9334D104BB}, /* pText */
        --  {D932150CD465FC86DF60DAED09D25B36AC}, /* cText */
        --  {F8C555974AEB108B1DAFB788}  /* mac */
        058 => (Key       => +"2B020E1257BF056E2B972C6DA280F86DAF16AC9CE5B50DC36F4E923EE1F1E008",
                Nonce     => +"81BFA71F52EC35DA55BE9C201D134AA8",
                Aad       => +"872DBEC25FD894F7612E6795B96724ADDBA1CEB3",
                Plaintext => +"52357BFBFA82E97220742D41050FFF99",
                Cipher    => +"E1B759220368FFC6642C9E414955ACED",
                MAC       => +"6D42C1160612B3C0FA39A926908972E2"),
        --  /* ---------- KAT vector # 58 ------------- */
        --  { 256,  16,  20, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {2B020E1257BF056E2B972C6DA280F86DAF16AC9CE5B50DC36F4E923EE1F1E008}, /* key */
        --  {81BFA71F52EC35DA55BE9C201D134AA8}, /* nonce */
        --  {872DBEC25FD894F7612E6795B96724ADDBA1CEB3}, /* aad */
        --  {52357BFBFA82E97220742D41050FFF99}, /* pText */
        --  {E1B759220368FFC6642C9E414955ACED}, /* cText */
        --  {6D42C1160612B3C0FA39A926908972E2}  /* mac */
        059 => (Key       => +"863A1A10A1DAEE533C3388F1FAD84260",
                Nonce     => +"A344C83FB16BC1E5AE5A5C003B6981D8",
                Aad       => +"E8817CD8748A2D77BA1C24CBDA8567C6532A3C55F1",
                Plaintext => +"4B867471AC6A9F185BEC974F6F538F",
                Cipher    => +"C3E98F53E27E55BDDD5173E868B577",
                MAC       => +"55E154E38031A5B07E9E944500D80444"),
        --  /* ---------- KAT vector # 59 ------------- */
        --  { 128,  15,  21, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {863A1A10A1DAEE533C3388F1FAD84260}, /* key */
        --  {A344C83FB16BC1E5AE5A5C003B6981D8}, /* nonce */
        --  {E8817CD8748A2D77BA1C24CBDA8567C6532A3C55F1}, /* aad */
        --  {4B867471AC6A9F185BEC974F6F538F}, /* pText */
        --  {C3E98F53E27E55BDDD5173E868B577}, /* cText */
        --  {55E154E38031A5B07E9E944500D80444}  /* mac */
        060 => (Key       => +"7A88563EF354F4256DE6D245D0549E7553F503FC035A25D8",
                Nonce     => +"5E1509974DF02FD3402C82926453F4C6",
                Aad       => +"4162EA6BB980EF788915CC188F233EB8E26C01CBE9DA",
                Plaintext => +"058E017FB8E7EAD784944910FE96",
                Cipher    => +"42BEAF9D2F3CD23B51954599A19F",
                MAC       => +"026E5EEBF663F7679997A5BB"),
        --  /* ---------- KAT vector # 60 ------------- */
        --  { 192,  14,  22,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {7A88563EF354F4256DE6D245D0549E7553F503FC035A25D8}, /* key */
        --  {5E1509974DF02FD3402C82926453F4C6}, /* nonce */
        --  {4162EA6BB980EF788915CC188F233EB8E26C01CBE9DA}, /* aad */
        --  {058E017FB8E7EAD784944910FE96}, /* pText */
        --  {42BEAF9D2F3CD23B51954599A19F}, /* cText */
        --  {026E5EEBF663F7679997A5BB}  /* mac */
        061 => (Key       => +"647BFE4D517A1DFBC1669C7CC253FAD296D44CFA2D487F677476D6067207EECE",
                Nonce     => +"4A5B0AAF7C5EEDDE2E69365A1030A2F4",
                Aad       => +"1FF84F6863ECB879813B055CC086441E12579B5AF1EF26",
                Plaintext => +"B055BD77EFAC960A1980ADF744",
                Cipher    => +"EE640A0104E41DB79086312469",
                MAC       => +"6B0A8CA8A6CBECC8C9B5C82CBA74FAAD"),
        --  /* ---------- KAT vector # 61 ------------- */
        --  { 256,  13,  23, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {647BFE4D517A1DFBC1669C7CC253FAD296D44CFA2D487F677476D6067207EECE}, /* key */
        --  {4A5B0AAF7C5EEDDE2E69365A1030A2F4}, /* nonce */
        --  {1FF84F6863ECB879813B055CC086441E12579B5AF1EF26}, /* aad */
        --  {B055BD77EFAC960A1980ADF744}, /* pText */
        --  {EE640A0104E41DB79086312469}, /* cText */
        --  {6B0A8CA8A6CBECC8C9B5C82CBA74FAAD}  /* mac */
        062 => (Key       => +"DE2116F7D1E735959F2C5DEF6EC0A2F2",
                Nonce     => +"941037CB17542988A99B1DF4D7D603E1",
                Aad       => +"19D2CBE9CA3D53AED8898F8CFB22ED71D350259496E583D5",
                Plaintext => +"7A56F716DCAC37566B17242C",
                Cipher    => +"2D20F7497398416C2536443A",
                MAC       => +"8DA654085E54F490890AD24C"),
        --  /* ---------- KAT vector # 62 ------------- */
        --  { 128,  12,  24,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {DE2116F7D1E735959F2C5DEF6EC0A2F2}, /* key */
        --  {941037CB17542988A99B1DF4D7D603E1}, /* nonce */
        --  {19D2CBE9CA3D53AED8898F8CFB22ED71D350259496E583D5}, /* aad */
        --  {7A56F716DCAC37566B17242C}, /* pText */
        --  {2D20F7497398416C2536443A}, /* cText */
        --  {8DA654085E54F490890AD24C}  /* mac */
        063 => (Key       => +"1B63C3DC6C0F00442E6F3E514052440E6BC75EE2909B7DBE",
                Nonce     => +"1E828E36B72DBE55BC6FD185C067E608",
                Aad       => +"73940F6331F01A5A416C15EC2EF1F2BE01FAE1182C2B1FBCB9",
                Plaintext => +"57D767B540CF1EDC83A23F",
                Cipher    => +"BD1AD54735884AE2756D24",
                MAC       => +"3DCF5A6A166C7476357CC1E4DC65DB41"),
        --  /* ---------- KAT vector # 63 ------------- */
        --  { 192,  11,  25, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {1B63C3DC6C0F00442E6F3E514052440E6BC75EE2909B7DBE}, /* key */
        --  {1E828E36B72DBE55BC6FD185C067E608}, /* nonce */
        --  {73940F6331F01A5A416C15EC2EF1F2BE01FAE1182C2B1FBCB9}, /* aad */
        --  {57D767B540CF1EDC83A23F}, /* pText */
        --  {BD1AD54735884AE2756D24}, /* cText */
        --  {3DCF5A6A166C7476357CC1E4DC65DB41}  /* mac */
        064 => (Key       => +"A7C90AF06FB2AC2876C96F2734C712B4B2FB845E4418CDB1737C096163A1E1A4",
                Nonce     => +"973616129E89912B663CB472A4107C79",
                Aad       => +"9688B712F1C7C6B4A4284C1A1A87CCBAAF72A49D6249E774825B",
                Plaintext => +"868A04318FB1D2C3D981",
                Cipher    => +"A2EFB435E80F2B8C23D1",
                MAC       => +"40538C9070CD13D23E7A01DB"),
        --  /* ---------- KAT vector # 64 ------------- */
        --  { 256,  10,  26,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {A7C90AF06FB2AC2876C96F2734C712B4B2FB845E4418CDB1737C096163A1E1A4}, /* key */
        --  {973616129E89912B663CB472A4107C79}, /* nonce */
        --  {9688B712F1C7C6B4A4284C1A1A87CCBAAF72A49D6249E774825B}, /* aad */
        --  {868A04318FB1D2C3D981}, /* pText */
        --  {A2EFB435E80F2B8C23D1}, /* cText */
        --  {40538C9070CD13D23E7A01DB}  /* mac */
        065 => (Key       => +"D9FDD2D8A1069EF1E2108BF441741E00",
                Nonce     => +"D0EAE947C5CD8A9795A5EB621C5EF746",
                Aad       => +"F15F7CF75DE1120159DC4950C3A9987525C680226C6648BB643154",
                Plaintext => +"76853F54C1563522E7",
                Cipher    => +"1904B89E79C54D98C9",
                MAC       => +"C35CDB7447BEEA3E1B1400F58E7A7FCC"),
        --  /* ---------- KAT vector # 65 ------------- */
        --  { 128,   9,  27, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {D9FDD2D8A1069EF1E2108BF441741E00}, /* key */
        --  {D0EAE947C5CD8A9795A5EB621C5EF746}, /* nonce */
        --  {F15F7CF75DE1120159DC4950C3A9987525C680226C6648BB643154}, /* aad */
        --  {76853F54C1563522E7}, /* pText */
        --  {1904B89E79C54D98C9}, /* cText */
        --  {C35CDB7447BEEA3E1B1400F58E7A7FCC}  /* mac */
        066 => (Key       => +"7FAED524B1FE1CC9C96F37FA5BC05DC0E6AD74F25BFFFA66",
                Nonce     => +"1F8CF4568976E7113B20371A27E855BC",
                Aad       => +"4ACB3148FD5E25EA83625096A5F8FC1DB47AC9E216CCBB182D76A5F7",
                Plaintext => +"C32A71E1E551565A",
                Cipher    => +"B7CB22E5449780DC",
                MAC       => +"D76FF2CCFB22E6DC78EA32BC64A8D338"),
        --  /* ---------- KAT vector # 66 ------------- */
        --  { 192,   8,  28, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {7FAED524B1FE1CC9C96F37FA5BC05DC0E6AD74F25BFFFA66}, /* key */
        --  {1F8CF4568976E7113B20371A27E855BC}, /* nonce */
        --  {4ACB3148FD5E25EA83625096A5F8FC1DB47AC9E216CCBB182D76A5F7}, /* aad */
        --  {C32A71E1E551565A}, /* pText */
        --  {B7CB22E5449780DC}, /* cText */
        --  {D76FF2CCFB22E6DC78EA32BC64A8D338}  /* mac */
        067 => (Key       => +"5FC2E412716416A0313B4C64836C8B087A161531377E2F99D4E4364CAE399A0F",
                Nonce     => +"D142D668ABA8D74EEC7CB8FAD910A10D",
                Aad       => +"2E6393DD5BF07D0D6FC19A00EA0AF845E737CA3D61DD87A657F4D974C7",
                Plaintext => +"3CE5F6EF970E64",
                Cipher    => +"80EAC67922C623",
                MAC       => +"C714D2CE1AD85FD9"),
        --  /* ---------- KAT vector # 67 ------------- */
        --  { 256,   7,  29,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {5FC2E412716416A0313B4C64836C8B087A161531377E2F99D4E4364CAE399A0F}, /* key */
        --  {D142D668ABA8D74EEC7CB8FAD910A10D}, /* nonce */
        --  {2E6393DD5BF07D0D6FC19A00EA0AF845E737CA3D61DD87A657F4D974C7}, /* aad */
        --  {3CE5F6EF970E64}, /* pText */
        --  {80EAC67922C623}, /* cText */
        --  {C714D2CE1AD85FD9}  /* mac */
        068 => (Key       => +"34CED32EA240CA6F5ACA5F0DC436593C",
                Nonce     => +"998EB24FB80A330111F7AC10C1B97DC9",
                Aad       => +"A213F0AE3BE92733262196694744B8FE31379626C3647D97A9779132D16B",
                Plaintext => +"52007818A7E9",
                Cipher    => +"25F9DEDCBFF0",
                MAC       => +"2805E406D5AB031089C5E3B33C21D7C6"),
        --  /* ---------- KAT vector # 68 ------------- */
        --  { 128,   6,  30, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {34CED32EA240CA6F5ACA5F0DC436593C}, /* key */
        --  {998EB24FB80A330111F7AC10C1B97DC9}, /* nonce */
        --  {A213F0AE3BE92733262196694744B8FE31379626C3647D97A9779132D16B}, /* aad */
        --  {52007818A7E9}, /* pText */
        --  {25F9DEDCBFF0}, /* cText */
        --  {2805E406D5AB031089C5E3B33C21D7C6}  /* mac */
        069 => (Key       => +"4D208B9E569DDB990916340C98FE2DE6A1E5F7A3F11EB2B0",
                Nonce     => +"565C8F51DF28EB6CBF2FDD2E2BF6B5F9",
                Aad       => +"161E1615FBD6F5F07C4D11424684F8F0788E37A7294D0ED5ECC876010E963C",
                Plaintext => +"B568A2E3A5",
                Cipher    => +"7AD00E0544",
                MAC       => +"EA792228DADA8736"),
        --  /* ---------- KAT vector # 69 ------------- */
        --  { 192,   5,  31,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {4D208B9E569DDB990916340C98FE2DE6A1E5F7A3F11EB2B0}, /* key */
        --  {565C8F51DF28EB6CBF2FDD2E2BF6B5F9}, /* nonce */
        --  {161E1615FBD6F5F07C4D11424684F8F0788E37A7294D0ED5ECC876010E963C}, /* aad */
        --  {B568A2E3A5}, /* pText */
        --  {7AD00E0544}, /* cText */
        --  {EA792228DADA8736}  /* mac */
        070 => (Key       => +"653F90772DEB5B2B2B712DB04872278328E4DCB2EE14C2215D92FF26BD9C6B5B",
                Nonce     => +"47451A4802964A8F4E417E02F25619C3",
                Aad       => +"23ABF2AB3BC6C8CB6E64659FC43BC258D631C3C9BF81E89FA66D0A9792BFA96F",
                Plaintext => +"1582CD30",
                Cipher    => +"463AFCFE",
                MAC       => +"04A790BBB5B026DC"),
        --  /* ---------- KAT vector # 70 ------------- */
        --  { 256,   4,  32,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {653F90772DEB5B2B2B712DB04872278328E4DCB2EE14C2215D92FF26BD9C6B5B}, /* key */
        --  {47451A4802964A8F4E417E02F25619C3}, /* nonce */
        --  {23ABF2AB3BC6C8CB6E64659FC43BC258D631C3C9BF81E89FA66D0A9792BFA96F}, /* aad */
        --  {1582CD30}, /* pText */
        --  {463AFCFE}, /* cText */
        --  {04A790BBB5B026DC}  /* mac */
        071 => (Key       => +"A5B00E06404845F87F74B665B4E44D32",
                Nonce     => +"6325E1EBC65EB71EBC317401DB05468F",
                Aad       => +"71661776C8DCC667A775FCFCDFDEBCBCB0D0CE220ECC6FB8A64A98B531BA3EA552",
                Plaintext => +"ECDB16",
                Cipher    => +"477716",
                MAC       => +"3106FB78880AA0E45EDC20AC"),
        --  /* ---------- KAT vector # 71 ------------- */
        --  { 128,   3,  33,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {A5B00E06404845F87F74B665B4E44D32}, /* key */
        --  {6325E1EBC65EB71EBC317401DB05468F}, /* nonce */
        --  {71661776C8DCC667A775FCFCDFDEBCBCB0D0CE220ECC6FB8A64A98B531BA3EA552}, /* aad */
        --  {ECDB16}, /* pText */
        --  {477716}, /* cText */
        --  {3106FB78880AA0E45EDC20AC}  /* mac */
        072 => (Key       => +"885D76D7C1A8E210A62BCD9B410F6E48787C5FF30016ECB4",
                Nonce     => +"6C76CAB155576410A9D37DC5607F40FA",
                Aad       => +"CAFE4DB59EB4FF941AC12166A2AD5CF43262AB0B10FE53E951751712B12345FDF6BB",
                Plaintext => +"801C",
                Cipher    => +"7FA9",
                MAC       => +"A1AA919439EA563B"),
        --  /* ---------- KAT vector # 72 ------------- */
        --  { 192,   2,  34,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {885D76D7C1A8E210A62BCD9B410F6E48787C5FF30016ECB4}, /* key */
        --  {6C76CAB155576410A9D37DC5607F40FA}, /* nonce */
        --  {CAFE4DB59EB4FF941AC12166A2AD5CF43262AB0B10FE53E951751712B12345FDF6BB}, /* aad */
        --  {801C}, /* pText */
        --  {7FA9}, /* cText */
        --  {A1AA919439EA563B}  /* mac */
        073 => (Key       => +"0F90A10795D7E26F18EF88D79FA2B4074BD4CAC1DE9289E41B972BFA1C9213EC",
                Nonce     => +"EE6A96C5222250C432DAF17AF9096689",
                Aad       => +"C51AE2E09989AB327C4657D98064B07F8592F26BDFE7CC416C50CA325F19D5E5C91AF1",
                Plaintext => +"B2",
                Cipher    => +"3E",
                MAC       => +"0F022698E1BF19F6A4FAB2315AF04DBB"),
        --  /* ---------- KAT vector # 73 ------------- */
        --  { 256,   1,  35, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {0F90A10795D7E26F18EF88D79FA2B4074BD4CAC1DE9289E41B972BFA1C9213EC}, /* key */
        --  {EE6A96C5222250C432DAF17AF9096689}, /* nonce */
        --  {C51AE2E09989AB327C4657D98064B07F8592F26BDFE7CC416C50CA325F19D5E5C91AF1}, /* aad */
        --  {B2}, /* pText */
        --  {3E}, /* cText */
        --  {0F022698E1BF19F6A4FAB2315AF04DBB}  /* mac */
        074 => (Key       => +"A6FC2F12C3632AC30458077CEAD97403",
                Nonce     => +"3B09F7C88031CE9AA7CDD365EB13131A",
                Aad       => +"69CD949AA1B35BE0FB5FCD45DBA9B00526F47B3B829E2878D48126022C32E1738C7BCDA2",
                Plaintext => +"",
                Cipher    => +"",
                MAC       => +"3A6B6D2A83C7707A2FBB72E176B77450"),
        --  /* ---------- KAT vector # 74 ------------- */
        --  { 128,   0,  36, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {A6FC2F12C3632AC30458077CEAD97403}, /* key */
        --  {3B09F7C88031CE9AA7CDD365EB13131A}, /* nonce */
        --  {69CD949AA1B35BE0FB5FCD45DBA9B00526F47B3B829E2878D48126022C32E1738C7BCDA2}, /* aad */
        --  {}, /* pText */
        --  {}, /* cText */
        --  {3A6B6D2A83C7707A2FBB72E176B77450}  /* mac */
        075 => (Key       => +"EA075128C9946D07A2CCB8950C4B8B72ABA314DD14ADB172B3A195F474B22D5B",
                Nonce     => +"8AB2C44800337423EEFBDE3352AB2400",
                Aad       => +"16573351AC68B133AE589C74",
                Plaintext => +"57FE1385F5323CE517C62B48CA3C458580EEE30188F2EE9784EC70B0E8EEBD2153E23958",
                Cipher    => +"3AE3A45D5BE2005546561F448490FD8FB066C72062D3CDA1702934FB890555411CCD2C16",
                MAC       => +"CD2C8A57090851F4348AF88E"),
        --  /* ---------- KAT vector # 75 ------------- */
        --  { 256,  36,  12,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {EA075128C9946D07A2CCB8950C4B8B72ABA314DD14ADB172B3A195F474B22D5B}, /* key */
        --  {8AB2C44800337423EEFBDE3352AB2400}, /* nonce */
        --  {16573351AC68B133AE589C74}, /* aad */
        --  {57FE1385F5323CE517C62B48CA3C458580EEE30188F2EE9784EC70B0E8EEBD2153E23958}, /* pText */
        --  {3AE3A45D5BE2005546561F448490FD8FB066C72062D3CDA1702934FB890555411CCD2C16}, /* cText */
        --  {CD2C8A57090851F4348AF88E}  /* mac */
        076 => (Key       => +"E9EE4213E3DFD40FBB2CA37AEDDAE0FFF278C0F8074132DFF4071398C0744D7D",
                Nonce     => +"7AC03936E5349B79638A114A6413EBBD",
                Aad       => +"57BB78F07E52FC8F",
                Plaintext => +"72E1B3C1ED2649D30AB0995A5E9181A886EAB7E35D98CCAC568F87132D189B9B595C09",
                Cipher    => +"00541DEB2DE425B259879DFC0E553C044F6FC22FF38BFF6FEA7C8820574193803B8705",
                MAC       => +"D9BF0C7802F476CFC6FB"),
        --  /* ---------- KAT vector # 76 ------------- */
        --  { 256,  35,   8,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {E9EE4213E3DFD40FBB2CA37AEDDAE0FFF278C0F8074132DFF4071398C0744D7D}, /* key */
        --  {7AC03936E5349B79638A114A6413EBBD}, /* nonce */
        --  {57BB78F07E52FC8F}, /* aad */
        --  {72E1B3C1ED2649D30AB0995A5E9181A886EAB7E35D98CCAC568F87132D189B9B595C09}, /* pText */
        --  {00541DEB2DE425B259879DFC0E553C044F6FC22FF38BFF6FEA7C8820574193803B8705}, /* cText */
        --  {D9BF0C7802F476CFC6FB}  /* mac */
        077 => (Key       => +"6DC84CB78225323BE4813B9094B573911D77653C103CDC72",
                Nonce     => +"DE06CD58BC37F879B6D2FB58D0A0292A",
                Aad       => +"FABA30091AB2",
                Plaintext => +"7A39D7B1BF94148941C45079C38D2FEC10016AB86F103522521F987D542B85FA4599",
                Cipher    => +"5AAE990316BDDA525CD081863FAFDAA2E20E970C3C9E5CA71BA468315B2BAF8882CA",
                MAC       => +"CAF9FB2AC29A49C5CB3E898A"),
        --  /* ---------- KAT vector # 77 ------------- */
        --  { 192,  34,   6,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {6DC84CB78225323BE4813B9094B573911D77653C103CDC72}, /* key */
        --  {DE06CD58BC37F879B6D2FB58D0A0292A}, /* nonce */
        --  {FABA30091AB2}, /* aad */
        --  {7A39D7B1BF94148941C45079C38D2FEC10016AB86F103522521F987D542B85FA4599}, /* pText */
        --  {5AAE990316BDDA525CD081863FAFDAA2E20E970C3C9E5CA71BA468315B2BAF8882CA}, /* cText */
        --  {CAF9FB2AC29A49C5CB3E898A}  /* mac */
        078 => (Key       => +"493C54299913A7C6F9E952CABA3CD53C",
                Nonce     => +"624B264FF4C0139654EE0933F2FA5E60",
                Aad       => +"54C19B0D684E3D",
                Plaintext => +"B577A21A3E4FF7EF14C41F6F0A9009F871D2A2022E86F4023D20AD5965132B9476",
                Cipher    => +"68B7D38707C28E5915CFA31B113EA98ACC9D25B715A95250E979783A07693F8208",
                MAC       => +"96A217A953E98283EFFB"),
        --  /* ---------- KAT vector # 78 ------------- */
        --  { 128,  33,   7,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {493C54299913A7C6F9E952CABA3CD53C}, /* key */
        --  {624B264FF4C0139654EE0933F2FA5E60}, /* nonce */
        --  {54C19B0D684E3D}, /* aad */
        --  {B577A21A3E4FF7EF14C41F6F0A9009F871D2A2022E86F4023D20AD5965132B9476}, /* pText */
        --  {68B7D38707C28E5915CFA31B113EA98ACC9D25B715A95250E979783A07693F8208}, /* cText */
        --  {96A217A953E98283EFFB}  /* mac */
        079 => (Key       => +"E231245E4A1883F13F6C1DC954BEB5E74E60AA458469279A97D4422CF90BF0B0",
                Nonce     => +"903DAD51BDBE3313BB15FA5D01E231CA",
                Aad       => +"6B782F64FEEDBF7A7C0554159BF80B21EE846580BDB5E6DE6B77332427A48F",
                Plaintext => +"6044939024CA517C3494B0519614703900B4C03875952352E227FCB1D7625984",
                Cipher    => +"138ECFF4C514DE407458F79F36635D024B463F23C5F7B0DB1CFD4DA0E156F164",
                MAC       => +"8E9D5D9BFB5E4ABFB974B206"),
        --  /* ---------- KAT vector # 79 ------------- */
        --  { 256,  32,  31,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {E231245E4A1883F13F6C1DC954BEB5E74E60AA458469279A97D4422CF90BF0B0}, /* key */
        --  {903DAD51BDBE3313BB15FA5D01E231CA}, /* nonce */
        --  {6B782F64FEEDBF7A7C0554159BF80B21EE846580BDB5E6DE6B77332427A48F}, /* aad */
        --  {6044939024CA517C3494B0519614703900B4C03875952352E227FCB1D7625984}, /* pText */
        --  {138ECFF4C514DE407458F79F36635D024B463F23C5F7B0DB1CFD4DA0E156F164}, /* cText */
        --  {8E9D5D9BFB5E4ABFB974B206}  /* mac */
        080 => (Key       => +"10BDA5DF6435EFA69D1001E18727100BBD59522AF6C3A9BA0D3417AD7F67DE66",
                Nonce     => +"47A51B48E4328E8C6B7F4D768EC4F4CF",
                Aad       => +"101DD61A0A886A538329F10D795244F562579E90AC9231DB3DB1",
                Plaintext => +"5BBBC1D827F04B5203BAD2F4CBB6A36F5159D302E314154E3EF73207294615",
                Cipher    => +"E05206EA9A68692529A0AAD1BD68A603D1278430743528521CF06857EB9419",
                MAC       => +"A0AFAF4B129FB57D9C0D47EF0ACD"),
        --  /* ---------- KAT vector # 80 ------------- */
        --  { 256,  31,  26, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {10BDA5DF6435EFA69D1001E18727100BBD59522AF6C3A9BA0D3417AD7F67DE66}, /* key */
        --  {47A51B48E4328E8C6B7F4D768EC4F4CF}, /* nonce */
        --  {101DD61A0A886A538329F10D795244F562579E90AC9231DB3DB1}, /* aad */
        --  {5BBBC1D827F04B5203BAD2F4CBB6A36F5159D302E314154E3EF73207294615}, /* pText */
        --  {E05206EA9A68692529A0AAD1BD68A603D1278430743528521CF06857EB9419}, /* cText */
        --  {A0AFAF4B129FB57D9C0D47EF0ACD}  /* mac */
        081 => (Key       => +"8C5AC049D3C9961D0C625C51838DF35B1AFE2AF177B0E73798F7DA2209CAAB7B",
                Nonce     => +"0293BC1C7278BBD34929CE3BCE25027F",
                Aad       => +"38BC9486BF1F314B5880D7A002F24336F2D80BB0680347C2F2FE25BAA708238F",
                Plaintext => +"0E9E8E153C4BECE751FE130B73B4C2647C81699529BEC4096923EBB5F72D",
                Cipher    => +"A898E0D69D6FF8D3044AA514913A7D47EF3430F37CC4C6243AE9A19C7EDB",
                MAC       => +"43DFAD9919B5ABDA2A40"),
        --  /* ---------- KAT vector # 81 ------------- */
        --  { 256,  30,  32,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {8C5AC049D3C9961D0C625C51838DF35B1AFE2AF177B0E73798F7DA2209CAAB7B}, /* key */
        --  {0293BC1C7278BBD34929CE3BCE25027F}, /* nonce */
        --  {38BC9486BF1F314B5880D7A002F24336F2D80BB0680347C2F2FE25BAA708238F}, /* aad */
        --  {0E9E8E153C4BECE751FE130B73B4C2647C81699529BEC4096923EBB5F72D}, /* pText */
        --  {A898E0D69D6FF8D3044AA514913A7D47EF3430F37CC4C6243AE9A19C7EDB}, /* cText */
        --  {43DFAD9919B5ABDA2A40}  /* mac */
        082 => (Key       => +"4E6B48DB9B2202A93E670634055DE69639D6C46F37443944",
                Nonce     => +"DE7F3180D9213B4CB16FA83E150CC8F0",
                Aad       => +"A8C0B6489DBD4A21B561230C22E31AE392A3FCECF8CEDBDB8066BB872A7D43",
                Plaintext => +"0A286A1DF45F5513E554D348AFC375EDC7019577C9076627D39F8652E6",
                Cipher    => +"15205C84F46F5031EFF7B2884283C5678ACBAE4A71C8104884CCED62B0",
                MAC       => +"80CA6016544A9EFB4E15369F"),
        --  /* ---------- KAT vector # 82 ------------- */
        --  { 192,  29,  31,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {4E6B48DB9B2202A93E670634055DE69639D6C46F37443944}, /* key */
        --  {DE7F3180D9213B4CB16FA83E150CC8F0}, /* nonce */
        --  {A8C0B6489DBD4A21B561230C22E31AE392A3FCECF8CEDBDB8066BB872A7D43}, /* aad */
        --  {0A286A1DF45F5513E554D348AFC375EDC7019577C9076627D39F8652E6}, /* pText */
        --  {15205C84F46F5031EFF7B2884283C5678ACBAE4A71C8104884CCED62B0}, /* cText */
        --  {80CA6016544A9EFB4E15369F}  /* mac */
        083 => (Key       => +"9A52D8D407FF4064A6B1682CD4D49A53D90E42EB54D33790",
                Nonce     => +"B0FBFF0B922D341616C0572CA03D4A78",
                Aad       => +"6F4ADADA9BB66C685821C078800809DBAB3D10C6443CC0D821816031C0B412",
                Plaintext => +"86BB609B54792C4431EB60C470BD78B549496859B068A332ADAD994E",
                Cipher    => +"9D03DDB592E571C48C73DFDD1FAC400DE7E6A889DBC6647D3B92937D",
                MAC       => +"3CDABD4453DF07D86FFE15FB"),
        --  /* ---------- KAT vector # 83 ------------- */
        --  { 192,  28,  31,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {9A52D8D407FF4064A6B1682CD4D49A53D90E42EB54D33790}, /* key */
        --  {B0FBFF0B922D341616C0572CA03D4A78}, /* nonce */
        --  {6F4ADADA9BB66C685821C078800809DBAB3D10C6443CC0D821816031C0B412}, /* aad */
        --  {86BB609B54792C4431EB60C470BD78B549496859B068A332ADAD994E}, /* pText */
        --  {9D03DDB592E571C48C73DFDD1FAC400DE7E6A889DBC6647D3B92937D}, /* cText */
        --  {3CDABD4453DF07D86FFE15FB}  /* mac */
        084 => (Key       => +"CB45DB9431C891D2BC8211C5441182F94A59E5355F840DC6",
                Nonce     => +"7F0C2C14E10F8FE3DD00A5EFAF0C8FBA",
                Aad       => +"C76900F0C3C08F6944647329E948ECFA",
                Plaintext => +"78C423A91BE0F6BF0A82D9DD210A78A144A9FEA32F2372470593F9",
                Cipher    => +"37A7CAD79D8686184A76555364885F31600D1083AEAE8DD24C6B1C",
                MAC       => +"A82DB1FD0F7FAC4F1FBCD5104E931347"),
        --  /* ---------- KAT vector # 84 ------------- */
        --  { 192,  27,  16, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {CB45DB9431C891D2BC8211C5441182F94A59E5355F840DC6}, /* key */
        --  {7F0C2C14E10F8FE3DD00A5EFAF0C8FBA}, /* nonce */
        --  {C76900F0C3C08F6944647329E948ECFA}, /* aad */
        --  {78C423A91BE0F6BF0A82D9DD210A78A144A9FEA32F2372470593F9}, /* pText */
        --  {37A7CAD79D8686184A76555364885F31600D1083AEAE8DD24C6B1C}, /* cText */
        --  {A82DB1FD0F7FAC4F1FBCD5104E931347}  /* mac */
        085 => (Key       => +"96EEAD0DE12BBE3EEEDDBD7955B1BD1CE98DE54553F33355",
                Nonce     => +"889AE25FA2FD5ACC7797C631A3CB2AEF",
                Aad       => +"719F8DE5",
                Plaintext => +"318BEE3EAA6CDF91A070965CF854AB189AF7E38DBC1BFDBDE009",
                Cipher    => +"23C7C39E6A6FC9337BB113E4267F885EC07BDE46014A35438231",
                MAC       => +"E92F0A0F5B0C551F37E1"),
        --  /* ---------- KAT vector # 85 ------------- */
        --  { 192,  26,   4,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {96EEAD0DE12BBE3EEEDDBD7955B1BD1CE98DE54553F33355}, /* key */
        --  {889AE25FA2FD5ACC7797C631A3CB2AEF}, /* nonce */
        --  {719F8DE5}, /* aad */
        --  {318BEE3EAA6CDF91A070965CF854AB189AF7E38DBC1BFDBDE009}, /* pText */
        --  {23C7C39E6A6FC9337BB113E4267F885EC07BDE46014A35438231}, /* cText */
        --  {E92F0A0F5B0C551F37E1}  /* mac */
        086 => (Key       => +"B74E79DF9D816D684C798C2CEA6B23FE6CD9F1BA00F3BF25",
                Nonce     => +"D5DE1776D6DF29026C1A9D212FA850E7",
                Aad       => +"E4939701C18D14F67F064D292CB5BF1A",
                Plaintext => +"A8CB8D12228E08B495E427BEF7374D5D20DC7B3B35DB66FEEE",
                Cipher    => +"956FE0DDCFCD1303D48ACB5CE1E1E6674AFBFB3D2992385698",
                MAC       => +"5395B7C8ECCB9FCAA56C88C39451"),
        --  /* ---------- KAT vector # 86 ------------- */
        --  { 192,  25,  16, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {B74E79DF9D816D684C798C2CEA6B23FE6CD9F1BA00F3BF25}, /* key */
        --  {D5DE1776D6DF29026C1A9D212FA850E7}, /* nonce */
        --  {E4939701C18D14F67F064D292CB5BF1A}, /* aad */
        --  {A8CB8D12228E08B495E427BEF7374D5D20DC7B3B35DB66FEEE}, /* pText */
        --  {956FE0DDCFCD1303D48ACB5CE1E1E6674AFBFB3D2992385698}, /* cText */
        --  {5395B7C8ECCB9FCAA56C88C39451}  /* mac */
        087 => (Key       => +"C008B464AE078D263DBC2593F33EFD682F0D6098B11C5C82",
                Nonce     => +"B53E131406CED6EBDFACB81F5ACB5F7C",
                Aad       => +"5AFD",
                Plaintext => +"EBB1094CD52B4C2231D59CE34837E29A98925384854E788D",
                Cipher    => +"AE93C519E9B5225920CB6A2B9036831460B0FAF84BAF4991",
                MAC       => +"149F5132BABEDE84CD96BF79"),
        --  /* ---------- KAT vector # 87 ------------- */
        --  { 192,  24,   2,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {C008B464AE078D263DBC2593F33EFD682F0D6098B11C5C82}, /* key */
        --  {B53E131406CED6EBDFACB81F5ACB5F7C}, /* nonce */
        --  {5AFD}, /* aad */
        --  {EBB1094CD52B4C2231D59CE34837E29A98925384854E788D}, /* pText */
        --  {AE93C519E9B5225920CB6A2B9036831460B0FAF84BAF4991}, /* cText */
        --  {149F5132BABEDE84CD96BF79}  /* mac */
        088 => (Key       => +"4DE43E0077EDACA0D68FEF8EAF587BC3B7A90EE2208770E2",
                Nonce     => +"0C60E36ED3B7A97AB6B8C29054A709D0",
                Aad       => +"B1DBAE4D2736E9BEAEEBB39F24CD5B44CFE643FAB1D6",
                Plaintext => +"6A3A0A3695B6B4CCCE9256C61FAD82602D63D19A88880A",
                Cipher    => +"F4D43FA57EE0D4078F3317FE3DADF73B60C7307C0ED20D",
                MAC       => +"43322D7F2245BF1CCAE147A02ADE"),
        --  /* ---------- KAT vector # 88 ------------- */
        --  { 192,  23,  22, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {4DE43E0077EDACA0D68FEF8EAF587BC3B7A90EE2208770E2}, /* key */
        --  {0C60E36ED3B7A97AB6B8C29054A709D0}, /* nonce */
        --  {B1DBAE4D2736E9BEAEEBB39F24CD5B44CFE643FAB1D6}, /* aad */
        --  {6A3A0A3695B6B4CCCE9256C61FAD82602D63D19A88880A}, /* pText */
        --  {F4D43FA57EE0D4078F3317FE3DADF73B60C7307C0ED20D}, /* cText */
        --  {43322D7F2245BF1CCAE147A02ADE}  /* mac */
        089 => (Key       => +"4A0B481C102F897B7B12DE6884869C7F",
                Nonce     => +"B6163F9C87D61D02E76A49AE9CA25CD8",
                Aad       => +"AA0DAACB1058AB231B3E1C64967D0BEA0EAEB1F362A8F4DDC3AB2F21",
                Plaintext => +"9B82880AB15863770A7AC32D9C8BCF62EDFE65C4FAD1",
                Cipher    => +"C35C66E06BB57E5A8AF89C9ACB6B77E2AB988CAA8651",
                MAC       => +"5087D4143F8BAA7DD228AB487EECB8E6"),
        --  /* ---------- KAT vector # 89 ------------- */
        --  { 128,  22,  28, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {4A0B481C102F897B7B12DE6884869C7F}, /* key */
        --  {B6163F9C87D61D02E76A49AE9CA25CD8}, /* nonce */
        --  {AA0DAACB1058AB231B3E1C64967D0BEA0EAEB1F362A8F4DDC3AB2F21}, /* aad */
        --  {9B82880AB15863770A7AC32D9C8BCF62EDFE65C4FAD1}, /* pText */
        --  {C35C66E06BB57E5A8AF89C9ACB6B77E2AB988CAA8651}, /* cText */
        --  {5087D4143F8BAA7DD228AB487EECB8E6}  /* mac */
        090 => (Key       => +"E232500C744DB7DC0B7714914ADD64E8",
                Nonce     => +"ACF76F2DF707863EA93984F5E0845D09",
                Aad       => +"281F54E30C7646F3DF22F9EE44D0E2FE5C",
                Plaintext => +"DD2405532A23DB81D81FAA0BD90FB3E27E93AED6E2",
                Cipher    => +"BA592911830DD10B80F825211D2CE8E58F03E506CB",
                MAC       => +"1431CE688473357AB23087B56B44"),
        --  /* ---------- KAT vector # 90 ------------- */
        --  { 128,  21,  17, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {E232500C744DB7DC0B7714914ADD64E8}, /* key */
        --  {ACF76F2DF707863EA93984F5E0845D09}, /* nonce */
        --  {281F54E30C7646F3DF22F9EE44D0E2FE5C}, /* aad */
        --  {DD2405532A23DB81D81FAA0BD90FB3E27E93AED6E2}, /* pText */
        --  {BA592911830DD10B80F825211D2CE8E58F03E506CB}, /* cText */
        --  {1431CE688473357AB23087B56B44}  /* mac */
        091 => (Key       => +"8704382288A44C443CF1F1F69BED8794",
                Nonce     => +"D8CE4197B2A3320C5549D03BD0167439",
                Aad       => +"5830392C2CC181C2C4676F9409",
                Plaintext => +"572D7DB9F26B4CC4A4D6FB2FF7C0F5EAE8BB2B56",
                Cipher    => +"49D8AC7D0F109BCF4F38AD39F150EB8B79252140",
                MAC       => +"E920DCACBCD8820A3216B0741242"),
        --  /* ---------- KAT vector # 91 ------------- */
        --  { 128,  20,  13, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {8704382288A44C443CF1F1F69BED8794}, /* key */
        --  {D8CE4197B2A3320C5549D03BD0167439}, /* nonce */
        --  {5830392C2CC181C2C4676F9409}, /* aad */
        --  {572D7DB9F26B4CC4A4D6FB2FF7C0F5EAE8BB2B56}, /* pText */
        --  {49D8AC7D0F109BCF4F38AD39F150EB8B79252140}, /* cText */
        --  {E920DCACBCD8820A3216B0741242}  /* mac */
        092 => (Key       => +"DE0F54DFA5E7B0A8C72F0D7F426894BBED2E0427E120549DE4352578C48925C5",
                Nonce     => +"AD7853126C9AD81FD63AEBD488E4DF25",
                Aad       => +"598A0C68B1BAEDE6BAC879E6B3E4ED23F7F242C5ECFE0F421960FCE194BE8241C227ECAB",
                Plaintext => +"63E84C5AA2EB906E62259F52B412053139634E",
                Cipher    => +"47DAB06C87CDEC0C0CD1D2964C36516056781F",
                MAC       => +"A4EB6C73F503FAF111DA6718"),
        --  /* ---------- KAT vector # 92 ------------- */
        --  { 256,  19,  36,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {DE0F54DFA5E7B0A8C72F0D7F426894BBED2E0427E120549DE4352578C48925C5}, /* key */
        --  {AD7853126C9AD81FD63AEBD488E4DF25}, /* nonce */
        --  {598A0C68B1BAEDE6BAC879E6B3E4ED23F7F242C5ECFE0F421960FCE194BE8241C227ECAB}, /* aad */
        --  {63E84C5AA2EB906E62259F52B412053139634E}, /* pText */
        --  {47DAB06C87CDEC0C0CD1D2964C36516056781F}, /* cText */
        --  {A4EB6C73F503FAF111DA6718}  /* mac */
        093 => (Key       => +"59781BD0B43CCAD97AD200196C885E086A0E3F83BF8D78DE32AC5E1B63ED751E",
                Nonce     => +"CC68F19671A2CDFB9AAAA1629062EFAC",
                Aad       => +"4B5F375E4DD6E6B0FA9362AD90",
                Plaintext => +"84C457F44B3C7E3BC9DDA127E667ABFA2A10",
                Cipher    => +"8EEF3D0D82880C58E3B15FFCC8D2D3873763",
                MAC       => +"37A21C9C38F279827BD0"),
        --  /* ---------- KAT vector # 93 ------------- */
        --  { 256,  18,  13,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {59781BD0B43CCAD97AD200196C885E086A0E3F83BF8D78DE32AC5E1B63ED751E}, /* key */
        --  {CC68F19671A2CDFB9AAAA1629062EFAC}, /* nonce */
        --  {4B5F375E4DD6E6B0FA9362AD90}, /* aad */
        --  {84C457F44B3C7E3BC9DDA127E667ABFA2A10}, /* pText */
        --  {8EEF3D0D82880C58E3B15FFCC8D2D3873763}, /* cText */
        --  {37A21C9C38F279827BD0}  /* mac */
        094 => (Key       => +"73B7F64BCC3388C59CE35C6156CB7C3F591E009A751D8336",
                Nonce     => +"359A58A47AEA89BA2D11A46EABD65AD0",
                Aad       => +"E78E8314163143139C7F513AAA6C52",
                Plaintext => +"3297BFA0ACC9992D09EC3879591A86C959",
                Cipher    => +"C4A4A642C99BD5933BF858DE1299135C82",
                MAC       => +"DA94D476B9FEF72126492377333116D9"),
        --  /* ---------- KAT vector # 94 ------------- */
        --  { 192,  17,  15, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {73B7F64BCC3388C59CE35C6156CB7C3F591E009A751D8336}, /* key */
        --  {359A58A47AEA89BA2D11A46EABD65AD0}, /* nonce */
        --  {E78E8314163143139C7F513AAA6C52}, /* aad */
        --  {3297BFA0ACC9992D09EC3879591A86C959}, /* pText */
        --  {C4A4A642C99BD5933BF858DE1299135C82}, /* cText */
        --  {DA94D476B9FEF72126492377333116D9}  /* mac */
        095 => (Key       => +"4777F2E65291120876A3363283797BE084B313B4320FABC8FE8DEF51D329A912",
                Nonce     => +"2F1B91DF52C1EE9CF9EB1A2D9FFCD563",
                Aad       => +"380547BB6748F4",
                Plaintext => +"BDA7ED5B583620681F1E9745B1D111A1",
                Cipher    => +"047633A43F57C12BFA3979E9A55D2F7E",
                MAC       => +"81A64CA44BB116B3F81D73DD"),
        --  /* ---------- KAT vector # 95 ------------- */
        --  { 256,  16,   7,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {4777F2E65291120876A3363283797BE084B313B4320FABC8FE8DEF51D329A912}, /* key */
        --  {2F1B91DF52C1EE9CF9EB1A2D9FFCD563}, /* nonce */
        --  {380547BB6748F4}, /* aad */
        --  {BDA7ED5B583620681F1E9745B1D111A1}, /* pText */
        --  {047633A43F57C12BFA3979E9A55D2F7E}, /* cText */
        --  {81A64CA44BB116B3F81D73DD}  /* mac */
        096 => (Key       => +"2DD007C77AB2DC9F077B91C4E520EDCCFD716367D1588B796ABDCC8B3A98F162",
                Nonce     => +"AB63C887817C5FE47255DB22B745A747",
                Aad       => +"8B1FDDDAD191EDEB84F6BA8962A178CD2D520D963CBA3F284E6FD02A753B6CBC644D44BC",
                Plaintext => +"17748D50E01BD328F163603E1CFEDA",
                Cipher    => +"CCCDBFC59CE3E81E2ACF8239A7E2D8",
                MAC       => +"8E8256021773CE60"),
        --  /* ---------- KAT vector # 96 ------------- */
        --  { 256,  15,  36,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {2DD007C77AB2DC9F077B91C4E520EDCCFD716367D1588B796ABDCC8B3A98F162}, /* key */
        --  {AB63C887817C5FE47255DB22B745A747}, /* nonce */
        --  {8B1FDDDAD191EDEB84F6BA8962A178CD2D520D963CBA3F284E6FD02A753B6CBC644D44BC}, /* aad */
        --  {17748D50E01BD328F163603E1CFEDA}, /* pText */
        --  {CCCDBFC59CE3E81E2ACF8239A7E2D8}, /* cText */
        --  {8E8256021773CE60}  /* mac */
        097 => (Key       => +"6E4ABB68DE51E2967A02D1B26486849E",
                Nonce     => +"D299367BB38E7BDA3983962C5BD69808",
                Aad       => +"083517DA92C9D402BE5DEF4CA0",
                Plaintext => +"46DEC6B2AC63EF533C4DCFAC420E",
                Cipher    => +"AEE95477E6E2A1C45D5106F0CCFA",
                MAC       => +"421D63B4AE3B5C22AF0F"),
        --  /* ---------- KAT vector # 97 ------------- */
        --  { 128,  14,  13,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {6E4ABB68DE51E2967A02D1B26486849E}, /* key */
        --  {D299367BB38E7BDA3983962C5BD69808}, /* nonce */
        --  {083517DA92C9D402BE5DEF4CA0}, /* aad */
        --  {46DEC6B2AC63EF533C4DCFAC420E}, /* pText */
        --  {AEE95477E6E2A1C45D5106F0CCFA}, /* cText */
        --  {421D63B4AE3B5C22AF0F}  /* mac */
        098 => (Key       => +"C1BEACD96B70FC71754F6050BE195BBA09FFE8ECACBFF14F1FF0AA13C6AFF233",
                Nonce     => +"6722AA28ACC2BAB554D0B035D7A5625E",
                Aad       => +"483A32E47B50D34A1C005D1866B3758483F487B1E7",
                Plaintext => +"8073DC3555F9B32BD62402E368",
                Cipher    => +"345A18EF7E2FE9149952461FC2",
                MAC       => +"3A9EEC20704B1A07093F9F8453C6"),
        --  /* ---------- KAT vector # 98 ------------- */
        --  { 256,  13,  21, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {C1BEACD96B70FC71754F6050BE195BBA09FFE8ECACBFF14F1FF0AA13C6AFF233}, /* key */
        --  {6722AA28ACC2BAB554D0B035D7A5625E}, /* nonce */
        --  {483A32E47B50D34A1C005D1866B3758483F487B1E7}, /* aad */
        --  {8073DC3555F9B32BD62402E368}, /* pText */
        --  {345A18EF7E2FE9149952461FC2}, /* cText */
        --  {3A9EEC20704B1A07093F9F8453C6}  /* mac */
        099 => (Key       => +"13DEDB0E5E42F6F47A495C4B1ACF00E6",
                Nonce     => +"98E09E79D204F9F4C605205A8B507374",
                Aad       => +"3EF9FD71E67FA705E67897BBCD1DD1F17A2C16657F2FAE9FFB32C4D517F51866497507",
                Plaintext => +"46A3EAF84B708750A0CA085A",
                Cipher    => +"D3BFEB378F35EDD3D4C97DDB",
                MAC       => +"18509CB74673005B"),
        --  /* ---------- KAT vector # 99 ------------- */
        --  { 128,  12,  35,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {13DEDB0E5E42F6F47A495C4B1ACF00E6}, /* key */
        --  {98E09E79D204F9F4C605205A8B507374}, /* nonce */
        --  {3EF9FD71E67FA705E67897BBCD1DD1F17A2C16657F2FAE9FFB32C4D517F51866497507}, /* aad */
        --  {46A3EAF84B708750A0CA085A}, /* pText */
        --  {D3BFEB378F35EDD3D4C97DDB}, /* cText */
        --  {18509CB74673005B}  /* mac */
        100 => (Key       => +"F988B24ABF5F7FA5C430AB2C89399DA2A8337CEDA38A0B2D",
                Nonce     => +"513B665A6955E67E732DE1745131A740",
                Aad       => +"7FE8510B5C6003",
                Plaintext => +"10AA0DA40F053847960282",
                Cipher    => +"87A51CABF6D69E1C3A1E2A",
                MAC       => +"14A961B4653B42EFE4EC9B97E9B2"),
        --  /* ---------- KAT vector #100 ------------- */
        --  { 192,  11,   7, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {F988B24ABF5F7FA5C430AB2C89399DA2A8337CEDA38A0B2D}, /* key */
        --  {513B665A6955E67E732DE1745131A740}, /* nonce */
        --  {7FE8510B5C6003}, /* aad */
        --  {10AA0DA40F053847960282}, /* pText */
        --  {87A51CABF6D69E1C3A1E2A}, /* cText */
        --  {14A961B4653B42EFE4EC9B97E9B2}  /* mac */
        101 => (Key       => +"1909149433E377582BD3F7F12915637C9FA8FEF6C410B933",
                Nonce     => +"A293E2769F8F63123137E5F4637E7772",
                Aad       => +"C5B51FBF9BD05B99FFA80D",
                Plaintext => +"3F8A5F9D0CBCE5B077BF",
                Cipher    => +"509E1E8EC4C76FEB4098",
                MAC       => +"6114F6B79BB098E8A98385CF4D829B59"),
        --  /* ---------- KAT vector #101 ------------- */
        --  { 192,  10,  11, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {1909149433E377582BD3F7F12915637C9FA8FEF6C410B933}, /* key */
        --  {A293E2769F8F63123137E5F4637E7772}, /* nonce */
        --  {C5B51FBF9BD05B99FFA80D}, /* aad */
        --  {3F8A5F9D0CBCE5B077BF}, /* pText */
        --  {509E1E8EC4C76FEB4098}, /* cText */
        --  {6114F6B79BB098E8A98385CF4D829B59}  /* mac */
        102 => (Key       => +"126332E989D53F6F6769C775E7113152FFCA100DA2C82EC0",
                Nonce     => +"9696100F0FD06682A6DD93A069909AC7",
                Aad       => +"10A05AB98E05CD4568E3E028523ECD3EC11E2930",
                Plaintext => +"B504A1F9BD67CBB8DD",
                Cipher    => +"7256B20AAAFB16BA38",
                MAC       => +"118F716E43D00BDAE9AFDC0F"),
        --  /* ---------- KAT vector #102 ------------- */
        --  { 192,   9,  20,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {126332E989D53F6F6769C775E7113152FFCA100DA2C82EC0}, /* key */
        --  {9696100F0FD06682A6DD93A069909AC7}, /* nonce */
        --  {10A05AB98E05CD4568E3E028523ECD3EC11E2930}, /* aad */
        --  {B504A1F9BD67CBB8DD}, /* pText */
        --  {7256B20AAAFB16BA38}, /* cText */
        --  {118F716E43D00BDAE9AFDC0F}  /* mac */
        103 => (Key       => +"DD75BEB51B53EEED08AC80D3E0FA704B",
                Nonce     => +"FCDDF1D4CF55B16F420E13A4B52053D3",
                Aad       => +"E35A88C52F6FA408",
                Plaintext => +"EB0B39E76A5F8CBA",
                Cipher    => +"85B7A130166ACC6B",
                MAC       => +"29F76C513AFCDBC6E7E5C6B6A6420A1B"),
        --  /* ---------- KAT vector #103 ------------- */
        --  { 128,   8,   8, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {DD75BEB51B53EEED08AC80D3E0FA704B}, /* key */
        --  {FCDDF1D4CF55B16F420E13A4B52053D3}, /* nonce */
        --  {E35A88C52F6FA408}, /* aad */
        --  {EB0B39E76A5F8CBA}, /* pText */
        --  {85B7A130166ACC6B}, /* cText */
        --  {29F76C513AFCDBC6E7E5C6B6A6420A1B}  /* mac */
        104 => (Key       => +"F270DE3961E54188BB0D49DED2A5E82E816C15C84C107E05",
                Nonce     => +"90A95F01B5D4BC13675961360334A1A7",
                Aad       => +"94D059AE255C784C64BAD206A42BAD7707B99AFF1A",
                Plaintext => +"8E209A2039A17E",
                Cipher    => +"7A4579A9696811",
                MAC       => +"47990B62BED3C83EA2B6"),
        --  /* ---------- KAT vector #104 ------------- */
        --  { 192,   7,  21,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {F270DE3961E54188BB0D49DED2A5E82E816C15C84C107E05}, /* key */
        --  {90A95F01B5D4BC13675961360334A1A7}, /* nonce */
        --  {94D059AE255C784C64BAD206A42BAD7707B99AFF1A}, /* aad */
        --  {8E209A2039A17E}, /* pText */
        --  {7A4579A9696811}, /* cText */
        --  {47990B62BED3C83EA2B6}  /* mac */
        105 => (Key       => +"54AF8506A4F1A65B5339826DA8E04972",
                Nonce     => +"63A59E8A9264B83D396EAC78C7C45D86",
                Aad       => +"A896CE9C5F82492782C04A4A49C9149E8EE0CB452E2F4D68451B5355D24D09",
                Plaintext => +"543E6311A84F",
                Cipher    => +"81CF469366C9",
                MAC       => +"2F39D88ED3833CFD68414C79B36E8BC6"),
        --  /* ---------- KAT vector #105 ------------- */
        --  { 128,   6,  31, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {54AF8506A4F1A65B5339826DA8E04972}, /* key */
        --  {63A59E8A9264B83D396EAC78C7C45D86}, /* nonce */
        --  {A896CE9C5F82492782C04A4A49C9149E8EE0CB452E2F4D68451B5355D24D09}, /* aad */
        --  {543E6311A84F}, /* pText */
        --  {81CF469366C9}, /* cText */
        --  {2F39D88ED3833CFD68414C79B36E8BC6}  /* mac */
        106 => (Key       => +"1627CEFA4F74C4957CF50659586782E5B5FFF686E81127DE",
                Nonce     => +"D3D66C3167197246095C24FCFA7B692F",
                Aad       => +"87DB6A31BCA3D530FD3FB75C904764F031ED2E0DE783612314F9655786438638",
                Plaintext => +"1B56B3F6A6",
                Cipher    => +"E37D4BE7FF",
                MAC       => +"1F311997FA816EA6203DE44F"),
        --  /* ---------- KAT vector #106 ------------- */
        --  { 192,   5,  32,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {1627CEFA4F74C4957CF50659586782E5B5FFF686E81127DE}, /* key */
        --  {D3D66C3167197246095C24FCFA7B692F}, /* nonce */
        --  {87DB6A31BCA3D530FD3FB75C904764F031ED2E0DE783612314F9655786438638}, /* aad */
        --  {1B56B3F6A6}, /* pText */
        --  {E37D4BE7FF}, /* cText */
        --  {1F311997FA816EA6203DE44F}  /* mac */
        107 => (Key       => +"FD9E8E6763E8100B1FE471B3776D3D25C2CC417E19948A30",
                Nonce     => +"8C402951A2D5DEEDA95154D6B31A692D",
                Aad       => +"C0",
                Plaintext => +"CF4DE662",
                Cipher    => +"50DD13BB",
                MAC       => +"1C17E4FCFEA262A516CC8EA6"),
        --  /* ---------- KAT vector #107 ------------- */
        --  { 192,   4,   1,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {FD9E8E6763E8100B1FE471B3776D3D25C2CC417E19948A30}, /* key */
        --  {8C402951A2D5DEEDA95154D6B31A692D}, /* nonce */
        --  {C0}, /* aad */
        --  {CF4DE662}, /* pText */
        --  {50DD13BB}, /* cText */
        --  {1C17E4FCFEA262A516CC8EA6}  /* mac */
        108 => (Key       => +"A1740A3CC144EB5FFBC281785AEB6C973611B31D11001562",
                Nonce     => +"2E92AEDEC563738601C656AEF5D1A900",
                Aad       => +"15B231324B76078E2F5B9D55A1BDCB05",
                Plaintext => +"90984F",
                Cipher    => +"6E847A",
                MAC       => +"2E9656AA7FBF7EBB04FA47BE8234"),
        --  /* ---------- KAT vector #108 ------------- */
        --  { 192,   3,  16, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {A1740A3CC144EB5FFBC281785AEB6C973611B31D11001562}, /* key */
        --  {2E92AEDEC563738601C656AEF5D1A900}, /* nonce */
        --  {15B231324B76078E2F5B9D55A1BDCB05}, /* aad */
        --  {90984F}, /* pText */
        --  {6E847A}, /* cText */
        --  {2E9656AA7FBF7EBB04FA47BE8234}  /* mac */
        109 => (Key       => +"FD3F9D2709378BA6C96A6A4D9E98BA4390DA9F8CC4079474C2A5D56D5ABF4301",
                Nonce     => +"582ED20AA730080285B13CE8482AB3CC",
                Aad       => +"F9228DB1D5523C2702B6BAE3FDC1C7FC027D56C5226F922622801C118C17",
                Plaintext => +"B77D",
                Cipher    => +"C538",
                MAC       => +"2FFC6A093B69427AFC61F27D921FF0D4"),
        --  /* ---------- KAT vector #109 ------------- */
        --  { 256,   2,  30, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {FD3F9D2709378BA6C96A6A4D9E98BA4390DA9F8CC4079474C2A5D56D5ABF4301}, /* key */
        --  {582ED20AA730080285B13CE8482AB3CC}, /* nonce */
        --  {F9228DB1D5523C2702B6BAE3FDC1C7FC027D56C5226F922622801C118C17}, /* aad */
        --  {B77D}, /* pText */
        --  {C538}, /* cText */
        --  {2FFC6A093B69427AFC61F27D921FF0D4}  /* mac */
        110 => (Key       => +"B494514B6A88CA866447A3AA95A89017DFF3F8A4600D7FA5",
                Nonce     => +"94387FE8C31F0D6792B4B35E180D18FC",
                Aad       => +"7BD8CDAC868EFEC2E30D667AD2EAB875A8743BBDDB4A19CCCCDA222552A724AA",
                Plaintext => +"E8",
                Cipher    => +"EF",
                MAC       => +"B07A5B9C5D655DC3"),
        --  /* ---------- KAT vector #110 ------------- */
        --  { 192,   1,  32,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {B494514B6A88CA866447A3AA95A89017DFF3F8A4600D7FA5}, /* key */
        --  {94387FE8C31F0D6792B4B35E180D18FC}, /* nonce */
        --  {7BD8CDAC868EFEC2E30D667AD2EAB875A8743BBDDB4A19CCCCDA222552A724AA}, /* aad */
        --  {E8}, /* pText */
        --  {EF}, /* cText */
        --  {B07A5B9C5D655DC3}  /* mac */
        111 => (Key       => +"6A0F8A3D2AB88008E49F14C095AB7E64",
                Nonce     => +"5898CB44974E43A9949E18D4AC68F682",
                Aad       => +"F03E964C531EC6179CF13833E4A396",
                Plaintext => +"",
                Cipher    => +"",
                MAC       => +"FB97D058527921B1754A58CB5991D5F3"),
        --  /* ---------- KAT vector #111 ------------- */
        --  { 128,   0,  15, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {6A0F8A3D2AB88008E49F14C095AB7E64}, /* key */
        --  {5898CB44974E43A9949E18D4AC68F682}, /* nonce */
        --  {F03E964C531EC6179CF13833E4A396}, /* aad */
        --  {}, /* pText */
        --  {}, /* cText */
        --  {FB97D058527921B1754A58CB5991D5F3}  /* mac */
        112 => (Key       => +"43E917FBB601237761CB4723A6CF9ECDB2CAEFFDE7BF6118FFF9A4A1637B4846",
                Nonce     => +"EC08BAA3A58E59BAA4D539B255855B64",
                Aad       => +"5891803373E7F4238FB3A6C50FDC1EFAD9BEAE1A8352EECFD875DF",
                Plaintext => +"5D14B4BFCDED158799041B37101B099EDD7BA05008C42078401F896C2708DEE456C49E2D",
                Cipher    => +"672B685D93EB656D7B626FBE623F616F5F9BF7DCACCB02B1CAFA3E8ACCFA1DE04F8C2763",
                MAC       => +"F374DC548AAF4C82BD0DB937"),
        --  /* ---------- KAT vector #112 ------------- */
        --  { 256,  36,  27,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {43E917FBB601237761CB4723A6CF9ECDB2CAEFFDE7BF6118FFF9A4A1637B4846}, /* key */
        --  {EC08BAA3A58E59BAA4D539B255855B64}, /* nonce */
        --  {5891803373E7F4238FB3A6C50FDC1EFAD9BEAE1A8352EECFD875DF}, /* aad */
        --  {5D14B4BFCDED158799041B37101B099EDD7BA05008C42078401F896C2708DEE456C49E2D}, /* pText */
        --  {672B685D93EB656D7B626FBE623F616F5F9BF7DCACCB02B1CAFA3E8ACCFA1DE04F8C2763}, /* cText */
        --  {F374DC548AAF4C82BD0DB937}  /* mac */
        113 => (Key       => +"4690D308E3936FEB2907ADD6D1A774F7BD7A12799A8F084B",
                Nonce     => +"0FE51FC9846DC2EEAA91DBD017F9A674",
                Aad       => +"9D23A99CCA97BB8E7EC2",
                Plaintext => +"5E83065E843B3073CE72CFC47992E577208984E7E759109ABCE19A988DF11F29193B89",
                Cipher    => +"40EA6094E532EB257DC9ADD7EB28FF6C54B2DD194D212A0DF8F8434254A19C70EEFB9A",
                MAC       => +"B49E9593B2A3B8D3EEE2A061"),
        --  /* ---------- KAT vector #113 ------------- */
        --  { 192,  35,  10,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {4690D308E3936FEB2907ADD6D1A774F7BD7A12799A8F084B}, /* key */
        --  {0FE51FC9846DC2EEAA91DBD017F9A674}, /* nonce */
        --  {9D23A99CCA97BB8E7EC2}, /* aad */
        --  {5E83065E843B3073CE72CFC47992E577208984E7E759109ABCE19A988DF11F29193B89}, /* pText */
        --  {40EA6094E532EB257DC9ADD7EB28FF6C54B2DD194D212A0DF8F8434254A19C70EEFB9A}, /* cText */
        --  {B49E9593B2A3B8D3EEE2A061}  /* mac */
        114 => (Key       => +"0F32752BC0C24F4364F7C94C2BAE87A5FA50E835702FEC2C",
                Nonce     => +"52F8830788ED3055DC2BE6B2910DD345",
                Aad       => +"5B53697418A3DD26559D439A4B5E83B5D3BA6B47656A6A18C18A6E7BA801F669096B",
                Plaintext => +"587F1426DC3951CB49DE28AFCC4FCBDAA5729085544C0ED2B22688D0F1DF80ED7D0E",
                Cipher    => +"F1693DCA7660EB2A5A0365366EF109684B9FD06E7A675AFF06D16E54B45AC81F8CB3",
                MAC       => +"CB40C5D4D69A335A"),
        --  /* ---------- KAT vector #114 ------------- */
        --  { 192,  34,  34,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {0F32752BC0C24F4364F7C94C2BAE87A5FA50E835702FEC2C}, /* key */
        --  {52F8830788ED3055DC2BE6B2910DD345}, /* nonce */
        --  {5B53697418A3DD26559D439A4B5E83B5D3BA6B47656A6A18C18A6E7BA801F669096B}, /* aad */
        --  {587F1426DC3951CB49DE28AFCC4FCBDAA5729085544C0ED2B22688D0F1DF80ED7D0E}, /* pText */
        --  {F1693DCA7660EB2A5A0365366EF109684B9FD06E7A675AFF06D16E54B45AC81F8CB3}, /* cText */
        --  {CB40C5D4D69A335A}  /* mac */
        115 => (Key       => +"411DFA057B68DDDFAD8EDF55080D8FC8938060078D7F21BB62A96BC05057C1A7",
                Nonce     => +"E85E3D454F57C5790D70A124C69583D6",
                Aad       => +"9776",
                Plaintext => +"79DC0C7AE7BFD9EEFE515EF2EF6A519DFCF8A412B5CC2CDA5F505691A5BF815C77",
                Cipher    => +"AA7FD27285BA1E6755E772404BB78585EAAD32F5AF726BD4BC8020EF2FEF2482EB",
                MAC       => +"50086813ACC81197B3A1DE5D"),
        --  /* ---------- KAT vector #115 ------------- */
        --  { 256,  33,   2,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {411DFA057B68DDDFAD8EDF55080D8FC8938060078D7F21BB62A96BC05057C1A7}, /* key */
        --  {E85E3D454F57C5790D70A124C69583D6}, /* nonce */
        --  {9776}, /* aad */
        --  {79DC0C7AE7BFD9EEFE515EF2EF6A519DFCF8A412B5CC2CDA5F505691A5BF815C77}, /* pText */
        --  {AA7FD27285BA1E6755E772404BB78585EAAD32F5AF726BD4BC8020EF2FEF2482EB}, /* cText */
        --  {50086813ACC81197B3A1DE5D}  /* mac */
        116 => (Key       => +"86A7FECF39C0CBB5A594BD7CFE262A70",
                Nonce     => +"B169AC11CABB3F44071EA191333D1909",
                Aad       => +"9BCEF50325136AA41FC4E1FDC0A7D29D82466E",
                Plaintext => +"9566F1028EC394551DFADCFF1EF8897CB6FD9DEEFC19D24590CEC38F7A58C734",
                Cipher    => +"61FC1C90EB594F79651B543D58FE96933D94E443E4B3CD5B33ABD3B8134AE938",
                MAC       => +"EA72434E1488FC1618525EF4982211B8"),
        --  /* ---------- KAT vector #116 ------------- */
        --  { 128,  32,  19, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {86A7FECF39C0CBB5A594BD7CFE262A70}, /* key */
        --  {B169AC11CABB3F44071EA191333D1909}, /* nonce */
        --  {9BCEF50325136AA41FC4E1FDC0A7D29D82466E}, /* aad */
        --  {9566F1028EC394551DFADCFF1EF8897CB6FD9DEEFC19D24590CEC38F7A58C734}, /* pText */
        --  {61FC1C90EB594F79651B543D58FE96933D94E443E4B3CD5B33ABD3B8134AE938}, /* cText */
        --  {EA72434E1488FC1618525EF4982211B8}  /* mac */
        117 => (Key       => +"45C1BBB76B4F71772EB040BE6F394C3A4D7448C9D3127885",
                Nonce     => +"7FFBBDDB26B9B569891D01E06F7316FD",
                Aad       => +"F632F9F5075CE1B4F54279DD9A768ADEBEEE01BF61C0",
                Plaintext => +"7759300C62202961F1228459F14916AF7B06EBE54F2369616BE3EB692A5F27",
                Cipher    => +"B6142267E194FC75643B8FF86F2936DC48949F611CED442C14F626E2507722",
                MAC       => +"36C10427ED060133"),
        --  /* ---------- KAT vector #117 ------------- */
        --  { 192,  31,  22,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {45C1BBB76B4F71772EB040BE6F394C3A4D7448C9D3127885}, /* key */
        --  {7FFBBDDB26B9B569891D01E06F7316FD}, /* nonce */
        --  {F632F9F5075CE1B4F54279DD9A768ADEBEEE01BF61C0}, /* aad */
        --  {7759300C62202961F1228459F14916AF7B06EBE54F2369616BE3EB692A5F27}, /* pText */
        --  {B6142267E194FC75643B8FF86F2936DC48949F611CED442C14F626E2507722}, /* cText */
        --  {36C10427ED060133}  /* mac */
        118 => (Key       => +"7FDC30B377BFEF0C0081E1DFAAE56D9DA4EFE804DEF381F0",
                Nonce     => +"4F6F91DC66A35E09B7FAFDA2DA1A25AF",
                Aad       => +"69E6D815CD4926189D62F2C7452A82B79DCF",
                Plaintext => +"BB7A47E22D1C7F90A7EF1F40E273C0187F0DEC3C600AB3AEE3873E5D0F5C",
                Cipher    => +"0A74B2AF918553BBF0A69905253C57030217AC7F3E434ED4BB88CBF29097",
                MAC       => +"FF49644295AF688ACDC7"),
        --  /* ---------- KAT vector #118 ------------- */
        --  { 192,  30,  18,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {7FDC30B377BFEF0C0081E1DFAAE56D9DA4EFE804DEF381F0}, /* key */
        --  {4F6F91DC66A35E09B7FAFDA2DA1A25AF}, /* nonce */
        --  {69E6D815CD4926189D62F2C7452A82B79DCF}, /* aad */
        --  {BB7A47E22D1C7F90A7EF1F40E273C0187F0DEC3C600AB3AEE3873E5D0F5C}, /* pText */
        --  {0A74B2AF918553BBF0A69905253C57030217AC7F3E434ED4BB88CBF29097}, /* cText */
        --  {FF49644295AF688ACDC7}  /* mac */
        119 => (Key       => +"A1249C94695F7F33828BF6744E33CB24",
                Nonce     => +"60318EA0AFC87D079E5F4430ECDC53EE",
                Aad       => +"3187DC896AD241F1",
                Plaintext => +"546AD1C611B88E390B5D28F56C671ACB6C3A479611C684E61FCB503F4D",
                Cipher    => +"7F0E39CDA5BBF4EE39F9EE837638AC8A0EE1FBA66054C76C2273F1574A",
                MAC       => +"F84E15D321ED6E6B6924E09880C6"),
        --  /* ---------- KAT vector #119 ------------- */
        --  { 128,  29,   8, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {A1249C94695F7F33828BF6744E33CB24}, /* key */
        --  {60318EA0AFC87D079E5F4430ECDC53EE}, /* nonce */
        --  {3187DC896AD241F1}, /* aad */
        --  {546AD1C611B88E390B5D28F56C671ACB6C3A479611C684E61FCB503F4D}, /* pText */
        --  {7F0E39CDA5BBF4EE39F9EE837638AC8A0EE1FBA66054C76C2273F1574A}, /* cText */
        --  {F84E15D321ED6E6B6924E09880C6}  /* mac */
        120 => (Key       => +"ABFA283FAE1203D265E68F99359D7B584F2ACC77BD90234BAEFAA396A98581C6",
                Nonce     => +"2B0CCC67B6FE56CEE7DBD77F8D0CF10B",
                Aad       => +"21B2A46F33D2877FEEE156C26297428BFCBDCF",
                Plaintext => +"D1B44F420611F4BCF916D3EF1D8E5DC71147BCC5AB0BA7281845A797",
                Cipher    => +"D0FC67B5363E2947BE5FBDDDBC74D04C88FB3A7219E34E1179F6169F",
                MAC       => +"5F812D88451B311C8B7DC318AE482AD6"),
        --  /* ---------- KAT vector #120 ------------- */
        --  { 256,  28,  19, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {ABFA283FAE1203D265E68F99359D7B584F2ACC77BD90234BAEFAA396A98581C6}, /* key */
        --  {2B0CCC67B6FE56CEE7DBD77F8D0CF10B}, /* nonce */
        --  {21B2A46F33D2877FEEE156C26297428BFCBDCF}, /* aad */
        --  {D1B44F420611F4BCF916D3EF1D8E5DC71147BCC5AB0BA7281845A797}, /* pText */
        --  {D0FC67B5363E2947BE5FBDDDBC74D04C88FB3A7219E34E1179F6169F}, /* cText */
        --  {5F812D88451B311C8B7DC318AE482AD6}  /* mac */
        121 => (Key       => +"8ACE7522A4D25490E60A1C44C926B4F5AFC8A32F8760F468D180A93ADB2142D9",
                Nonce     => +"40607D4DE54223C7B9182D64613126B8",
                Aad       => +"1F394A1A",
                Plaintext => +"614FCC88EDE9048FD5EDA914CCD52493366EB2767FF229607CF26C",
                Cipher    => +"F2C9F76813E2D14B6AD629D9862AF278432665921A2AAE76D0A013",
                MAC       => +"46EA0E66B4A07A16F4D70E4997AC"),
        --  /* ---------- KAT vector #121 ------------- */
        --  { 256,  27,   4, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {8ACE7522A4D25490E60A1C44C926B4F5AFC8A32F8760F468D180A93ADB2142D9}, /* key */
        --  {40607D4DE54223C7B9182D64613126B8}, /* nonce */
        --  {1F394A1A}, /* aad */
        --  {614FCC88EDE9048FD5EDA914CCD52493366EB2767FF229607CF26C}, /* pText */
        --  {F2C9F76813E2D14B6AD629D9862AF278432665921A2AAE76D0A013}, /* cText */
        --  {46EA0E66B4A07A16F4D70E4997AC}  /* mac */
        122 => (Key       => +"C75B54850888351EA5493380E0DD4432C2CB92DFE28B98F5F1C9FFC0D16C824D",
                Nonce     => +"FE43A7AFBBDDB97DBC69AA8CE91D120A",
                Aad       => +"59E97EEB5E270AD6F8F4F60A0AAECB5DBB9F",
                Plaintext => +"6D6B3FDFEA4E7DC9FE87A4CB2D4412C0D008F657327A8DBE40A6",
                Cipher    => +"D974C3D2670FDC7FEA1198A696C0A285B9E35363ABBF422B4C17",
                MAC       => +"5FE1688443F2291DDB42EB9BA571"),
        --  /* ---------- KAT vector #122 ------------- */
        --  { 256,  26,  18, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {C75B54850888351EA5493380E0DD4432C2CB92DFE28B98F5F1C9FFC0D16C824D}, /* key */
        --  {FE43A7AFBBDDB97DBC69AA8CE91D120A}, /* nonce */
        --  {59E97EEB5E270AD6F8F4F60A0AAECB5DBB9F}, /* aad */
        --  {6D6B3FDFEA4E7DC9FE87A4CB2D4412C0D008F657327A8DBE40A6}, /* pText */
        --  {D974C3D2670FDC7FEA1198A696C0A285B9E35363ABBF422B4C17}, /* cText */
        --  {5FE1688443F2291DDB42EB9BA571}  /* mac */
        123 => (Key       => +"B7E88562E95A9DDCB88F12EA7BAB3723",
                Nonce     => +"F466255513D3DE82FA9AC8735E047353",
                Aad       => +"296CD0F3DBCF7B14B7D3073C7BD7",
                Plaintext => +"ACC68E7CED530596FC8AE8CBDC513A980D211ABDBCAF3CB82B",
                Cipher    => +"1139479B870AA11B01BC5AB2CBE80B9217D1AE53D5B9EE31EF",
                MAC       => +"7FED84FBB7E58C8057D3D9D40134"),
        --  /* ---------- KAT vector #123 ------------- */
        --  { 128,  25,  14, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {B7E88562E95A9DDCB88F12EA7BAB3723}, /* key */
        --  {F466255513D3DE82FA9AC8735E047353}, /* nonce */
        --  {296CD0F3DBCF7B14B7D3073C7BD7}, /* aad */
        --  {ACC68E7CED530596FC8AE8CBDC513A980D211ABDBCAF3CB82B}, /* pText */
        --  {1139479B870AA11B01BC5AB2CBE80B9217D1AE53D5B9EE31EF}, /* cText */
        --  {7FED84FBB7E58C8057D3D9D40134}  /* mac */
        124 => (Key       => +"118DC9C0C529AA9796263A78712B0F0D",
                Nonce     => +"82C57513991F9611450CE79FFA04A726",
                Aad       => +"631CD974397CA0CB267DA4A972A77A179F",
                Plaintext => +"B6092555E58C9930A23157126B05A4204A0874546B6C24DE",
                Cipher    => +"684DD901EF2E0273A3BACFBCAB7FCCA44D801D9E6B43567B",
                MAC       => +"62C7BEB7CF3616A3"),
        --  /* ---------- KAT vector #124 ------------- */
        --  { 128,  24,  17,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {118DC9C0C529AA9796263A78712B0F0D}, /* key */
        --  {82C57513991F9611450CE79FFA04A726}, /* nonce */
        --  {631CD974397CA0CB267DA4A972A77A179F}, /* aad */
        --  {B6092555E58C9930A23157126B05A4204A0874546B6C24DE}, /* pText */
        --  {684DD901EF2E0273A3BACFBCAB7FCCA44D801D9E6B43567B}, /* cText */
        --  {62C7BEB7CF3616A3}  /* mac */
        125 => (Key       => +"50844FF613637B2776C026B22A40D6A5EC002C9423C4BE59542761A0CF888B7A",
                Nonce     => +"C466CB83D0A1C5BCD11B9001E40A6C53",
                Aad       => +"29CFFC294996FE72CFBB710BD527D84ABFC93B700004AB13DA62BF3883E0D2DCF5998A",
                Plaintext => +"4B537C0BE32F47C80C1BDCA44DD79FF6360212115F1FD6",
                Cipher    => +"9B38F183F5C4B7C566DDC5D305C27BA473B71CAD03DB5B",
                MAC       => +"4057714A463907C54C44"),
        --  /* ---------- KAT vector #125 ------------- */
        --  { 256,  23,  35,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {50844FF613637B2776C026B22A40D6A5EC002C9423C4BE59542761A0CF888B7A}, /* key */
        --  {C466CB83D0A1C5BCD11B9001E40A6C53}, /* nonce */
        --  {29CFFC294996FE72CFBB710BD527D84ABFC93B700004AB13DA62BF3883E0D2DCF5998A}, /* aad */
        --  {4B537C0BE32F47C80C1BDCA44DD79FF6360212115F1FD6}, /* pText */
        --  {9B38F183F5C4B7C566DDC5D305C27BA473B71CAD03DB5B}, /* cText */
        --  {4057714A463907C54C44}  /* mac */
        126 => (Key       => +"D9B85EE8344BA4BEDCEC61E9EFF96C82D297F12A58613D451BC2ECD1EDAB6AF3",
                Nonce     => +"37ED99DC430C82407E13A06A204E4844",
                Aad       => +"46E862A0E90A2ED0A963CFCE25",
                Plaintext => +"EE43EA57FB3135E68D5C3DBD0C5050B92CEC42471DC6",
                Cipher    => +"2099EC6B8509A4C4946288278025417DDCC8341290E7",
                MAC       => +"57EBDEFA54BB6E4C"),
        --  /* ---------- KAT vector #126 ------------- */
        --  { 256,  22,  13,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {D9B85EE8344BA4BEDCEC61E9EFF96C82D297F12A58613D451BC2ECD1EDAB6AF3}, /* key */
        --  {37ED99DC430C82407E13A06A204E4844}, /* nonce */
        --  {46E862A0E90A2ED0A963CFCE25}, /* aad */
        --  {EE43EA57FB3135E68D5C3DBD0C5050B92CEC42471DC6}, /* pText */
        --  {2099EC6B8509A4C4946288278025417DDCC8341290E7}, /* cText */
        --  {57EBDEFA54BB6E4C}  /* mac */
        127 => (Key       => +"39A967359ECAAD5E8818CF43FA82820BA7C75D03B3ADFA23AAEC66A6DC4ABFF4",
                Nonce     => +"243FEBDE84AF4E6A66E240CC0C7B4168",
                Aad       => +"0045CFC6CFFB52F8347ADDFE29",
                Plaintext => +"5A63B18106F577C636195D9B5B491E0C4E20F46265",
                Cipher    => +"FA5095D9947D2EFAFC759AEA5397D236767CABF844",
                MAC       => +"B3CCCBE61042023BFBAD60900AE165DB"),
        --  /* ---------- KAT vector #127 ------------- */
        --  { 256,  21,  13, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {39A967359ECAAD5E8818CF43FA82820BA7C75D03B3ADFA23AAEC66A6DC4ABFF4}, /* key */
        --  {243FEBDE84AF4E6A66E240CC0C7B4168}, /* nonce */
        --  {0045CFC6CFFB52F8347ADDFE29}, /* aad */
        --  {5A63B18106F577C636195D9B5B491E0C4E20F46265}, /* pText */
        --  {FA5095D9947D2EFAFC759AEA5397D236767CABF844}, /* cText */
        --  {B3CCCBE61042023BFBAD60900AE165DB}  /* mac */
        128 => (Key       => +"A704A56A052FD30C45D42F32EC1F89D5DFC6D4BADC00482B5833390039C19558",
                Nonce     => +"E298FD9526ECBE6860087530CFF9563C",
                Aad       => +"FE189C468DC559F69CBEED98E1170F9D06",
                Plaintext => +"49EBF4D461F8BD01DC9ABEA09DCC6F22A053FE14",
                Cipher    => +"21AD74084B5B5C4BA3DB5CAF3FF20E56C2E5E3F5",
                MAC       => +"E57EEF4D3E74B397D9A8DE5C1DF4"),
        --  /* ---------- KAT vector #128 ------------- */
        --  { 256,  20,  17, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {A704A56A052FD30C45D42F32EC1F89D5DFC6D4BADC00482B5833390039C19558}, /* key */
        --  {E298FD9526ECBE6860087530CFF9563C}, /* nonce */
        --  {FE189C468DC559F69CBEED98E1170F9D06}, /* aad */
        --  {49EBF4D461F8BD01DC9ABEA09DCC6F22A053FE14}, /* pText */
        --  {21AD74084B5B5C4BA3DB5CAF3FF20E56C2E5E3F5}, /* cText */
        --  {E57EEF4D3E74B397D9A8DE5C1DF4}  /* mac */
        129 => (Key       => +"E67A52E352CDDFA6452D5A1B41777ACA",
                Nonce     => +"D215075F50053861C9073BAFD82DAFDF",
                Aad       => +"E16CC3ECB8",
                Plaintext => +"E09E938E88AAE90B1DB6865C266D632EE5657E",
                Cipher    => +"B0DC76A29FC59D9B2D3127EEFCCA367688FEA0",
                MAC       => +"5D78D5AB6D128C0EA824DA2302FC"),
        --  /* ---------- KAT vector #129 ------------- */
        --  { 128,  19,   5, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {E67A52E352CDDFA6452D5A1B41777ACA}, /* key */
        --  {D215075F50053861C9073BAFD82DAFDF}, /* nonce */
        --  {E16CC3ECB8}, /* aad */
        --  {E09E938E88AAE90B1DB6865C266D632EE5657E}, /* pText */
        --  {B0DC76A29FC59D9B2D3127EEFCCA367688FEA0}, /* cText */
        --  {5D78D5AB6D128C0EA824DA2302FC}  /* mac */
        130 => (Key       => +"5B780CBD298B937BC65A6564FFAC718D875AC0AF58DC5992",
                Nonce     => +"61BDAA379173CA28F16AD07F36B3ACFD",
                Aad       => +"8564BB20CCF109D97938F231311F1D2B75EF4474AB037C46F54E0866",
                Plaintext => +"D3A11B4F81BD4E955EAACEF58BE0E844D0F2",
                Cipher    => +"4B09632E0A55F9F75CFD78160F02E630621E",
                MAC       => +"81A6BFC566FCAD4BBF9FFF31"),
        --  /* ---------- KAT vector #130 ------------- */
        --  { 192,  18,  28,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {5B780CBD298B937BC65A6564FFAC718D875AC0AF58DC5992}, /* key */
        --  {61BDAA379173CA28F16AD07F36B3ACFD}, /* nonce */
        --  {8564BB20CCF109D97938F231311F1D2B75EF4474AB037C46F54E0866}, /* aad */
        --  {D3A11B4F81BD4E955EAACEF58BE0E844D0F2}, /* pText */
        --  {4B09632E0A55F9F75CFD78160F02E630621E}, /* cText */
        --  {81A6BFC566FCAD4BBF9FFF31}  /* mac */
        131 => (Key       => +"2C680ABEE7AB5532D404EB1538D99F1E63CF98541B1A347651AD84C40CC4EC8A",
                Nonce     => +"628BE31EA6FA1F56AAF7A9F135A6B8D3",
                Aad       => +"DD9C16AE92B8BF",
                Plaintext => +"D99147BB82A9C0B957EB48E81616EEF42C",
                Cipher    => +"FC9E233A1DFB99A28122EFB112DF4A7B0E",
                MAC       => +"DD817FE66D676F11"),
        --  /* ---------- KAT vector #131 ------------- */
        --  { 256,  17,   7,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {2C680ABEE7AB5532D404EB1538D99F1E63CF98541B1A347651AD84C40CC4EC8A}, /* key */
        --  {628BE31EA6FA1F56AAF7A9F135A6B8D3}, /* nonce */
        --  {DD9C16AE92B8BF}, /* aad */
        --  {D99147BB82A9C0B957EB48E81616EEF42C}, /* pText */
        --  {FC9E233A1DFB99A28122EFB112DF4A7B0E}, /* cText */
        --  {DD817FE66D676F11}  /* mac */
        132 => (Key       => +"2665F77FCD948FFDB6D85F4A91FCB5835819472364A2186E",
                Nonce     => +"8DFF013D5E1449595F6352BFAA5DC47F",
                Aad       => +"47",
                Plaintext => +"056C0969C24CB4BF45E7455D72C30C3B",
                Cipher    => +"06A43E59A55906C1E7CAD556D2F25490",
                MAC       => +"626BB9C24665442C89AAF615"),
        --  /* ---------- KAT vector #132 ------------- */
        --  { 192,  16,   1,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {2665F77FCD948FFDB6D85F4A91FCB5835819472364A2186E}, /* key */
        --  {8DFF013D5E1449595F6352BFAA5DC47F}, /* nonce */
        --  {47}, /* aad */
        --  {056C0969C24CB4BF45E7455D72C30C3B}, /* pText */
        --  {06A43E59A55906C1E7CAD556D2F25490}, /* cText */
        --  {626BB9C24665442C89AAF615}  /* mac */
        133 => (Key       => +"63D07BA4AA27C833D79BB2613256ABCAC1DD7FC275B65DBBA95ABFA7A0587D39",
                Nonce     => +"F39891C8B4780F0C9AC80A98D39DF52A",
                Aad       => +"",
                Plaintext => +"1132A0185AB450ECDF978BFD0494DE",
                Cipher    => +"0B59A9C7136171C4FDFF89B283E9F4",
                MAC       => +"C51447A7310D1F7115E8"),
        --  /* ---------- KAT vector #133 ------------- */
        --  { 256,  15,   0,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {63D07BA4AA27C833D79BB2613256ABCAC1DD7FC275B65DBBA95ABFA7A0587D39}, /* key */
        --  {F39891C8B4780F0C9AC80A98D39DF52A}, /* nonce */
        --  {}, /* aad */
        --  {1132A0185AB450ECDF978BFD0494DE}, /* pText */
        --  {0B59A9C7136171C4FDFF89B283E9F4}, /* cText */
        --  {C51447A7310D1F7115E8}  /* mac */
        134 => (Key       => +"9FA6BBADCE84266DD8EC82B50055CD36",
                Nonce     => +"6CDF822054FD0D53FACA083B9FAC52E9",
                Aad       => +"92C2502BF19E2EDED595162B3A644BB279",
                Plaintext => +"5E35B3E90A44B44D2230A9E788F4",
                Cipher    => +"47226491B0D75BDB5204FB3D8A54",
                MAC       => +"D65900E07EB6C4037A063BC505A88D1B"),
        --  /* ---------- KAT vector #134 ------------- */
        --  { 128,  14,  17, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {9FA6BBADCE84266DD8EC82B50055CD36}, /* key */
        --  {6CDF822054FD0D53FACA083B9FAC52E9}, /* nonce */
        --  {92C2502BF19E2EDED595162B3A644BB279}, /* aad */
        --  {5E35B3E90A44B44D2230A9E788F4}, /* pText */
        --  {47226491B0D75BDB5204FB3D8A54}, /* cText */
        --  {D65900E07EB6C4037A063BC505A88D1B}  /* mac */
        135 => (Key       => +"6A34C1AF757FA301178B6A2177067F6B3EF45BCEF427F406D7DE3A593E8F5E6B",
                Nonce     => +"41BF17267669B9784508995E6674FA0D",
                Aad       => +"C32A81684C961BB5DBBA90923090780B7D45CACA96",
                Plaintext => +"AE1F5A48A0FDEA8301B2E86C0D",
                Cipher    => +"20D26ADBF91C31DDF1EDB74C12",
                MAC       => +"8A6A5B96FFF77E3EE4B4CF236686"),
        --  /* ---------- KAT vector #135 ------------- */
        --  { 256,  13,  21, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {6A34C1AF757FA301178B6A2177067F6B3EF45BCEF427F406D7DE3A593E8F5E6B}, /* key */
        --  {41BF17267669B9784508995E6674FA0D}, /* nonce */
        --  {C32A81684C961BB5DBBA90923090780B7D45CACA96}, /* aad */
        --  {AE1F5A48A0FDEA8301B2E86C0D}, /* pText */
        --  {20D26ADBF91C31DDF1EDB74C12}, /* cText */
        --  {8A6A5B96FFF77E3EE4B4CF236686}  /* mac */
        136 => (Key       => +"4A10719F1AE4DCEFFF934FFCB2CBB343DB28CC2574EBD17FE088F3F211ADBCE9",
                Nonce     => +"1FB62DBD78C8B24BBE87D22C4B65AFB7",
                Aad       => +"BA5CE2DEAF3F85B35E6B08F8",
                Plaintext => +"D57025089EE6863C9C9255FC",
                Cipher    => +"10D6540F88BF6AB3BD188E35",
                MAC       => +"67B7A1D8C46462D64C2BF314"),
        --  /* ---------- KAT vector #136 ------------- */
        --  { 256,  12,  12,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {4A10719F1AE4DCEFFF934FFCB2CBB343DB28CC2574EBD17FE088F3F211ADBCE9}, /* key */
        --  {1FB62DBD78C8B24BBE87D22C4B65AFB7}, /* nonce */
        --  {BA5CE2DEAF3F85B35E6B08F8}, /* aad */
        --  {D57025089EE6863C9C9255FC}, /* pText */
        --  {10D6540F88BF6AB3BD188E35}, /* cText */
        --  {67B7A1D8C46462D64C2BF314}  /* mac */
        137 => (Key       => +"41014462895EF445111CCAB9AE2D6E5EFA51112C61AABB6B",
                Nonce     => +"00CB65ADBC0A32D02AB2F7F3ACC271B7",
                Aad       => +"F18A70E17293CE2E9FAA9C5D8BFA93EFD33C51EA90A25342",
                Plaintext => +"DF12ADBFDB934368C6BD96",
                Cipher    => +"48348162F5301478231420",
                MAC       => +"B93AF190241D9FA68D99F8277BA984C8"),
        --  /* ---------- KAT vector #137 ------------- */
        --  { 192,  11,  24, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {41014462895EF445111CCAB9AE2D6E5EFA51112C61AABB6B}, /* key */
        --  {00CB65ADBC0A32D02AB2F7F3ACC271B7}, /* nonce */
        --  {F18A70E17293CE2E9FAA9C5D8BFA93EFD33C51EA90A25342}, /* aad */
        --  {DF12ADBFDB934368C6BD96}, /* pText */
        --  {48348162F5301478231420}, /* cText */
        --  {B93AF190241D9FA68D99F8277BA984C8}  /* mac */
        138 => (Key       => +"898C516D69D0292D00C6235AC2F6AAFA2269DD0ABC475E4B",
                Nonce     => +"3780A6FA92839675C9629C0D00BAD86B",
                Aad       => +"0A301FAC45C8DA46A6",
                Plaintext => +"98B8B4430EA61644F15B",
                Cipher    => +"A164878EF9AFFC0E59A0",
                MAC       => +"73A26B07B74D8A01"),
        --  /* ---------- KAT vector #138 ------------- */
        --  { 192,  10,   9,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {898C516D69D0292D00C6235AC2F6AAFA2269DD0ABC475E4B}, /* key */
        --  {3780A6FA92839675C9629C0D00BAD86B}, /* nonce */
        --  {0A301FAC45C8DA46A6}, /* aad */
        --  {98B8B4430EA61644F15B}, /* pText */
        --  {A164878EF9AFFC0E59A0}, /* cText */
        --  {73A26B07B74D8A01}  /* mac */
        139 => (Key       => +"3A5F55E0A91EF2CDF6C502B23323C75971A911451CE8C27B9BD1E2CF01CC069F",
                Nonce     => +"CDC66819FE73E0D04C09E8DDBEEB12FF",
                Aad       => +"16B01666717AFBD809F93C1671FAD9780813E7808F4F",
                Plaintext => +"1EAA642432C0E6CA85",
                Cipher    => +"11BC09C339D37D69A1",
                MAC       => +"EA2E294AEA7FFC7700DB1BEFB51BF4E2"),
        --  /* ---------- KAT vector #139 ------------- */
        --  { 256,   9,  22, 128, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {3A5F55E0A91EF2CDF6C502B23323C75971A911451CE8C27B9BD1E2CF01CC069F}, /* key */
        --  {CDC66819FE73E0D04C09E8DDBEEB12FF}, /* nonce */
        --  {16B01666717AFBD809F93C1671FAD9780813E7808F4F}, /* aad */
        --  {1EAA642432C0E6CA85}, /* pText */
        --  {11BC09C339D37D69A1}, /* cText */
        --  {EA2E294AEA7FFC7700DB1BEFB51BF4E2}  /* mac */
        140 => (Key       => +"40E4EFDA6311744ACCA2BA8AA1E891F9C9D2B6861E3F9480B4B19CC2CF4A947D",
                Nonce     => +"3CF74511FCCF7B018454EBEC8D169378",
                Aad       => +"5C07A2E84F7DE6C99E1E3CACF58B6C94DA9E233E839766F1129B8537C2DAD0",
                Plaintext => +"100A08EF97044988",
                Cipher    => +"5F41B20FF9A56062",
                MAC       => +"193BB5985514C6B5"),
        --  /* ---------- KAT vector #140 ------------- */
        --  { 256,   8,  31,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {40E4EFDA6311744ACCA2BA8AA1E891F9C9D2B6861E3F9480B4B19CC2CF4A947D}, /* key */
        --  {3CF74511FCCF7B018454EBEC8D169378}, /* nonce */
        --  {5C07A2E84F7DE6C99E1E3CACF58B6C94DA9E233E839766F1129B8537C2DAD0}, /* aad */
        --  {100A08EF97044988}, /* pText */
        --  {5F41B20FF9A56062}, /* cText */
        --  {193BB5985514C6B5}  /* mac */
        141 => (Key       => +"8944A4BFA2DE920F1757B572B3DE0A0005DC42E44B375AE631747F1596E7C309",
                Nonce     => +"CD539834B628BABCF0425172B925A709",
                Aad       => +"235EC6EEDB4C4B8A659AB69A05602C9B39D73B2A267C52",
                Plaintext => +"339AF683DE5807",
                Cipher    => +"A3BE30466C2C7A",
                MAC       => +"18CE7A5770E793E7C5705183A2A1"),
        --  /* ---------- KAT vector #141 ------------- */
        --  { 256,   7,  23, 112, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {8944A4BFA2DE920F1757B572B3DE0A0005DC42E44B375AE631747F1596E7C309}, /* key */
        --  {CD539834B628BABCF0425172B925A709}, /* nonce */
        --  {235EC6EEDB4C4B8A659AB69A05602C9B39D73B2A267C52}, /* aad */
        --  {339AF683DE5807}, /* pText */
        --  {A3BE30466C2C7A}, /* cText */
        --  {18CE7A5770E793E7C5705183A2A1}  /* mac */
        142 => (Key       => +"24F5A9B82CE0771C5DCF1354FE1D0549DA047B9F91467DE9",
                Nonce     => +"6479196B5DEF28357CE8D5A227631DC4",
                Aad       => +"D03DDCBFA4A7D7EDE067E021961A89A42681",
                Plaintext => +"144021C19226",
                Cipher    => +"E2CBC9498E99",
                MAC       => +"CA0DF05B89C2B4738BB0"),
        --  /* ---------- KAT vector #142 ------------- */
        --  { 192,   6,  18,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {24F5A9B82CE0771C5DCF1354FE1D0549DA047B9F91467DE9}, /* key */
        --  {6479196B5DEF28357CE8D5A227631DC4}, /* nonce */
        --  {D03DDCBFA4A7D7EDE067E021961A89A42681}, /* aad */
        --  {144021C19226}, /* pText */
        --  {E2CBC9498E99}, /* cText */
        --  {CA0DF05B89C2B4738BB0}  /* mac */
        143 => (Key       => +"3AD70FA544E2D87774D3B40F8E218E77",
                Nonce     => +"FC1CED7FA78179D346A9D4CAF453FAD9",
                Aad       => +"44D368434A",
                Plaintext => +"471CE3B567",
                Cipher    => +"8982A1F4F7",
                MAC       => +"60A7ACBFE8404C93526E9AF4"),
        --  /* ---------- KAT vector #143 ------------- */
        --  { 128,   5,   5,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {3AD70FA544E2D87774D3B40F8E218E77}, /* key */
        --  {FC1CED7FA78179D346A9D4CAF453FAD9}, /* nonce */
        --  {44D368434A}, /* aad */
        --  {471CE3B567}, /* pText */
        --  {8982A1F4F7}, /* cText */
        --  {60A7ACBFE8404C93526E9AF4}  /* mac */
        144 => (Key       => +"6C33950A842FCEA9BA9925182646C3E24D1843BE0C50C9EB",
                Nonce     => +"E89486477A09A73AFC545E36AA7470E7",
                Aad       => +"42E4EF64F952EAD37A",
                Plaintext => +"5E43CEF6",
                Cipher    => +"B4A9684F",
                MAC       => +"26C206D1CAC2BE38D8C6DA21"),
        --  /* ---------- KAT vector #144 ------------- */
        --  { 192,   4,   9,  96, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {6C33950A842FCEA9BA9925182646C3E24D1843BE0C50C9EB}, /* key */
        --  {E89486477A09A73AFC545E36AA7470E7}, /* nonce */
        --  {42E4EF64F952EAD37A}, /* aad */
        --  {5E43CEF6}, /* pText */
        --  {B4A9684F}, /* cText */
        --  {26C206D1CAC2BE38D8C6DA21}  /* mac */
        145 => (Key       => +"437043BC990EC41182B124803932E5653DAEC1C1A4A20A115390E42E7FDAF6B5",
                Nonce     => +"8D0CFE1AADF1FB3A2B9DC73FBC60FE90",
                Aad       => +"5BE6352037BE28EF14C45A8F3B45",
                Plaintext => +"2819EB",
                Cipher    => +"7695A4",
                MAC       => +"4D4544C35A6365020F63"),
        --  /* ---------- KAT vector #145 ------------- */
        --  { 256,   3,  14,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {437043BC990EC41182B124803932E5653DAEC1C1A4A20A115390E42E7FDAF6B5}, /* key */
        --  {8D0CFE1AADF1FB3A2B9DC73FBC60FE90}, /* nonce */
        --  {5BE6352037BE28EF14C45A8F3B45}, /* aad */
        --  {2819EB}, /* pText */
        --  {7695A4}, /* cText */
        --  {4D4544C35A6365020F63}  /* mac */
        146 => (Key       => +"BAADB11CE6976D6C9EEB0D23C6866DED37E8B33AFC7742AB94232566A62AEF23",
                Nonce     => +"57CAC744E915C156470BB92597A51448",
                Aad       => +"76CE70A8F795099BF25E807FDDB4FF716E8F",
                Plaintext => +"0D7C",
                Cipher    => +"AF3A",
                MAC       => +"2BE8BBA78691320EDA72"),
        --  /* ---------- KAT vector #146 ------------- */
        --  { 256,   2,  18,  80, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {BAADB11CE6976D6C9EEB0D23C6866DED37E8B33AFC7742AB94232566A62AEF23}, /* key */
        --  {57CAC744E915C156470BB92597A51448}, /* nonce */
        --  {76CE70A8F795099BF25E807FDDB4FF716E8F}, /* aad */
        --  {0D7C}, /* pText */
        --  {AF3A}, /* cText */
        --  {2BE8BBA78691320EDA72}  /* mac */
        147 => (Key       => +"DB7DE65C348BB0A7D6A0EB4E4D478C8844756B76D36A1EDB4F29FFE93D54FEC6",
                Nonce     => +"3A2C40E26076CCFD00FC28B56B480F1E",
                Aad       => +"1B6DA1EF4C10C02350C125233476A6DA98039FDD698740",
                Plaintext => +"E9",
                Cipher    => +"42",
                MAC       => +"6EC468CDAD581A91"),
        --  /* ---------- KAT vector #147 ------------- */
        --  { 256,   1,  23,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {DB7DE65C348BB0A7D6A0EB4E4D478C8844756B76D36A1EDB4F29FFE93D54FEC6}, /* key */
        --  {3A2C40E26076CCFD00FC28B56B480F1E}, /* nonce */
        --  {1B6DA1EF4C10C02350C125233476A6DA98039FDD698740}, /* aad */
        --  {E9}, /* pText */
        --  {42}, /* cText */
        --  {6EC468CDAD581A91}  /* mac */
        148 => (Key       => +"3F78A3ACA524E1AA5D56346AA8F89029",
                Nonce     => +"034597E0B64AE8BB312EDCEB34D3E394",
                Aad       => +"D434E2D1E419",
                Plaintext => +"",
                Cipher    => +"",
                MAC       => +"1FCD00E69D850635"),
        --  /* ---------- KAT vector #148 ------------- */
        --  { 128,   0,   6,  64, 128,  /* keySize, msgLen, aadLen, macSize, nonceSize */
        --  {3F78A3ACA524E1AA5D56346AA8F89029}, /* key */
        --  {034597E0B64AE8BB312EDCEB34D3E394}, /* nonce */
        --  {D434E2D1E419}, /* aad */
        --  {}, /* pText */
        --  {}, /* cText */
        --  {1FCD00E69D850635}  /* mac */

        --
        --  Following are the test vectors from the orginal paper
        --
        --  "Phelix - Fast Encryption and Authentication in a Single Cryptographic Primitive"
        --
        149 => (Key       => +"",
                Nonce     => +"00000000000000000000000000000000",
                Aad       => +"",
                Plaintext => +"00000000000000000000",
                Cipher    => +"D52D45C605FD7A67748D",
                MAC       => +"EF7BFE7AEBDC1A8B43362F2893800DBC"),
        --  Initial Key: <empty string>
        --  Nonce: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        --  AAD: <empty string>
        --  Plaintext: 00 00 00 00 00 00 00 00 00 00
        --  Ciphertext: D5 2D 45 C6 05 FD 7A 67 74 8D
        --  MAC: EF 7B FE 7A EB DC 1A 8B 43 36 2F 28 93 80 0D BC
        150 => (Key       => +"0000000001000000020000000300000004000000050000000600000007000000",
                Nonce     => +"00000001010000010200000103000001",
                Aad       => +"",
                Plaintext => +"000102030102030402030405030405060405060705060708060708090708090A",
                Cipher    => +"B5FC4BF5BC640A56003D596D334BA594A5487B4E308EDB05A7D62F234514024A",
                MAC       => +"DB0C22C466BDCDE4E32903F79AE542D1"),
        --  Initial Key: 00 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04 00 00 00 05 00 00 00 06 00 00 00 07 00 00 00
        --  Nonce: 00 00 00 01 01 00 00 01 02 00 00 01 03 00 00 01
        --  AAD: <empty string>
        --  Plaintext: 00 01 02 03 01 02 03 04 02 03 04 05 03 04 05 06 04 05 06 07 05 06 07 08 06 07 08 09 07 08 09 0A
        --  Ciphertext: B5 FC 4B F5 BC 64 0A 56 00 3D 59 6D 33 4B A5 94 A5 48 7B 4E 30 8E DB 05 A7 D6 2F 23 45 14 02 4A
        --  MAC: DB 0C 22 C4 66 BD CD E4 E3 29 03 F7 9A E5 42 D1
        151 => (Key       => +"01020304050607080807060504030201",
                Nonce     => +"04000000050000000600000007000000",
                Aad       => +"",
                Plaintext => +"",
                Cipher    => +"",
                MAC       => +"BEAFD3BD00BE4417"),
        --  Initial Key: 01 02 03 04 05 06 07 08 08 07 06 05 04 03 02 01
        --  Nonce: 04 00 00 00 05 00 00 00 06 00 00 00 07 00 00 00
        --  AAD: <empty string>
        --  Plaintext: <empty string>
        --  Ciphertext: <empty string>
        --  MAC: BE AF D3 BD 00 BE 44 17

        152 => (Key       => +"0907050301",
                Nonce     => +"08070605040302010001020304050607",
                Aad       => +"000204060103050708",
                Plaintext => +"000102030102030402030405FF",
                Cipher    => +"F10D3E067A32B1BEDAA5898BDE",
                MAC       => +"60A231C1C9F5E4EF40AA0A1C")
        --  Initial Key: 09 07 05 03 01
        --  Nonce: 08 07 06 05 04 03 02 01 00 01 02 03 04 05 06 07
        --  AAD: 00 02 04 06 01 03 05 07 08
        --  Plaintext: 00 01 02 03 01 02 03 04 02 03 04 05 FF
        --  Ciphertext: F1 0D 3E 06 7A 32 B1 BE DA A5 89 8B DE
        --  MAC: 60 A2 31 C1 C9 F5 E4 EF 40 AA 0A 1C
);

end Saatana.Crypto.Phelix.Test_Vectors;
