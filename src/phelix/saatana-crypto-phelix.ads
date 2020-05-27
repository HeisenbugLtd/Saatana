------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

------------------------------------------------------------------------------
--  SPARK implementation of PHELIX.
--
--  A.  Cover sheet for Phelix Submission to ECRYPT
--
--  1.  Name of submitted algorithm:    Phelix
--
--
--  2.  Type of submitted algorithm:    Synchronous stream cipher with authentication
--      Proposed security level:        128-bit. Key length:  up to 256 bits.
--      Proposed environment:           Any.
--
--  3.  Principle Submitter:            Douglas Whiting
--      Telephone:                      +1-760-827-4502
--      Fax:                            +1-760-930-9115
--      Organization:                   Hifn, Inc.
--      Postal Address:                 5973 Avenida Encinas, Suite 110,
--                                      Carlsbad, California 92009  USA
--      E-mail Address:                 dwhiting@hifn.com
--
--  4.  Name of auxiliary submitter:    Bruce Schneier
--
--  5.  Name of algorithm inventors:    Douglas Whiting, Bruce Schneier,
--                                      John Kelsey, Stefan Lucks, Tadayoshi Kohno
--
--  6.  Name of owner of the algorithm: Public domain
--
--  7.  Signature of submitter:         _________________________________________
--
--  8.  Backup point of contact:        Bruce Schneier,
--      Telephone:                      +1-650-404-2400
--      Fax:                            +1-650-903-0461
--      Organization:                   Counterpane Internet Security
--      Postal Address:                 1090A La Avenida
--                                      Mountain View, CA 94043    USA
--      E-mail Address:                 schneier@counterpane.com
------------------------------------------------------------------------------

package Saatana.Crypto.Phelix with
  SPARK_Mode => On,
  Pure       => True
is

   Max_Nonce_Size : constant := 128;
   Max_MAC_Size   : constant := 128;
   Max_Key_Size   : constant := 256;

   subtype MAC_Size_32 is Word_32 range 0 .. Max_MAC_Size with
     Dynamic_Predicate => MAC_Size_32 mod 8 = 0;

   subtype Key_Size_32 is Word_32 range 0 .. Max_Key_Size with
     Dynamic_Predicate => Key_Size_32 mod 8 = 0;

   type Context is private;

   --  Proof functions.
   function Ctx_AAD_Len (Ctx : in Context) return Stream_Count with
     Ghost  => True,
     Global => null;

   function Ctx_I (Ctx : in Context) return Word_32 with
     Ghost  => True,
     Global => null;

   function Ctx_Key_Size (Ctx : in Context) return Key_Size_32 with
     Ghost  => True,
     Global => null;

   function Ctx_Mac_Size (Ctx : in Context) return MAC_Size_32 with
     Ghost  => True,
     Global => null;

   function Ctx_Msg_Len (Ctx : in Context) return Word_32 with
     Ghost  => True,
     Global => null;

   --  As the order in which calls are made is important, we define some proof
   --  functions to be used as precondition.
   function Setup_Key_Called (Ctx : in Context) return Boolean with
     Ghost  => True,
     Global => null;

   function Setup_Nonce_Called (Ctx : in Context) return Boolean with
     Ghost  => True,
     Global => null;

   --
   --  Encrypt_Packet
   --
   --  Using the cipher context This, this subprogram encrypts Payload and
   --  stores the Header followed by the encrypted Payload into Packet, and
   --  the message authentication code into MAC.
   --
   procedure Encrypt_Packet (This    : in out Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Plaintext_Stream;
                             Packet  :    out Ciphertext_Stream;
                             Mac     :    out MAC_Stream) with
     Global  => null,
     Depends => (This   => (This,
                            Nonce,
                            Header,
                            Payload),
                 Packet => (Packet,
                            This,
                            Nonce,
                            Header,
                            Payload),
                 Mac    => (Mac, -- Not really, but SPARK insists.
                            This,
                            Nonce,
                            Header,
                            Payload)),
     Pre     => (Setup_Key_Called (This)                        and then
                 Header'Initialized                             and then
                 Payload'Initialized                            and then
                 Header'Length + Payload'Length = Packet'Length and then
                 Nonce'Length = Max_Nonce_Size / 8              and then
                 Mac'Length = Stream_Count (Ctx_Mac_Size (This) / 8)),
     Post    => (Setup_Key_Called (This) = Setup_Key_Called (This'Old) and then
                 not Setup_Nonce_Called (This)                         and then
                 Packet'Initialized);

   --
   --  Decrypt_Packet
   --
   --  Using the cipher context This, this subprogram decrypts Payload and
   --  stores the Header followed by the decrypted Payload into Packet, and
   --  the message authentication code into MAC.
   --
   --  The resulting Packet must only be processed if the returned MAC matches
   --  the expected one.
   --
   procedure Decrypt_Packet (This    : in out Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Ciphertext_Stream;
                             Packet  :    out Plaintext_Stream;
                             Mac     :    out MAC_Stream) with
     Global  => null,
     Depends => (This   => (This,
                            Nonce,
                            Header,
                            Payload),
                 Packet => (Packet, -- not really
                            This,
                            Nonce,
                            Header,
                            Payload),
                 Mac    => (Mac,
                            This,
                            Nonce,
                            Header,
                            Payload)),
     Pre     => (Setup_Key_Called (This)                        and then
                 Header'Initialized                             and then
                 Payload'Initialized                            and then
                 Header'Length + Payload'Length = Packet'Length and then
                 Nonce'Length = Max_Nonce_Size / 8              and then
                 Mac'Length = Stream_Count (Ctx_Mac_Size (This) / 8)),
     Post    => (Setup_Key_Called (This) = Setup_Key_Called (This'Old) and then
                 not Setup_Nonce_Called (This)                         and then
                 Packet'Initialized);

   --
   --  Setup_Key
   --
   --  Initializes the key schedule of the cipher context This.
   --
   procedure Setup_Key (This     :    out Context;
                        Key      : in     Key_Stream;
                        Mac_Size : in     MAC_Size_32) with
     Global  => null,
     Depends => (This => (Key,
                          Mac_Size)),
     Pre     => (Key'Length <= Max_Key_Size / 8), -- Support key sizes between 0 and 256 bits
     Post    => (Setup_Key_Called (This)              and then
                 not Setup_Nonce_Called (This)        and then
                 Ctx_Key_Size (This) = Key'Length * 8 and then
                 Ctx_Mac_Size (This) = Mac_Size);

   --
   --  Setup_Nonce
   --
   --  Updates the internal cipher state with the given Nonce.
   --
   --  Setup_Nonce can be called several times to setup a new cipher context.
   --
   procedure Setup_Nonce (This  : in out Context;
                          Nonce : in     Nonce_Stream) with
     Global  => null,
     Depends => (This => (This,
                          Nonce)),
     Pre     => (Setup_Key_Called (This) and then
                 Nonce'Length = Max_Nonce_Size / 8),
     Post    => (Setup_Key_Called (This) = Setup_Key_Called (This'Old) and then
                 Setup_Nonce_Called (This)                             and then
                 Ctx_I (This) = 8                                      and then
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old)         and then
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old)         and then
                 Ctx_AAD_Len (This) = 0                                and then
                 Ctx_Msg_Len (This) = 0);

   --
   --  Process_AAD
   --
   --  Updates the internal cipher state for a proper calculation of the
   --  message authentication code for a subsequent decryption or encryption.
   --
   --  Process_AAD can be called several times in succession for different
   --  parts of the plain text stream.
   --
   procedure Process_AAD (This    : in out Context;
                          Aad     : in     Plaintext_Stream) with
     Global  => null,
     Depends => (This => (This,
                          Aad)),
     Pre     => (Aad'Initialized              and then
                 Setup_Nonce_Called (This)    and then
                 Ctx_Msg_Len (This) = 0       and then --  AAD processing must be done first
                 Ctx_AAD_Len (This) mod 4 = 0 and then --  can only make ONE sub-word call!
                 Ctx_AAD_Len (This) < Stream_Count'Last - Aad'Length),
     Post    => (Setup_Key_Called (This) = Setup_Key_Called (This'Old)     and then
                 Setup_Nonce_Called (This) = Setup_Nonce_Called (This'Old) and then
                 Ctx_AAD_Len (This) = Ctx_AAD_Len (This'Old) + Aad'Length  and then
                 Ctx_Msg_Len (This) = 0                                    and then
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old)             and then
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old));

   --
   --  Encrypt_Bytes
   --
   --  Using the cipher context This, this subprogram encrypts the Source into
   --  Destination.
   --
   --  Encrypt_Bytes can be called several times in succession for different
   --  parts of the plaintext.
   --
   procedure Encrypt_Bytes (This        : in out Context;
                            Source      : in     Plaintext_Stream;
                            Destination :    out Ciphertext_Stream) with
     Global  => null,
     Depends => (This        => (This,
                                 Source),
                 Destination => (This,
                                 Destination,
                                 Source)),
     Pre     => (Source'Initialized                 and then
                 Source'Length = Destination'Length and then
                 Setup_Nonce_Called (This)          and then
                 Ctx_Msg_Len (This) mod 4 = 0), --  Can only make ONE sub-word call!
     Post    => (Setup_Key_Called (This) = Setup_Key_Called (This'Old)                             and then
                 Setup_Nonce_Called (This) = Setup_Nonce_Called (This'Old)                         and then
                 Ctx_AAD_Len (This) = Ctx_AAD_Len (This'Old)                                       and then
                 Ctx_Msg_Len (This) = Ctx_Msg_Len (This'Old) + Word_32 (Source'Length mod 2 ** 32) and then
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old)                                     and then
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old)                                     and then
                 Destination'Initialized);

   --
   --  Decrypt_Bytes
   --
   --  Using the cipher context This, this subprogram decrypts the Source into
   --  Destination.
   --
   --  Decrypt_Bytes can be called several times in succession for different
   --  parts of the cipher text.
   --
   procedure Decrypt_Bytes (This        : in out Context;
                            Source      : in     Ciphertext_Stream;
                            Destination :    out Plaintext_Stream) with
     Global  => null,
     Depends => (This        => (This,
                                 Source),
                 Destination => (Destination,
                                 This,
                                 Source)),
     Pre     => (Source'Initialized                 and then
                 Source'Length = Destination'Length and then
                 Setup_Nonce_Called (This)          and then
                 Ctx_Msg_Len (This) mod 4 = 0),
     Post    => (Setup_Key_Called (This) = Setup_Key_Called (This'Old)                             and then
                 Setup_Nonce_Called (This) = Setup_Nonce_Called (This'Old)                         and then
                 Ctx_AAD_Len (This) = Ctx_AAD_Len (This'Old)                                       and then
                 Ctx_Msg_Len (This) = Ctx_Msg_Len (This'Old) + Word_32 (Source'Length mod 2 ** 32) and then
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old)                                     and then
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old)                                     and then
                 Destination'Initialized);

   --
   --  Finalize
   --
   --  Calculates the message authentication code after a decryption or
   --  encryption and stores it in Mac.
   --
   procedure Finalize (This : in out Context;
                       Mac  :    out MAC_Stream) with
     Global  => null,
     Depends => (This => This,
                 Mac  => (Mac, -- This isn't exactly True, but SPARK insists, probably because we rely on Mac'Length
                          This)),
     Pre     => (Setup_Nonce_Called (This) and then
                 Mac'Length = Stream_Count (Ctx_Mac_Size (This) / 8)),
     Post    => (Setup_Key_Called (This) = Setup_Key_Called (This'Old) and then
                 not Setup_Nonce_Called (This));

private

   type Mod_8 is mod 8;

   subtype Full_State_Words is Mod_8 range 0 .. 4; --  5 state words
   subtype Old_State_Words  is Mod_8 range 0 .. 3; --  4 old state words

   type Unsigned_32_Array is array (Mod_8 range <>) of Word_32;

   --  Several state arrays (old Z, state words, expanded key.
   subtype Old_Z_4        is Unsigned_32_Array (Old_State_Words);
   subtype State_Words    is Unsigned_32_Array (Full_State_Words);
   subtype Key_Processing is Unsigned_32_Array (Mod_8);

   type Key_Schedule is
      tagged record
         Key_Size : Key_Size_32;    --  initial key size, in bits
         MAC_Size : MAC_Size_32;    --  MAC tag size, in bits
         X_1_Bump : Word_32;        --  4 * (keySize / 8) + 256 * (MAC_Size mod 128)
         X_0      : Key_Processing;
         X_1      : Key_Processing; --  processed working key material
      end record;

   type Cipher_State is
      tagged record
         Old_Z   : Old_Z_4;      --  Previous four Z_4 values for output
         Z       : State_Words;  --  5 internal state words (160 bits)
         AAD_Len : Stream_Count; --  AAD length
         I       : Word_32;      --  block number (modulo 2 ** 32)
         Msg_Len : Word_32;      --  message length  (modulo 2 ** 32)
         AAD_Xor : Word_32;      --  aadXor constant
      end record;

   type Phase is (Uninitialized, Key_Has_Been_Setup, Nonce_Has_Been_Setup);
   --  Ensure proper call sequence. State changes are:
   --
   --     (Uninitialized)
   --           |
   --           v
   --   (Key_Has_Been_Setup) <-.
   --           |              |
   --           v              |
   --  (Nonce_Has_Been_Setup)  |
   --           |              |
   --           `--------------'

   type Context is
      record
         KS        : Key_Schedule;
         CS        : Cipher_State;
         --  This state variable is merely here to ensure proper call sequences
         --  as precondition.
         --  Also, we need it to be automatically initialized.
         Setup_Phase : Phase := Uninitialized;
      end record;

   --  Proof functions

   function Ctx_AAD_Len (Ctx : in Context) return Stream_Count is
     (Ctx.CS.AAD_Len);

   function Ctx_I (Ctx : in Context) return Word_32 is
     (Ctx.CS.I);

   function Ctx_Key_Size (Ctx : in Context) return Key_Size_32 is
     (Ctx.KS.Key_Size);

   function Ctx_Mac_Size (Ctx : in Context) return MAC_Size_32 is
     (Ctx.KS.MAC_Size);

   function Ctx_Msg_Len (Ctx : in Context) return Word_32 is
     (Ctx.CS.Msg_Len);

   function Setup_Key_Called (Ctx : in Context) return Boolean is
     (Ctx.Setup_Phase in Key_Has_Been_Setup .. Nonce_Has_Been_Setup);

   function Setup_Nonce_Called (Ctx : in Context) return Boolean is
     (Ctx.Setup_Phase in Nonce_Has_Been_Setup);

end Saatana.Crypto.Phelix;
