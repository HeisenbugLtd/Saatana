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

with Interfaces;

package Crypto.Phelix with
  SPARK_Mode => On,
  Pure       => True
is

   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Max_Nonce_Size : constant := 128;
   Max_MAC_Size   : constant := 128;
   Max_Key_Size   : constant := 256;

   subtype MAC_Size_32 is Interfaces.Unsigned_32 range 0 .. Max_MAC_Size with
     Dynamic_Predicate => MAC_Size_32 mod 8 = 0;

   subtype Key_Size_32 is Interfaces.Unsigned_32 range 0 .. Max_Key_Size with
     Dynamic_Predicate => Key_Size_32 mod 8 = 0;

   type Context is private;

   --  Proof functions.
   function Ctx_AAD_Len (Ctx : Context) return Stream_Count with
     Ghost => True;

   function Ctx_I (Ctx : Context) return Interfaces.Unsigned_32 with
     Ghost => True;

   function Ctx_Key_Size (Ctx : Context) return Key_Size_32 with
     Ghost => True;

   function Ctx_Mac_Size (Ctx : Context) return MAC_Size_32 with
     Ghost => True;

   function Ctx_Msg_Len (Ctx : Context) return Interfaces.Unsigned_32 with
     Ghost => True;

   --
   --  Encrypt_Packet
   --
   procedure Encrypt_Packet (This    : in     Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Plaintext_Stream;
                             Packet  :    out Ciphertext_Stream;
                             Mac     :    out MAC_Stream) with
     Depends => (Packet => (Packet,
                            This,
                            Nonce,
                            Header,
                            Payload),
                 Mac    => (Mac, -- Not really, but SPARK insists.
                            This,
                            Nonce,
                            Header,
                            Payload)),
     Pre     => (Header'First in Stream_Index                                     and then -- FIXME
                 (Payload'First in Stream_Index and Packet'First in Stream_Index) and then -- FIXME: implicit, needed for proof
                 Header'Length + Payload'Length = Packet'Length                   and then
                 Nonce'Length = Max_Nonce_Size / 8                                and then
                 Mac'Length = Stream_Count (Ctx_Mac_Size (This) / 8)              and then
                 Ctx_AAD_Len (This) = 0                                           and then
                 Ctx_Msg_Len (This) = 0);

   --
   --  Decrypt_Packet
   --
   procedure Decrypt_Packet (This    : in     Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Ciphertext_Stream;
                             Packet  :    out Plaintext_Stream;
                             Mac     :    out MAC_Stream) with
     Depends => (Packet => (Packet, -- not really
                            This,
                            Nonce,
                            Header,
                            Payload),
                 Mac    => (Mac,
                            This,
                            Nonce,
                            Header,
                            Payload)),
     Pre     => (Header'First in Stream_Index                                     and then -- FIXME
                 (Payload'First in Stream_Index and Packet'First in Stream_Index) and then -- FIXME: implicit, needed for proof
                 Header'Length + Payload'Length = Packet'Length                   and then
                 Nonce'Length = Max_Nonce_Size / 8                                and then
                 Mac'Length = Stream_Count (Ctx_Mac_Size (This) / 8)              and then
                 Ctx_AAD_Len (This) = 0                                           and then
                 Ctx_Msg_Len (This) = 0);

   --
   --  Setup_Key
   --
   procedure Setup_Key (This     : in out Context;
                        Key      : in     Key_Stream;
                        Mac_Size : in     MAC_Size_32) with
     Depends => (This => (This,
                          Key,
                          Mac_Size)),
     Pre     => (Key'Length <= Max_Key_Size / 8 and -- Support key sizes between 0 and 256 bits
                 Mac_Size in MAC_Size_32), --  We only support "sane" MAC sizes
     Post    => (Ctx_Key_Size (This) = Key'Length * 8 and
                 Ctx_Mac_Size (This) = Mac_Size);

   --
   --  Setup_Nonce
   --
   procedure Setup_Nonce (This  : in out Context;
                          Nonce : in     Nonce_Stream) with
     Depends => (This => (This,
                          Nonce)),
     Pre     => (Nonce'Length = Max_Nonce_Size / 8),
     Post    => (Ctx_I (This) = 8                              and
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old) and
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old) and
                 Ctx_AAD_Len (This) = 0                        and
                 Ctx_Msg_Len (This) = 0);

   --
   --  Process_AAD
   --
   procedure Process_AAD (This    : in out Context;
                          Aad     : in     Plaintext_Stream) with
     Depends => (This => (This,
                          Aad)),
     Pre     => (Aad'First in Stream_Index and then -- FIXME: Precondition is implicit, but without that the proof fails.
                 Ctx_AAD_Len (This) mod 4 = 0 and then --  can only make ONE sub-word call!
                 Ctx_AAD_Len (This) < Stream_Count'Last - Aad'Length),
     Post    => (Ctx_AAD_Len (This) = Ctx_AAD_Len (This'Old) + Aad'Length and then
                 Ctx_Msg_Len (This) = Ctx_Msg_Len (This'Old)              and then
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old)            and then
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old));

   --
   --  Encrypt_Bytes
   --
   procedure Encrypt_Bytes (This        : in out Context;
                            Source      : in     Plaintext_Stream;
                            Destination :    out Ciphertext_Stream) with
     Depends => (This        => (This,
                                 Source),
                 Destination => (This,
                                 Destination,
                                 Source)),
     Pre     => ((Source'First in Stream_Index and Destination'First in Stream_Index) and
                 --  implicit, but needed for proof
                 Source'Length = Destination'Length and
                 Ctx_Msg_Len (This) mod 4 = 0), --  Can only make ONE sub-word call!
     Post    => (Ctx_AAD_Len (This) = Ctx_AAD_Len (This'Old)                 and then
                 Ctx_Msg_Len (This) = Ctx_Msg_Len (This'Old) + Interfaces.Unsigned_32 (Source'Length mod 2 ** 32) and then
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old)               and then
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old));

   --
   --  Decrypt_Bytes
   --
   procedure Decrypt_Bytes (This        : in out Context;
                            Source      : in     Ciphertext_Stream;
                            Destination :    out Plaintext_Stream) with
     Depends => (This        => (This,
                                 Source),
                 Destination => (Destination,
                                 This,
                                 Source)),
     Pre     => (((Source'First in Stream_Index and Destination'First in Stream_Index) and
                  --  FIXME: implicit, but needed for proof
                  Source'Length = Destination'Length) and then
                 Ctx_Msg_Len (This) mod 4 = 0),
     Post    => (Ctx_AAD_Len (This) = Ctx_AAD_Len (This'Old)                                                      and then
                 Ctx_Msg_Len (This) = Ctx_Msg_Len (This'Old) + Interfaces.Unsigned_32 (Source'Length mod 2 ** 32) and then
                 Ctx_Key_Size (This) = Ctx_Key_Size (This'Old)                                                    and then
                 Ctx_Mac_Size (This) = Ctx_Mac_Size (This'Old));

   --
   --  Finalize
   --
   procedure Finalize (This : in     Context;
                       Mac  :    out MAC_Stream) with
     Depends => (Mac  => (Mac, -- This isn't exactly True, but SPARK insists, probably because we rely on Mac'Length
                          This)),
     Pre     => (Ctx_Mac_Size (This) <= Max_MAC_Size and
                 Mac'Length = Stream_Count (Ctx_Mac_Size (This) / 8));

private

   type Mod_8 is mod 8;

   subtype Full_State_Words is Mod_8 range 0 .. 4; --  5 state words
   subtype Old_State_Words  is Mod_8 range 0 .. 3; --  4 old state words

   type Unsigned_32_Array is array (Mod_8 range <>) of Interfaces.Unsigned_32;

   --  Several state arrays (old Z, state words, expanded key.
   subtype Old_Z_4        is Unsigned_32_Array (Old_State_Words);
   subtype State_Words    is Unsigned_32_Array (Full_State_Words);
   subtype Key_Processing is Unsigned_32_Array (Mod_8);

   type Key_Schedule is
      record
         Key_Size : Key_Size_32;             --  Initial Key Size, in Bits : 64 .. 256
         MAC_Size : MAC_Size_32;             --  Mac Tag     Size, in Bits : 64 .. 128
         X_1_Bump : Interfaces.Unsigned_32;  --  4 * (keySize / 8) + 256 * (macSize mod 128)
         X_0      : Key_Processing;
         X_1      : Key_Processing;          --  processed working key material
      end record;

   type Cipher_State is
      record
         Old_Z   : Old_Z_4;                --  Previous four Z_4 values for output
         Z       : State_Words;            --  5 internal state words (160 bits)
         AAD_Len : Stream_Count;           --  64-bit aadLen counter (LSW first)
         I       : Interfaces.Unsigned_32; --  Block number (modulo 2 ** 32!)
         Msg_Len : Interfaces.Unsigned_32; --  low 32 bits of msgLen
         AAD_Xor : Interfaces.Unsigned_32; --  aadXor constant
      end record;

   type Context is
      record
         KS : Key_Schedule;
         CS : Cipher_State;
      end record;

   --  Proof functions

   function Ctx_AAD_Len (Ctx : Context) return Stream_Count is
     (Ctx.CS.AAD_Len);

   function Ctx_I (Ctx : Context) return Interfaces.Unsigned_32 is
     (Ctx.CS.I);

   function Ctx_Key_Size (Ctx : Context) return Key_Size_32 is
     (Ctx.KS.Key_Size);

   function Ctx_Mac_Size (Ctx : Context) return MAC_Size_32 is
     (Ctx.KS.MAC_Size);

   function Ctx_Msg_Len (Ctx : Context) return Interfaces.Unsigned_32 is
     (Ctx.CS.Msg_Len);

end Crypto.Phelix;
