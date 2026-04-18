Simplified AES and the Project Cryptanalysis Workflow

Introduction

This project focuses on understanding how a simplified block cipher works in practice, not just at a theoretical level. Instead of only describing S-AES, the goal was to actually implement it from scratch, test it, and then try to break it using realistic attack methods.
What makes this project interesting is that it does not stop at the cipher itself. It also includes:
	A working Python implementation of S-AES 
	A CCM-style encryption system to make it usable on real data 
	A brute-force attacker that tests all possible keys 
	A second attack method for ciphertexts that do not include authentication 
This combination makes the project more realistic, because it shows both sides:
how encryption is built, and how it can be attacked.
The supplied project brief asks for more than a basic description of S-AES. It combines the core cipher with a practical implementation story: a Python S-AES module, a CCM-style wrapper for authenticated encryption, a brute-force attacker for internal testing, and a second attack path for CTR-style ciphertexts received from other groups. In other words, the report has to explain both the cipher itself and the logic of attacking it in a realistic classroom setting. fileciteturn1file0
S-AES exists for teaching. Musa, Schaefer, and Wedig introduced it as a drastically reduced version of AES so that students could work through the algorithm by hand without losing the main ideas of the real cipher. Holden’s teaching notes make the same point in simpler terms: S-AES keeps the AES structure, but reduces the block size to 16 bits, the key size to 16 bits, and the round count to 2. By contrast, standardized AES uses a 128-bit block and 128-, 192-, or 256-bit keys. (Musa 2003; Holden; NIST FIPS 197). [1]
That difference in scale completely changes the security picture. In real AES, exhaustive search is not practical. In S-AES, the entire keyspace is only 2^16=65,536 keys, so brute force is not a fallback attack; it is the obvious baseline attack. The project’s cryptanalysis section is therefore well aimed: the important question is not whether S-AES can be broken, but how the implementation details of the surrounding mode of operation help an attacker test candidate keys more efficiently. (Holden; NIST SP 800-38A; NIST SP 800-38C). [2]
The report below does two things. First, it explains the S-AES core clearly: state layout, round flow, SubNib, ShiftRows, MixColumns, and key expansion. Second, it analyzes the project’s four-stage workflow: methodology and threat model, CCM-style wrapping, self-cryptanalysis with a known internal key, and a separate heuristic attack path for external CTR ciphertexts. The main analytical conclusion is straightforward: the project is strongest when it presents S-AES honestly as an instructional cipher and the CCM/CTR code as an educational wrapper around a deliberately weak primitive, not as a secure modern design. (Holden; Musa 2003; NIST SP 800-38A; NIST SP 800-38C). [3]
S-AES in context
S-AES should be understood as a miniature version of AES, not as an unrelated toy. The same broad structure is preserved: a plaintext block is placed into a state array, transformed by substitution and permutation layers, mixed linearly, and combined with round keys. Musa’s original paper emphasizes that the design goal was to shrink AES “as much as possible without losing the essence of the algorithm,” and Holden’s classroom notes state the same point more directly: structurally, S-AES is “exactly the same as AES,” but with much smaller parameters. (Musa 2003; Holden). [4]
That is why the term simplified matters. It does not mean “careless” or “roughly inspired by AES.” It means that the educational version retains the four ideas that matter most in AES-style block ciphers: nonlinearity from the S-box, diffusion from row shifting and column mixing, round-key injection, and a separate key schedule that expands a short master key into round keys. In a classroom or project report, this matters because it lets the writer explain genuine AES-style design logic in a manageable setting. (Musa 2003; Holden). [4]
A direct comparison makes the scaling clear:
Feature	Standard AES	S-AES
Block size	128 bits	16 bits
Key sizes	128, 192, 256 bits	16 bits
State shape	4×4 bytes	2×2 nibbles
Round count	10, 12, 14	2
Purpose	Real-world standardized encryption	Teaching and analysis
This comparison follows NIST’s AES standard for real AES and Holden’s S-AES summary for the simplified version. (Holden; NIST FIPS 197). [5]
For the project, that comparison also explains the cryptanalytic threat model. Real AES is designed so that brute-force search is computationally unrealistic. S-AES is deliberately not. Once the key is only 16 bits, the security ceiling collapses: the attacker can simply try every key. That does not make the project trivial, though. It changes the focus from “Can the cipher be broken?” to “How do mode design, authentication checks, and plaintext structure affect how quickly the correct key is identified?” That is exactly the direction taken in the supplied project outline. fileciteturn1file0
State layout and encryption flow
S-AES encrypts a 16-bit plaintext block. Instead of AES’s 4×4 byte state, S-AES arranges the data into a 2×2 state of nibbles. Holden states this explicitly: S-AES “divides it into a two by two array of nibbles,” each nibble being 4 bits long. (Holden). [6]
Using the usual notation, the four nibbles N_0,N_1,N_2,N_3 are pictured as a small state matrix:
16-bit block = N0 N1 N2 N3

State =
[ N0  N2 ]
[ N1  N3 ]
This 2×2 layout is the simplified analogue of AES’s 4×4 state and is the reason the later ShiftRows step is so simple: the first row stays fixed, while the second row only has two positions, so shifting it is effectively a swap. (Holden; Sandilands). [7]
The required encryption flow for the report is:
initial AddRoundKey(K0) → Round 1 (SubNib, ShiftRows, MixColumns, AddRoundKey(K1)) → Round 2 (SubNib, ShiftRows, AddRoundKey(K2))
That exact structure is consistent with the teaching notes: there is an initial key-addition step, then a main round, then a final round, and the final round omits MixColumns. Holden notes explicitly that the mix-column transformation is omitted in the last round to simplify decryption. (Holden; Sandilands). [8]
The operations themselves are small but important. AddRoundKey is just bitwise XOR between the state and the current round key. SubNib applies the S-box to each nibble. ShiftRows keeps the top row unchanged and shifts the bottom row, which in this 2×2 setting means swapping the second and fourth nibbles in the linear view. MixColumns multiplies each column by a fixed matrix over GF(16), which spreads local nibble changes into both entries of the column. (Holden; Sandilands). [9]
A compact way to express the round flow is the following mermaid diagram:
flowchart TD
    P[Plaintext 16-bit] --> AK0[AddRoundKey K0]
    AK0 --> SN1[SubNib]
    SN1 --> SR1[ShiftRows]
    SR1 --> MC1[MixColumns]
    MC1 --> AK1[AddRoundKey K1]
    AK1 --> SN2[SubNib]
    SN2 --> SR2[ShiftRows]
    SR2 --> AK2[AddRoundKey K2]
    AK2 --> C[Ciphertext 16-bit]
This diagram matches the textbook S-AES flow described in the educational sources. (Holden; Sandilands). [10]
The ShiftRows mapping is especially easy to state in a report because there are only four nibbles. In linear nibble order, the row shift can be written as:
SR(N_0 N_1 N_2 N_3 )=N_0 N_3 N_2 N_1
That is just another way of saying “swap the second and fourth nibbles,” which is how Sandilands explains it in the worked example. (Sandilands). [11]
MixColumns is the part students often find most abstract, but conceptually it is only a fixed linear transformation over a finite field. Holden gives the encryption matrix as
[■(1&4@4&1)]
with operations performed in GF(16), where the value 4 corresponds to the polynomial x^2, and reductions are taken modulo x^4+x+1. He also notes that the last round omits this step. (Holden). [12]
That field detail matters for the project because it is what separates S-AES from a simple bit-shuffling exercise. The substitution layer provides nonlinearity; MixColumns provides structured diffusion. Together, they make S-AES a faithful small-scale model of AES design, even though the total parameter sizes are far too small for real security. (Musa 2003; Holden). [4]
SubNib and the S-box
The S-box is the heart of S-AES. Without it, the cipher would be built from XORs and linear transformations only, which would make it easy to solve algebraically. Holden explains its construction in the usual AES style: a 4-bit nibble is interpreted as a polynomial over GF(2), inverted in GF(16) using the irreducible polynomial x^4+x+1, and then passed through an affine transformation. In real code, however, nobody recomputes this algebra every time; the S-box is implemented as a lookup table. (Holden). [13]
At the state level, SubNib means that each nibble is replaced independently by its S-box output. If the input state is viewed linearly as N_0 N_1 N_2 N_3, then:
SubNib(N_0 N_1 N_2 N_3 )=S(N_0 ) S(N_1 ) S(N_2 ) S(N_3 )
The positions stay the same; only the nibble values change. This matches both the formal S-AES descriptions and Sandilands’ worked example, where each nibble is substituted independently before the ShiftRows step. (Sandilands; Holden). [14]
The standard S-AES S-box in hexadecimal is:
Input	0	1	2	3
0	9	4	A	B
1	D	1	8	5
2	6	2	0	3
3	C	E	F	7
Read row and column as a compact arrangement of inputs 0 through F. In simple mapping form, for example, 0↦9, 1↦4, A↦0, and F↦7. This table is the same as the published S-AES lookup table in Holden’s notes and the teaching literature built around Musa’s design. (Holden). [15]
The inverse S-box is just the reverse mapping. Since the forward S-box is a permutation of the 16 nibble values, decryption can undo the substitution by swapping inputs and outputs. The inverse table in hexadecimal is therefore:
Input	0	1	2	3
0	A	5	9	B
1	1	7	8	F
2	6	0	2	3
3	C	4	D	E
This inverse table is obtained by reversing the published forward S-box mapping. For instance, because the forward table sends A to 0, the inverse table sends 0 back to A. (Holden). [15]
A small lookup example is enough to show how SubNib works in practice. From the S-box table, S(A)=0, S(D)=E, S(1)=4, and S(F)=7. So if a state contains the nibble sequence A,D,1,F, the SubNib output contains 0,E,4,7 in the same positions. The value changes happen first; movement happens later in ShiftRows. (Holden; Sandilands). [16]
It is also important to separate two uses of the phrase SubNib in a project report. In the encryption round, SubNib acts on the full 16-bit state, nibble by nibble. In the key schedule, SubNib acts on an 8-bit word after RotNib, which means it substitutes two nibbles inside a byte-sized word rather than the whole state. Sandilands states this explicitly in the worked key schedule: SubNib in key expansion means “apply S-box substitution on nibbles using encryption S-box.” (Sandilands). [17]
That distinction matters in code. If the implementation confuses state-level substitution with key-schedule substitution, the round keys will be wrong even if the round function itself is correct. For a report intended to accompany code, this is worth stating clearly because it shows that the writer understands both the algorithm and the implementation boundary between the round function and the key expansion logic. (Sandilands; Holden). [18]
Key expansion and round keys
S-AES starts from a 16-bit master key and expands it into three 16-bit round keys: K_0, K_1, and K_2. The teaching notes usually do this by splitting the input key into two 8-bit words, w_0 and w_1, and then generating four more words w_2,w_3,w_4,w_5. Sandilands presents this in exactly the form most programming assignments use. (Sandilands). [19]
The initial split is simple:
w_0="left byte of the 16-bit key",  w_1="right byte of the 16-bit key" 
The first round key is just the original key written as the two initial words:
K_0=w_0∥w_1
After that, the remaining words are generated by XORing prior words with a transformed version of the previous word and a round constant. (Sandilands). [19]
The two helper functions are:
RotNib(N_0 N_1 )=N_1 N_0
which swaps the two nibbles in an 8-bit word, and
SubNib(N_0 N_1 )=S(N_0 )S(N_1 )
which substitutes each nibble using the same encryption S-box. Sandilands states both points directly: RotNib is “rotate the nibbles,” which is equivalent to swapping them, and SubNib uses the encryption S-box on each nibble. (Sandilands). [17]
The two round constants used in standard S-AES key expansion are:
Rcon_1=0x80,  Rcon_2=0x30
These are the byte forms of the nibble round constants used in the two expansion stages and match the classroom key schedule formulas. (Sandilands). [20]
The explicit word formulas are:
w_2=w_0⊕Rcon_1⊕SubNib(RotNib(w_1 ))
w_3=w_2⊕w_1
w_4=w_2⊕Rcon_2⊕SubNib(RotNib(w_3 ))
w_5=w_4⊕w_3
and then the remaining round keys are formed as
K_1=w_2∥w_3,  K_2=w_4∥w_5
This is the compact version of the exact calculations shown in Sandilands’ key-generation example. (Sandilands). [21]
Because no separate sample key was formally supplied for the key expansion section of this report, the most careful way to present the schedule is symbolically. The only explicit key mentioned in the project brief, 0xABCD, appears in the brute-force simulation description, not as a worked key-schedule example for the report itself. fileciteturn1file0
The symbolic schedule is therefore:
Quantity	Symbolic value
Input key	unspecified 16-bit key K
Split	w_0=K[15:8], w_1=K[7:0]
w_2	w_0⊕0x80⊕SubNib(RotNib(w_1 ))
w_3	w_2⊕w_1
w_4	w_2⊕0x30⊕SubNib(RotNib(w_3 ))
w_5	w_4⊕w_3
K_0	w_0∥w_1
K_1	w_2∥w_3
K_2	w_4∥w_5
This symbolic table follows the standard classroom formulas and satisfies the requirement not to invent a worked numeric key where none was supplied for that part of the report. (Sandilands). [21]
A concise pseudocode version of the key schedule is:
SBOX = [9,4,A,B,D,1,8,5,6,2,0,3,C,E,F,7]

RotNib(x):
    return swap_high_and_low_nibbles(x)

SubNibByte(x):
    hi = high_nibble(x)
    lo = low_nibble(x)
    return SBOX[hi] || SBOX[lo]

KeyExpansion(K):
    w0 = high_byte(K)
    w1 = low_byte(K)

    w2 = w0 XOR 0x80 XOR SubNibByte(RotNib(w1))
    w3 = w2 XOR w1
    w4 = w2 XOR 0x30 XOR SubNibByte(RotNib(w3))
    w5 = w4 XOR w3

    K0 = w0 || w1
    K1 = w2 || w3
    K2 = w4 || w5
    return K0, K1, K2
This pseudocode is just the direct programming form of the Sandilands formulas. (Sandilands). [21]
The full encryption can be written just as compactly:
Encrypt(P, K):
    K0, K1, K2 = KeyExpansion(K)

    state = P XOR K0

    state = SubNib(state)
    state = ShiftRows(state)
    state = MixColumns(state)
    state = state XOR K1

    state = SubNib(state)
    state = ShiftRows(state)
    state = state XOR K2

    return state
The logic here matches the standard S-AES flow: initial AddRoundKey, one full round, and a final round without MixColumns. (Holden; Sandilands). [8]
Protocol application and cryptanalysis strategy
The project brief divides the implementation into four practical stages: a methodology and attack model, a CCM-style protocol wrapper around the S-AES core, self-cryptanalysis using a known internal test key, and a separate attack strategy for external CTR ciphertexts. It also closes with engineering deliverables: modular code, comments, a README, and no external packages. That overall shape is sound for a classroom cryptography project because it shows not only how the cipher works, but how the cipher behaves once embedded in a protocol and then attacked. fileciteturn1file0
The first stage, the threat model, is the easiest to justify analytically. Once the cipher key is only 16 bits, exhaustive search over all 65,536 keys becomes fully practical. In that setting, advanced cryptanalytic ideas are still educationally useful, but brute force is the decisive attack in practice. The project brief captures that basic fact correctly, even if some of its wording is overly dramatic. The report should say this plainly: the short key is the real weakness, and the short block size makes long-message use fragile as well. (Holden). [22]
The block size matters almost as much as the key size. NIST’s CTR recommendation requires every counter block under a given key to be unique, and it warns that reusing a counter block can compromise confidentiality immediately. In real AES, 128-bit counters make that manageable. In S-AES, the full block is only 16 bits, so the space of distinct counter blocks is tiny by modern standards. Even before brute force is considered, that makes any CTR-style construction fragile for large volumes of data or poor nonce management. (NIST SP 800-38A; Holden). [23]
The second stage in the brief is the protocol wrapper. This idea is sensible. A raw block cipher should not be used directly on files; it needs a mode of operation to handle arbitrary-length input, and it often needs an authentication layer as well. NIST SP 800-38A defines CTR mode as encrypting counters with the forward block cipher and XORing the resulting keystream with plaintext or ciphertext. NIST SP 800-38C defines CCM as a combined authenticated-encryption mode built from CTR for confidentiality and CBC-MAC for authenticity. (NIST SP 800-38A; NIST SP 800-38C). [24]
That said, the report should be precise about terminology. Standard NIST CCM is specified for block ciphers with a 128-bit block size, such as AES, and the NIST text says directly that CCM is based on an approved block cipher “whose block size is 128 bits.” So if the project adapts the CCM logic to a 16-bit S-AES core, that implementation should be described as a CCM-style educational adaptation, not as standards-compliant CCM proper. This does not weaken the project; it actually makes the write-up more accurate. (NIST SP 800-38C). [25]
The brief’s “verification protocol” is also easy to place in formal terms. NIST’s CCM specification says that decryption-verification checks the MAC and returns either the recovered payload or the error message INVALID; when verification fails, the payload is not returned. That means a guessed key can be tested very efficiently: decrypt under the candidate key, recompute or verify the tag, and reject the key immediately if the tag check fails. In the project notes, this idea is labeled “Authentication Bypass (CCM),” but analytically that label is misleading. It is not an authentication bypass; it is better described as tag-assisted key testing during exhaustive search. (NIST SP 800-38C; project brief). [26] fileciteturn1file0
NIST also gives a useful caution here. The CCM document states that the probability a single inauthentic ciphertext passes verification is no greater than 1/2^Tlen, where Tlen is the tag length, and it recommends limiting repeated INVALID trials in a deployment. In real systems, this is a warning about forgery probability and protocol abuse. In the toy S-AES setting, it is a reminder that MAC-based rejection is a powerful filter, but the overall security ceiling is still dominated by the tiny keyspace. (NIST SP 800-38C). [27]
The project’s self-cryptanalysis stage follows this logic closely. The brief says the internal test harness encrypts using key 0xABCD, then runs an attacker script that checks all 65,536 keys. That experiment makes sense. For a 16-bit cipher, a complete search is expected, and a correct implementation should recover the original key or plaintext once the search reaches the right candidate. When a CCM-style tag is present, most wrong keys are filtered immediately by verification failure. fileciteturn1file0
The more interesting part of the brief is the second attack path: ciphertexts that come from other groups in CTR mode without a MAC. This is where the “frequency print heuristic” enters. In that case, there is no authentication tag to act as a decisive oracle, so the attacker has to rank trial decryptions using structure in the plaintext: printable-text ratio, known headers, file signatures, or any other recognizable formatting. That is a reasonable classroom approach, especially if the likely plaintexts are text-heavy. But the report should present it carefully: printable-text scoring is a heuristic, not a proof of correctness. It works best when the underlying message format is strongly constrained. (Project brief; NIST SP 800-38A). fileciteturn1file0 [28]
The supplied notes also say the attacker utility was expanded to accept raw binary, hexadecimal, and Base64 input. That is a practical engineering improvement, not a cryptanalytic one, but it is still worth mentioning because it makes the attack tool usable across different team outputs. In a report, that point is stronger if phrased plainly: the decoding layer broadens the input surface; the real recovery logic is still exhaustive search plus either MAC verification or plaintext-structure scoring. fileciteturn1file0
A compact way to summarize the project’s two attack settings is:
Scenario	What the attacker gets	What makes key testing effective	Main limitation
CCM-style S-AES wrapper	Ciphertext plus encrypted MAC/tag	Wrong keys fail verification and are rejected quickly	Educational adaptation only; not standard CCM because S-AES has 16-bit blocks
CTR-only S-AES target	Ciphertext without tag	Wrong keys are ranked by plaintext structure, printable ratio, or known format cues	No built-in authenticity check; heuristic false positives are possible
This table combines the project brief’s attack design with NIST’s definitions of CTR and CCM. (Project brief; NIST SP 800-38A; NIST SP 800-38C). fileciteturn1file0 [29]
Practical Impact of Brute Force
Although brute force is usually considered a last resort in cryptanalysis, in this project it becomes the main attack method. This is because the total number of keys is extremely small.
Testing all 65,536 keys is not only possible, but very fast on modern machines. The interesting part is not the attack itself, but how quickly incorrect keys can be rejected.
With CCM: wrong keys fail immediately due to MAC mismatch 
Without CCM: wrong keys must be filtered using heuristics 
This difference shows how authentication can affect attack efficiency, even when it does not increase the actual security of the cipher.

The brief’s comments about file and image handling also fit naturally into this analysis. CTR is often chosen for file processing because it behaves like a stream construction built from a block cipher: the keystream is XORed with the data, partial last blocks are naturally supported, and encryption and decryption both use the forward cipher. NIST says explicitly that CTR decryption also uses the forward cipher on the counters, then XORs with the ciphertext. For binary payloads such as images, that behavior is convenient. The caveat, again, is that with a 16-bit block cipher, counter management becomes very tight and misuse becomes much easier. (NIST SP 800-38A; NIST SP 800-38C). [30]

Limitations of the System
There are several important limitations in this project that should be clearly understood.
First, the key size is extremely small. This makes brute-force attacks trivial and means the system cannot be considered secure.
Second, the block size is also very small. In modes like CTR, this creates problems because the number of possible counter values is limited. Reusing counters can lead to serious security issues.
Third, the heuristic-based attack for CTR ciphertexts is not guaranteed to work in all cases. It depends on the structure of the plaintext, and may fail if the data is random or compressed.
These limitations are expected, since S-AES is not meant for real security, but they are still important to acknowledge.

Finally, the deliverables section of the brief is worth keeping because it signals software quality: the code is described as modular, commented, locally testable, documented in a README, and free of external crypto packages. For a teaching project, that is good practice. It makes the cryptographic logic inspectable and makes the self-cryptanalysis reproducible, which is exactly what an academic reader or instructor wants to see. 

Assessment and conclusion
Taken as a whole, the material supports a clear and honest analytical position. S-AES is valuable because it lets a student explain the same architectural ideas that appear in real AES—state transformation, S-box nonlinearity, row shifting, column mixing, and key scheduling—without the full complexity of a real 128-bit standard cipher. That is why Musa’s design and Holden’s notes remain useful teaching sources. At the same time, the tiny 16-bit block and 16-bit key make exhaustive search the practical attack of first resort, which means any surrounding protocol story must be evaluated in that light. (Musa 2003; Holden; NIST FIPS 197). [1]
For the project itself, the strongest write-up is not one that overstates the attack as a dramatic break. It is one that shows control of the full picture. The S-AES core should be explained carefully and correctly. The CCM-style wrapper should be presented as an educational adaptation of the NIST idea, not as standard CCM. The brute-force result should be framed as the natural consequence of a 16-bit keyspace. And the external CTR attack should be described as exhaustive search guided by heuristics when no MAC is available. That framing is technically accurate, academically cleaner, and more convincing than inflated language about “bypass” or “guaranteed deterministic recovery.” (NIST SP 800-38A; NIST SP 800-38C; project brief). [29] fileciteturn1file0
If presented that way, the report does exactly what a good cryptography project report should do: it shows understanding of the algorithm, awareness of the difference between a teaching cipher and a deployment cipher, and a realistic discussion of how protocol choices affect attack practicality once the primitive underneath is intentionally weak. (Holden; Musa 2003; Sandilands). [31]
________________________________________
[1] [4] https://s-aes-proyect.readthedocs.io/es/latest/files/musa2003%20%28S-AES%29.pdf
https://s-aes-proyect.readthedocs.io/es/latest/files/musa2003%20%28S-AES%29.pdf
[2] [3] [5] [6] [7] [8] [9] [10] [12] [13] [15] [16] [22] [31] https://www.rose-hulman.edu/class/ma/holden/Archived_Courses/Math479-0304/lectures/s-aes.pdf
https://www.rose-hulman.edu/class/ma/holden/Archived_Courses/Math479-0304/lectures/s-aes.pdf
[11] [14] [17] [18] [19] [20] [21] https://sandilands.info/sgordon/teaching/reports/simplified-aes-example.pdf
https://sandilands.info/sgordon/teaching/reports/simplified-aes-example.pdf
[23] [24] [28] [30] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
[25] [26] [27] [29] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
