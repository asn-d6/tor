# This is a reference implementation of the SRV calculation for prop250. We use
# it to generate a test vector for the test_sr_compute_srv() unittest.
#
# Here is the SRV computation formula:
#
#      HASHED_REVEALS = H(ID_a | R_a | ID_b | R_b | ..)
#
#      SRV = HMAC(HASHED_REVEALS,
#                "shared-random" | INT_8(reveal_num) | INT_8(version) |
#                previous_SRV)
#

import hmac
import hashlib

# Identity and reveal value of dirauth a
ID_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" # 43 base64 characters
R_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" # 56 base64 characters

# Identity and reveal value of dirauth b
ID_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" # 43 base64 characters
R_b = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" # 56 base64 characters

# Identity and reveal value of dirauth c
ID_c = "ccccccccccccccccccccccccccccccccccccccccccc" # 43 base64 characters
R_c = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" # 56 base64 characters

# Concatenate them all together and hash them to form HASHED_REVEALS.
# This is the key of the HMAC.
REVEALS = ID_a + R_a + ID_b + R_b + ID_c + R_c
hashed_reveals_object = hashlib.sha256(REVEALS)
hashed_reveals = hashed_reveals_object.digest()

# Now form the message of the HMAC
previous_SRV = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
HMAC_msg = "shared-random" + "\x03" + "\x01" + previous_SRV

# Now calculate the HMAC
dig = hmac.new(hashed_reveals, HMAC_msg, digestmod=hashlib.sha256)
print "Result: %s" % dig.hexdigest().upper()

# Result: BD2D7C0D3F9680585828389C787E3D478C3DDFCD1EB39E42A9D7B49D1ABCB7FC

