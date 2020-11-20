# Sign-verify-and-Authenticate
CIA triade. signing, verifying and authentication assignment.

Takes an input file and Studentnummer, writes the SHA256 sum to studentnummer.hash, signs this hash value with generated privatekey (RSA),
Writes the value to studentnummer.sign 
The input file will be encrypted using a session key (AES) and writen to studentnummer.code
This session key is then encrypted with the public key of the assignment giver.

Confidentiality, Authentication, Integrity and non-repudiation.
