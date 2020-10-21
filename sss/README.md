# TO BE PLACED IN PR

## purpose

* publicly verifiable secret sharing for the backup phrase for an account

*inspiration*
* [PVSS by Berry Schoenmakers](https://www.win.tue.nl/~berry/papers/crypto99.pdf)
* [SLIP0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)

## Safe Secret Sharing Client (TODO)
1. encrypt secret with dealer's key
2. split (encrypted) secret into n shares s.t. t<=n can reconstruct
3. commit to hash of shares using substrate (start round)
4. encrypt each share with public key for recipient and send to each member (strobe)
5. holders decrypt their shares and report the decrypted value to verify if it is the preimage of the hash on-chain