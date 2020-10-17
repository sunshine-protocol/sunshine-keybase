//! Secret Sharing Client
//! 1. encrypt secret with dealer's key
//! 2. split (encrypted) secret into n shares s.t. t<=n can reconstruct
//! 3. commit to hash of shares using substrate (start round)
//! 4. encrypt each share with public key for recipient and send to each member (strobe)
//! 5. holders report whether committed hash matches secret share for fault tolerance
