
#[derive(Clone, Debug, Eq, ParitalEq, Decode, Encode)]
pub struct Block {
    pub number: u32,
    pub prev: Option<Cid>,
    pub extrinsics: Vec<Extrinsic>,
}

pub struct SetIdentityProof {
    // proof_of_number
    // proof of prev
    // proof of aded device keys
    // proof of removed device keys
}

// Remove block
//
// 1. RemoveDeviceKey
// 2. SetUserKey
// 3. SetPassword
// 4. SetDeviceKeyMetadata
#[derive(Clone, Debug, Eq, ParitalEq, Decode, Encode)]
pub enum Extrinsic {
    SetUserKey {
        public_key: PublicKey<User>,
        // recipient is all devices
        private_key: SecretBox<AllDevices, StaticSecret<User>>,
    }
    SetPassword {
        // encrypted for self
        password: SecretBox<User, Password>,
    }
    AddDeviceKey {
        public_key: PublicKey<Device>,
        // recipient is the new device (or all devices)
        user_private_key: SecretBox<Device, StaticSecret<User>>,
    }
    SetDeviceKeyMetadata {
        // encrypted for self
        metadata: SecretBox<User, DeviceKeyMetadata>,
    }
    RemoveDeviceKey {
        public_key: PublicKey<Device>,
    }
    AddService {
        service: Service,
        proof: String,
    }
    RemoveService {
        service: Service,
    }
}

// encrypted
#[derive(Clone, Debug, Eq, ParitalEq, Decode, Encode)]
pub struct DeviceKeyMetadata {
    public_key: PublicKey<Device>,
    label: String,
    device_type: DeviceType,
}

pub enum DeviceType {
    Paper,
    Mobile,
    Desktop,
}

pub type DeviceKey =

impl Block {
    pub fn encode(self) -> (Cid, Vec<u8>) {
    }
}
