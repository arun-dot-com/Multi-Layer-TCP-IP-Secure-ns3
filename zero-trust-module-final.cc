#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h" 
#include <cassert>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <oqs/oqs.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h> 
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>

#include "ns3/netanim-module.h"
#include <cryptopp/sha.h>
#include "ns3/applications-module.h"
#include "ns3/onoff-application.h"
#include <cryptopp/hmac.h>
#include <iomanip>

#include <cryptopp/hex.h>
#include "ns3/wifi-phy.h"
#include "ns3/tag.h"
#include "ns3/warnings.h"

#include <iomanip>
#include <set>



using namespace ns3;
using namespace CryptoPP;

NS_LOG_COMPONENT_DEFINE("WifiAdhocNodes");
std::set<uint32_t> removedDrones;  // Declare globally

void SuppressWarnings() {
    if (freopen("/dev/null", "w", stderr) == nullptr) {
        std::cerr << "Warning suppression failed!" << std::endl;
    }
}
struct Drone {
    std::string id;
    std::vector<uint8_t> dilithiumPublicKey;
    std::vector<uint8_t> dilithiumPrivateKey;
    std::vector<uint8_t> kyberPublicKey;
    std::vector<uint8_t> kyberPrivateKey;
    std::string aesKey;
};

// Global key registry for tracking authenticated drones
std::map<std::string, Drone> keyRegistry;

// Generate Dilithium Key Pair (Authentication)
Drone GenerateDilithiumKeyPair(const std::string& id) {
    Drone drone;
    drone.id = id;

    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (!sig) {
        NS_FATAL_ERROR("Failed to initialize Dilithium-3");
    }

    drone.dilithiumPublicKey.resize(sig->length_public_key);
    drone.dilithiumPrivateKey.resize(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, drone.dilithiumPublicKey.data(), drone.dilithiumPrivateKey.data()) != OQS_SUCCESS) {
        NS_FATAL_ERROR("Dilithium key pair generation failed");
    }

    OQS_SIG_free(sig);
    return drone;
}


// Expected RSSI range for drones (Pre-registered RF fingerprints)
std::map<std::string, double> rssiThresholds = {
    {"node-1", -50.0},  // Expected RSSI (in dBm) for drone-1
    {"node-2", -55.0},  // Expected RSSI for drone-2
    {"node-3", -60.0}   // Expected RSSI for drone-3
};

// Allowed variation in RSSI for authentication
const double RSSI_TOLERANCE = 5.0;  
std::string ByteArrayToHexString(const unsigned char* byteArray, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byteArray[i];
    }
    return ss.str();
}

void AuthenticateUsingRssi(std::string droneId, double receivedRssi) {
    if (rssiThresholds.find(droneId) == rssiThresholds.end()) {
        std::cout << "[SECURITY ALERT] Unknown node detected: " << droneId << std::endl;
        return;
    }

    double expectedRssi = rssiThresholds[droneId];
    if (std::abs(receivedRssi - expectedRssi) > RSSI_TOLERANCE) {
        std::cout << "[SECURITY ALERT] Possible spoofing detected for " << droneId 
                  << " (Expected RSSI: " << expectedRssi << ", Received RSSI: " << receivedRssi << ")" << std::endl;
    } else {
        std::cout << "[SECURITY] " << droneId << " authenticated successfully based on RSSI." << std::endl;
    }
}

// Generate Kyber Key Pair (Key Exchange)
void GenerateKyberKeyPair(Drone& drone) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) {
        NS_FATAL_ERROR("Failed to initialize Kyber-1024");
    }

    drone.kyberPublicKey.resize(kem->length_public_key);
    drone.kyberPrivateKey.resize(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, drone.kyberPublicKey.data(), drone.kyberPrivateKey.data()) != OQS_SUCCESS) {
        NS_FATAL_ERROR("Kyber key pair generation failed");
    }

    OQS_KEM_free(kem);
}

// Perform Kyber Key Exchange to derive a shared AES key
std::string PerformKyberKeyExchange(const Drone& sender, const Drone& receiver) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) {
        NS_FATAL_ERROR("Failed to initialize Kyber-1024 for key exchange");
    }

    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> sharedSecretSender(kem->length_shared_secret);
    std::vector<uint8_t> sharedSecretReceiver(kem->length_shared_secret);

    // Sender encrypts using receiver's public key
    if (OQS_KEM_encaps(kem, ciphertext.data(), sharedSecretSender.data(), receiver.kyberPublicKey.data()) != OQS_SUCCESS) {
        NS_FATAL_ERROR("Kyber encapsulation failed");
    }

    // Receiver decrypts to obtain the shared secret
    if (OQS_KEM_decaps(kem, sharedSecretReceiver.data(), ciphertext.data(), receiver.kyberPrivateKey.data()) != OQS_SUCCESS) {
        NS_FATAL_ERROR("Kyber decapsulation failed");
    }

    OQS_KEM_free(kem);
    
    // Hash the shared secret with SHA-256 and truncate to 16 bytes for AES-128
    CryptoPP::SHA256 hash;
    std::string hashedKey;
    CryptoPP::StringSource(sharedSecretReceiver.data(), sharedSecretReceiver.size(), true,
        new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(hashedKey)));

    return hashedKey.substr(0, AES::DEFAULT_KEYLENGTH);
}


// AES Encryption

Ptr<Packet> EncryptAES(Ptr<Packet> packet, const std::string &key) {
    if (packet->GetSize() == 0) return packet;

    uint8_t *data = new uint8_t[packet->GetSize()];
    packet->CopyData(data, packet->GetSize());

    // Generate IV
    AutoSeededRandomPool prng;
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    // Encrypt using AES-CTR
    CTR_Mode<AES>::Encryption encryptor;
    SecByteBlock aesKey(reinterpret_cast<const byte *>(key.data()), AES::DEFAULT_KEYLENGTH);
    encryptor.SetKeyWithIV(aesKey, aesKey.size(), iv);

    std::string encryptedData;
    ArraySource(data, packet->GetSize(), true,
                new StreamTransformationFilter(encryptor, new StringSink(encryptedData)));

    // Append HMAC
    std::string mac;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(aesKey, aesKey.size());
    StringSource(encryptedData, true,
                 new CryptoPP::HashFilter(hmac, new StringSink(mac)));

    // Construct final packet (IV + Ciphertext + HMAC)
    std::string finalPacket(reinterpret_cast<const char *>(iv), AES::BLOCKSIZE);
    finalPacket += encryptedData + mac;

    Ptr<Packet> encryptedPacket = Create<Packet>((const uint8_t *)finalPacket.data(), finalPacket.size());

    delete[] data;
    return encryptedPacket;
}




// AES Decryption
Ptr<Packet> DecryptAES(Ptr<Packet> packet, const std::string &key) {
    if (packet->GetSize() < (size_t)AES::BLOCKSIZE + CryptoPP::SHA256::DIGESTSIZE) return packet;

    uint8_t *data = new uint8_t[packet->GetSize()];
    packet->CopyData(data, packet->GetSize());

    // Extract IV
    byte iv[AES::BLOCKSIZE];
    std::memcpy(iv, data, AES::BLOCKSIZE);

    // Separate ciphertext and HMAC
    std::string encryptedMessage(reinterpret_cast<const char *>(data + AES::BLOCKSIZE),
                                 packet->GetSize() - AES::BLOCKSIZE - CryptoPP::SHA256::DIGESTSIZE);
    std::string receivedMac(reinterpret_cast<const char *>(data + packet->GetSize() - CryptoPP::SHA256::DIGESTSIZE),
                            CryptoPP::SHA256::DIGESTSIZE);

    // Compute HMAC for integrity check
    SecByteBlock aesKey(reinterpret_cast<const byte *>(key.data()), AES::DEFAULT_KEYLENGTH);
    std::string computedMac;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(aesKey, aesKey.size());
    StringSource(encryptedMessage, true,
                 new CryptoPP::HashFilter(hmac, new StringSink(computedMac)));

    if (computedMac != receivedMac) {
        NS_FATAL_ERROR("[SECURITY] HMAC verification failed! Packet may be tampered.");
        delete[] data;
        return packet;
    }

    // Decrypt using AES-CTR
    CTR_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(aesKey, aesKey.size(), iv);

    std::string decryptedData;
    ArraySource(reinterpret_cast<const byte *>(encryptedMessage.data()), encryptedMessage.size(), true,
                new StreamTransformationFilter(decryptor, new StringSink(decryptedData)));

    Ptr<Packet> decryptedPacket = Create<Packet>((const uint8_t *)decryptedData.data(), decryptedData.size());

    delete[] data;
    return decryptedPacket;
}

// Add a new drone dynamically to the swarm
void AddDroneToSwarm(const std::string& droneId) {
    Drone drone = GenerateDilithiumKeyPair(droneId);
    GenerateKyberKeyPair(drone);
    keyRegistry[droneId] = drone;
    std::cout << droneId << " added to network and authenticated!" << std::endl;
}

// Remove a drone from the swarm and update key registry
void RemoveDroneFromSwarm(const std::string& droneId, uint32_t nodeId, AnimationInterface& anim) {
    if (keyRegistry.erase(droneId)) {
        std::cout << droneId << " removed from network. Updating security keys!" << std::endl;
        //anim.UpdateNodeSize(nodeId, 0, 0); // Hide the drone in NetAnim
        anim.UpdateNodeColor(nodeId, 0, 255, 0); // Change color to red
        anim.UpdateNodeSize(nodeId, 0.5, 0.5);   // Reduce size
        anim.UpdateNodeDescription(nodeId, "REMOVED");
        removedDrones.insert(nodeId);
        
    } else {
        std::cout << "Node " << droneId << " not found in the swarm." << std::endl;
    }
}




// Periodic Key Rotation for all active drones
void RotateKeys() {
    std::cout << "\nRotating encryption keys for all active nodes...\n";
    for (auto& [id, drone] : keyRegistry) {
        uint32_t nodeId = std::distance(keyRegistry.begin(), keyRegistry.find(id));  // Get drone index
        if (removedDrones.find(nodeId) != removedDrones.end()) continue;  // Skip removed drones

        GenerateKyberKeyPair(drone);
        std::cout << " " << id << " regenerated Kyber keys!" << std::endl;
    }
    Simulator::Schedule(Seconds(10), &RotateKeys);
}


// Function to generate a random MAC address
std::string GenerateRandomMac() {
    std::ostringstream mac;
    uint8_t firstByte = (rand() % 256) | 0x02; // Ensure Locally Administered MAC
    mac << std::hex << std::setw(2) << std::setfill('0') << (int)firstByte;

    for (int i = 1; i < 6; i++) {
        int byte = rand() % 256;
        mac << ":" << std::hex << std::setw(2) << std::setfill('0') << byte;
    }

    return mac.str();
}

// Function to change the MAC address of a drone
void ChangeMacAddress(NodeContainer drones) {
    std::cout << "\n[SECURITY] Changing MAC addresses dynamically..." << std::endl;

    for (uint32_t i = 0; i < drones.GetN(); ++i) {
        if (removedDrones.find(i) != removedDrones.end()) continue; // Skip removed drones

        Ptr<NetDevice> device = drones.Get(i)->GetDevice(0);
        Ptr<WifiNetDevice> wifiDevice = DynamicCast<WifiNetDevice>(device);

        if (wifiDevice) {
            std::string newMac = GenerateRandomMac();
            Mac48Address newMacAddr(newMac.c_str());

            wifiDevice->GetMac()->SetAddress(newMacAddr);

            std::cout << "[SECURITY] Node-" << i + 1 << " MAC changed to: " << newMac << std::endl;
        }
    }

    Simulator::Schedule(Seconds(10), &ChangeMacAddress, drones);
}



// Function to periodically change MAC addresses
void ScheduleMacChange(NodeContainer& drones, NetDeviceContainer& devices) {
    for (uint32_t i = 0; i < drones.GetN(); i++) {
Simulator::Schedule(Seconds(15), &ChangeMacAddress, drones);

    }
    Simulator::Schedule(Seconds(15), &ScheduleMacChange, drones, devices); // Schedule again
}



// Shared secret key for HMAC (must be securely exchanged)
const std::string hmacKey = "secure_shared_key";

std::string GenerateHMAC(const std::string &message, const std::string &key) {
    std::string mac;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac((const CryptoPP::byte*)key.data(), key.size());
    
    CryptoPP::StringSource(
        message, true,
        new CryptoPP::HashFilter(hmac, new CryptoPP::HexEncoder(new CryptoPP::StringSink(mac)))
    );

    return mac;
}

bool VerifyHMAC(const std::string &message, const std::string &receivedHmac) {
    std::string computedHmac = GenerateHMAC(message, hmacKey);
    return computedHmac == receivedHmac;
}

void AddHMACToPacket(Ptr<Packet> packet, const std::string& key) {
    uint8_t* buffer = new uint8_t[packet->GetSize()];
    packet->CopyData(buffer, packet->GetSize());

    std::string data(reinterpret_cast<char*>(buffer), packet->GetSize());
    delete[] buffer;

    std::string hmac = GenerateHMAC(data, hmacKey);

    // Append HMAC at transport layer
    Ptr<Packet> newPacket = Create<Packet>((uint8_t*)hmac.data(), hmac.size());
    newPacket->AddAtEnd(packet);
    packet = newPacket;
}


bool VerifyHMACInPacket(Ptr<Packet> packet, const std::string& key) {
    uint32_t packetSize = packet->GetSize();
    if (packetSize < CryptoPP::SHA256::DIGESTSIZE) {
        std::cout << "[SECURITY] Transport-layer packet too small to contain HMAC!" << std::endl;
        return false;
    }

    // Extract packet data
    std::vector<uint8_t> buffer(packetSize);
    packet->CopyData(buffer.data(), packetSize);

    // Separate transport-layer payload and HMAC
    std::string transportData(reinterpret_cast<char*>(buffer.data()), packetSize - CryptoPP::SHA256::DIGESTSIZE);
    std::string receivedMac(reinterpret_cast<char*>(buffer.data() + (packetSize - CryptoPP::SHA256::DIGESTSIZE)), CryptoPP::SHA256::DIGESTSIZE);

    // Compute HMAC on received transport-layer data
    std::string computedMac = GenerateHMAC(transportData, hmacKey);
    
    // Verify HMAC integrity
    if (computedMac != receivedMac) {
        std::cout << "[SECURITY] Transport-layer HMAC verification failed! Dropping packet." << std::endl;
        return false;
    }

    std::cout << "[SECURITY] Transport-layer HMAC verification successful!" << std::endl;
    return true;
}

void SendSecurePacket(Ptr<Socket> socket, const std::string& message) {
    std::string hmac = GenerateHMAC(message, hmacKey);  // Generate HMAC properly
    std::string payload = message + "|" + hmac;  // Concatenate message and HMAC

    Ptr<Packet> packet = Create<Packet>((uint8_t*)payload.data(), payload.size());
    socket->Send(packet);

    NS_LOG_INFO("[TRANSPORT] Packet sent with HMAC: " << hmac);
}


void ReceiveSecurePacket(Ptr<Socket> socket) {
    Ptr<Packet> packet = socket->Recv();
    Ptr<Node> node = socket->GetNode();
    double receivedRssi = 0.0;

    // Get RSSI from PHY layer
    Ptr<NetDevice> device = node->GetDevice(0);
    Ptr<WifiNetDevice> wifiDevice = DynamicCast<WifiNetDevice>(device);
    Ptr<WifiPhy> phy = wifiDevice->GetPhy();

    ns3::SnrTag snrTag;
    if (packet->PeekPacketTag(snrTag)) {
        receivedRssi = snrTag.Get();
        NS_LOG_INFO("Received RSSI (from SNR): " << receivedRssi);
    } else {
        NS_LOG_WARN("No SNR tag found in the packet.");
    }

    // Use vector to avoid memory leaks
    std::vector<uint8_t> buffer(packet->GetSize());
    packet->CopyData(buffer.data(), packet->GetSize());

    std::string receivedData(reinterpret_cast<char*>(buffer.data()), packet->GetSize());

    size_t delimiter = receivedData.find("|");
    if (delimiter == std::string::npos) {
        NS_LOG_ERROR("[SECURITY ALERT] Malformed packet received! Dropping.");
        return;
    }

    std::string message = receivedData.substr(0, delimiter);
    std::string receivedHmac = receivedData.substr(delimiter + 1);

    // Extract sender ID
    std::string senderId = message.substr(0, message.find(" "));

    // Authenticate RSSI before verifying HMAC
    AuthenticateUsingRssi(senderId, receivedRssi);

    // Verify HMAC
    if (!VerifyHMAC(message, receivedHmac)) {
        NS_LOG_ERROR("[SECURITY ALERT] HMAC verification failed! Dropping packet.");
        return;
    }

    NS_LOG_INFO("[SECURITY] Packet integrity verified successfully.");
    std::cout << "[SECURITY] Received Message: " << message << std::endl;
}


void SecureCommunication(Drone &sender, Drone &receiver) {
    std::string message = "Hello, secure world!";
    
    Ptr<Packet> packet = Create<Packet>((const uint8_t *)message.data(), message.size());
    packet = EncryptAES(packet, sender.aesKey);
    
    // Simulate network transmission
    Ptr<Packet> receivedPacket = packet->Copy();
    
    receivedPacket = DecryptAES(receivedPacket, receiver.aesKey);
    
    uint8_t *decryptedData = new uint8_t[receivedPacket->GetSize()];
    receivedPacket->CopyData(decryptedData, receivedPacket->GetSize());
    
    std::string decryptedMessage(reinterpret_cast<const char *>(decryptedData), receivedPacket->GetSize());
    std::cout << "[SECURITY] Decrypted message: " << decryptedMessage << std::endl;
    
    delete[] decryptedData;
}



 FlowMonitorHelper flowHelper;
Ptr<FlowMonitor> flowMonitor;


// Test 1: Post-Quantum Cryptography - Dilithium & Kyber Key Pair Generation
void TestPostQuantumCryptography() {
    std::cout << "\n===== Post-Quantum Cryptography Test =====" << std::endl;

    // Generate keys for two drones
    Drone droneA = GenerateDilithiumKeyPair("droneA");
    GenerateKyberKeyPair(droneA);

    Drone droneB = GenerateDilithiumKeyPair("droneB");
    GenerateKyberKeyPair(droneB);

   

    // Perform key exchange and validate AES key
    std::string sharedKey = PerformKyberKeyExchange(droneA, droneB);
    //std::cout << "Shared AES Key: " << sharedKey << std::endl;

    if (sharedKey.size() == AES::DEFAULT_KEYLENGTH) {
        std::cout << "[PASS] Post-Quantum Cryptography Test Passed!" << std::endl;
    } else {
        std::cout << "[FAIL] Kyber key exchange failed!" << std::endl;
    }
}

// Test 2: RSSI-Based Authentication
void TestRSSIAuthentication() {
    std::cout << "\n===== RSSI-Based Authentication Test =====" << std::endl;

    // Valid RSSI (should pass)
    std::cout << "Testing RSSI -51 (Valid Node)..." << std::endl;
    AuthenticateUsingRssi("node-1", -51.0);

    // Invalid RSSI (should fail)
    std::cout << "Testing RSSI -70 (Possible Spoofing)..." << std::endl;
    AuthenticateUsingRssi("node-1", -70.0);

    // Unknown Drone (should alert)
    std::cout << "Testing Unknown node RSSI -55..." << std::endl;
    AuthenticateUsingRssi("unknown-node", -55.0);

    std::cout << "[INFO] RSSI-Based Authentication Test Completed!" << std::endl;
}

// Test 3: AES Encryption & HMAC Integrity Verification
void TestEncryptionAndIntegrity() {
    std::cout << "\n===== AES Encryption & HMAC Integrity Test =====" << std::endl;

    Drone sender = GenerateDilithiumKeyPair("droneX");
    Drone receiver = GenerateDilithiumKeyPair("droneY");
    GenerateKyberKeyPair(sender);
    GenerateKyberKeyPair(receiver);

    // Perform key exchange
    sender.aesKey = PerformKyberKeyExchange(sender, receiver);
    receiver.aesKey = sender.aesKey;

    std::string message = "Test message from NodeX";
    std::cout << "Original Message: " << message << std::endl;

    // Convert string to packet
    Ptr<Packet> packet = Create<Packet>((const uint8_t *)message.data(), message.size());

    // Encrypt the packet
    Ptr<Packet> encryptedPacket = EncryptAES(packet, sender.aesKey);

    // Decrypt the packet
    Ptr<Packet> decryptedPacket = DecryptAES(encryptedPacket, receiver.aesKey);

    // Convert decrypted packet back to string
    uint8_t *decryptedData = new uint8_t[decryptedPacket->GetSize()];
    decryptedPacket->CopyData(decryptedData, decryptedPacket->GetSize());
    std::string decryptedMessage(reinterpret_cast<const char *>(decryptedData), decryptedPacket->GetSize());

    std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

    if (decryptedMessage == message) {
        std::cout << "[PASS] AES Encryption/Decryption Successful!" << std::endl;
    } else {
        std::cout << "[FAIL] AES Encryption/Decryption Failed!" << std::endl;
    }

    delete[] decryptedData;  // Free allocated memory

    // Test HMAC verification
    std::string key = "secure_shared_key";
    std::string hmac = GenerateHMAC(message, key);
    std::cout << "Generated HMAC: " << hmac << std::endl;
    
    bool verificationResult = VerifyHMAC(message, hmac);
std::cout << "Verifying HMAC..." << std::endl;
std::cout << "HMAC Passed?: " << (verificationResult ? "YES" : "NO") << std::endl;

    if (VerifyHMAC(message, hmac)) {
        std::cout << "[PASS] HMAC Verification Successful!" << std::endl;
    } else {
        std::cout << "[FAIL] HMAC Verification Failed!" << std::endl;
    }

    // Tampered message should fail
    std::string tamperedMessage = message + "!";
    std::cout << "Testing Tampered Message HMAC Verification..." << std::endl;

    if (!VerifyHMAC(tamperedMessage, hmac)) {
        std::cout << "[PASS] Tampered HMAC Verification Correctly Failed!" << std::endl;
    } else {
        std::cout << "[FAIL] Tampered HMAC Verification Incorrectly Passed!" << std::endl;
    }

    std::cout << "=====================================\n" << std::endl;
}



int main(int argc, char* argv[]) {
    SuppressWarnings();  // Call this at the start of your simulation
    CommandLine cmd;
    cmd.Parse(argc, argv);

    // Create Drones (Nodes)
    NodeContainer drones;
    drones.Create(3);

    // Set Mobility Model
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                              "Bounds", RectangleValue(Rectangle(-100, 100, -100, 100)),
                              "Speed", StringValue("ns3::ConstantRandomVariable[Constant=10]"),
                              "Time", TimeValue(Seconds(2.0)));
    mobility.Install(drones);

    // Install WiFi (Adhoc Mode)
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    phy.SetChannel(channel.Create());

    NetDeviceContainer devices = wifi.Install(phy, mac, drones);

    // Install Internet Stack
    InternetStackHelper internet;
    internet.Install(drones);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    // Initialize and Authenticate Drones
    std::cout << "\nInitializing Nodes with Authentication and Key Exchange...\n";
    AddDroneToSwarm("node-1");
    AddDroneToSwarm("node-2");
    AddDroneToSwarm("node-3");

    // Create UDP sockets for secure communication
    Ptr<Socket> drone1Socket = Socket::CreateSocket(drones.Get(0), UdpSocketFactory::GetTypeId());
    Ptr<Socket> drone2Socket = Socket::CreateSocket(drones.Get(1), UdpSocketFactory::GetTypeId());

    drone1Socket->Bind();  // Bind socket to node
    drone2Socket->Bind();

    // Set up receive callbacks for drones
    drone1Socket->SetRecvCallback(MakeCallback(&ReceiveSecurePacket));
    drone2Socket->SetRecvCallback(MakeCallback(&ReceiveSecurePacket));

    // NetAnim setup
    AnimationInterface anim("zero-trust-final-security.xml");
    anim.EnableIpv4L3ProtocolCounters(Seconds(0.0), Seconds(1.0), Seconds(15.0));

    anim.UpdateNodeDescription(drones.Get(0), "Node 1");
    anim.UpdateNodeDescription(drones.Get(1), "Node 2");
    anim.UpdateNodeDescription(drones.Get(2), "Node 3");
    anim.UpdateNodeSize(drones.Get(0), 2.0, 2.0);
    anim.UpdateNodeSize(drones.Get(1), 2.0, 2.0);
    anim.UpdateNodeSize(drones.Get(2), 2.0, 2.0);
    
    for (uint32_t i = 0; i < drones.GetN(); ++i) {
        anim.SetConstantPosition(drones.Get(i), i * 10, 10);
    }

    // Simulate Secure Communication
    std::cout << "\nSimulating Secure Communication Between Nodes...\n";
    Simulator::Schedule(Seconds(2), &SecureCommunication, std::ref(keyRegistry["node-1"]), std::ref(keyRegistry["node-2"]));

    // Schedule Periodic Key Rotation (Every 10 Seconds)
    Simulator::Schedule(Seconds(10), &RotateKeys);

    // Schedule MAC Address Change
    Simulator::Schedule(Seconds(15), &ChangeMacAddress, drones);

    // Simulate Drone Removal After 5 Seconds
    //Simulator::Schedule(Seconds(5), &RemoveDroneFromSwarm, "drone-3", 2, std::ref(anim));

    // Authenticate using RSSI
    Simulator::Schedule(Seconds(2), &AuthenticateUsingRssi, "node-1", -45.0); // Test valid authentication
   // Simulator::Schedule(Seconds(4), &AuthenticateUsingRssi, "node-2", -70.0); // Test spoofed drone alert

    // Install Applications (UDP Traffic)
    // Install Applications (UDP Traffic)
Ipv4Address receiverAddress1 = interfaces.GetAddress(1);
Ipv4Address receiverAddress2 = interfaces.GetAddress(2);
Ipv4Address receiverAddress0 = interfaces.GetAddress(0);

// Flow 1: Node 0 → Node 1 (100 packets, 1 Mbps)
ns3::OnOffHelper onoff1("ns3::UdpSocketFactory", InetSocketAddress(receiverAddress1, 9));
onoff1.SetConstantRate(DataRate("1Mbps"), 1024); // 1 Mbps, Packet Size: 1024 bytes
ApplicationContainer senderApp1 = onoff1.Install(drones.Get(0));
senderApp1.Start(Seconds(1.0));
senderApp1.Stop(Seconds(15.0));

// Flow 2: Node 1 → Node 2 (200 packets, 512 Kbps)
ns3::OnOffHelper onoff2("ns3::UdpSocketFactory", InetSocketAddress(receiverAddress2, 10));
onoff2.SetConstantRate(DataRate("512Kbps"), 512); // 512 Kbps, Packet Size: 512 bytes
ApplicationContainer senderApp2 = onoff2.Install(drones.Get(1));
senderApp2.Start(Seconds(2.0));
senderApp2.Stop(Seconds(15.0));

// Flow 3: Node 2 → Node 0 (50 packets, 2 Mbps)
ns3::OnOffHelper onoff3("ns3::UdpSocketFactory", InetSocketAddress(receiverAddress0, 11));
onoff3.SetConstantRate(DataRate("2Mbps"), 2048); // 2 Mbps, Packet Size: 2048 bytes
ApplicationContainer senderApp3 = onoff3.Install(drones.Get(2));
senderApp3.Start(Seconds(3.0));
senderApp3.Stop(Seconds(15.0));

// Install Packet Sinks on Each Node
ns3::PacketSinkHelper sink1("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 9));
ApplicationContainer receiverApp1 = sink1.Install(drones.Get(1));
receiverApp1.Start(Seconds(0.0));
receiverApp1.Stop(Seconds(15.0));

ns3::PacketSinkHelper sink2("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 10));
ApplicationContainer receiverApp2 = sink2.Install(drones.Get(2));
receiverApp2.Start(Seconds(0.0));
receiverApp2.Stop(Seconds(15.0));

ns3::PacketSinkHelper sink3("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 11));
ApplicationContainer receiverApp3 = sink3.Install(drones.Get(0));
receiverApp3.Start(Seconds(0.0));
receiverApp3.Stop(Seconds(15.0));


    
    
    // Stop Simulation After 30 Seconds
    Simulator::Stop(Seconds(20));
    
   
flowMonitor = flowHelper.InstallAll();

//tracemetrics
/*AsciiTraceHelper ascii;
Ptr<OutputStreamWrapper> stream = ascii.CreateFileStream("trace.tr");
phy.EnablePcapAll("trace");

phy.EnableAsciiAll(stream);
//phy.EnableAscii("trace.tr", devices.Get(0));  // Logs only for Node 0
*/

TestPostQuantumCryptography();
TestRSSIAuthentication();
    TestEncryptionAndIntegrity();


    // Run Simulation
    Simulator::Run();
    
    flowMonitor->CheckForLostPackets();

Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());


std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();

std::cout << "Flow Statistics:\n";
std::cout << "Total Number of Flows: " << stats.size() << "\n";


/*
for (auto &flow : stats) {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);
    std::cout << "Flow ID: " << flow.first
              << " Source: " << t.sourceAddress << " --> Destination: " << t.destinationAddress
              << "\n Tx Packets: " << flow.second.txPackets
              << " Rx Packets: " << flow.second.rxPackets
              << " Lost Packets: " << flow.second.lostPackets
              << " Throughput: " << (flow.second.rxBytes * 8.0 / (flow.second.timeLastRxPacket.GetSeconds() - flow.second.timeFirstTxPacket.GetSeconds())) / 1024
              << " Kbps\n";
}
*/

for (const auto &flow : stats) {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow.first);

    

    std::cout << "Flow ID: " << flow.first << std::endl;
    std::cout << "  Source Address: " << t.sourceAddress << std::endl;
    std::cout << "  Destination Address: " << t.destinationAddress << std::endl;
    std::cout << "  Transmitted Packets: " << flow.second.txPackets << std::endl;
    std::cout << "  Received Packets: " << flow.second.rxPackets << std::endl;
    std::cout << "  Lost Packets: " << flow.second.lostPackets << std::endl;
    std::cout << "  First Transmission Time: " << flow.second.timeFirstTxPacket.GetSeconds() << "s\n";
    std::cout << "  Last Reception Time: " << flow.second.timeLastRxPacket.GetSeconds() << "s\n";
    
    //double firstTxTime = flow.second.timeFirstTxPacket.GetSeconds();
    //double lastRxTime = flow.second.timeLastRxPacket.GetSeconds();
    double duration = flow.second.timeLastRxPacket.GetSeconds() - flow.second.timeFirstTxPacket.GetSeconds();
    double throughput = (duration > 0) ? (flow.second.rxBytes * 8.0 / duration) / 1024 : 0;

    std::cout << "  Throughput: " << std::fixed << std::setprecision(2) << throughput << " Kbps" << std::endl;
    std::cout << "--------------------------------------" << std::endl;
}


flowMonitor->SerializeToXmlFile("flowmon-zero-trust.xml", true, true);
    Simulator::Destroy();

    std::cout << "\nSimulation Complete!\n";
    return 0;
}

