#pragma once

#include "Ctu.h"

enum class PacketTypes : uint32_t
{
	PublicRSA,
	GeneralTesting
};

/*
TEST_CASE("Add function works correctly", "[add]") {
	REQUIRE(5 == 5);
	REQUIRE(0 == 0);
	REQUIRE(0 == 0);
}
*/

int main()
{
	// ========== RSA & AES ==========

	/*
	This code demonstrates the use of RSA and AES algorithms for generating, encrypting and decrypting keys and 
	messages. It generates an RSA key pair and signs and verifies a message using it. It then retrieves the RSA 
	private and public keys, generates an AES key, encrypts it using the RSA public key, and decrypts it using the RSA 
	private key. Finally, it compares the decrypted AES key to the original AES key and asserts that they are equal.
	*/

	int RSA_SIZE = 2048;
	int AES_SIZE = 512;

	// Generate an RSA key pair
	EVP_PKEY* rsaKeyPair = ctu::security::GenerateRSAKey(RSA_SIZE);

	std::string message = "hello, world";
	std::string signature = ctu::security::SignMessage(message, rsaKeyPair);
	
	assert(ctu::security::VerifyMessage(message, signature, rsaKeyPair) == true);

	// Get RSA Private & Public Keys
	EVP_PKEY* privateKey = ctu::security::GetPrivateRSAKey(rsaKeyPair);
	EVP_PKEY* publicKey = ctu::security::GetPublicRSAKey(rsaKeyPair);

	// Generate an AES key
	std::string plaintext_aes = ctu::security::GenerateAESKey(AES_SIZE);

	// Encrypt AES key via the public RSA key
	std::string encrypted_aes = ctu::security::EncryptWithPublicKey(publicKey, plaintext_aes);

	// Decrypt the AES key via the private RSA key
	std::string decrypted_aes = ctu::security::DecryptWithPrivateKey(privateKey, encrypted_aes);

	// Compaire the orginal AES key to the Decrypted AES key.
	assert(decrypted_aes.compare(plaintext_aes) == true);

	// ========== Serialization ==========

	/*
	This code utilizes a packet structure provided by the ctu::net library to transfer data over a network. It creates 
	a packet object with a header ID of PacketTypes::PublicRSA, then pushes an EVP_PKEY object called publicKey into 
	it using the << operator. Subsequently, it pulls the publicKey object out of the packet using the >> operator and 
	stores it in a new EVP_PKEY object called publicKeyOut. Finally, it asserts that the publicKey and publicKeyOut 
	objects are equal, which confirms that the packing and unpacking of the object from the packet works correctly. 
	This technique of packing and unpacking data can be useful when sending data over a network, as it allows the data 
	to be transmitted in a standardized way, regardless of the underlying data representation, and can help ensure the 
	data is delivered correctly.
	*/

	// Packet test public key
	ctu::net::packet<PacketTypes> packet;
	packet.header.id = PacketTypes::PublicRSA;

	// Push into packet vector
	packet << publicKey;

	// Pull out of packet vector
	EVP_PKEY* publicKeyOut;
	packet >> publicKeyOut;

	assert(publicKey == publicKeyOut);

	// Packet test random data
	ctu::net::packet<PacketTypes> test;
	test.header.id = PacketTypes::GeneralTesting;

	// Struct test
	struct pos {
		float x;
		float y;
	};

	// Original Data
	int a = 10;
	float b = 1.2101;
	double c = 1000.9;
	short d = 1;
	bool e = false;
	bool f = true;
	char g = 'G';
	char h = 'z';
	std::string i = "Testing";
	pos j;
	j.x = 1.0;
	j.y = -1.0;

	test << a << b << c << d << e << f << g << h << i << j;

	// Set random Data
	a = 5;
	b = 1.2401;
	c = 1040.9;
	d = 99;
	e = true;
	f = false;
	g = 'J';
	h = 'i';
	i = "Hello";
	j.x = 9;
	j.y = -4.70001;

	assert(a == 5);
	assert(b == 1.2401);
	assert(c == 1040.9);
	assert(d == 99);
	assert(e == true);
	assert(f == false);
	assert(g == 'J');
	assert(h == 'i');
	assert(i == "Hello");
	assert(j.x == 9);
	assert(j.y == -4.70001);

	// Retrieve original Data
	test >> j >> i >> h >> g >> f >> e >> d >> c >> b >> a;

	assert(a == 10);
	assert(b == 1.2101);
	assert(c == 1000.9);
	assert(d == 1);
	assert(e == false);
	assert(f == true);
	assert(g == 'G');
	assert(h == 'z');
	assert(i == "Testing");
	assert(j.x == 1.0);
	assert(j.y == -1.0);

	// ========== ASIO Server ==========

	/*
	
	*/



	// ========== ASIO Client ==========

	/*

	*/



	return 0; // Exit with success code 0
}