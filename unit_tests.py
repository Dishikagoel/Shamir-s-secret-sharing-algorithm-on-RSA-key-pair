import unittest
import rsa_sss

class TestRSA_SSSAlgorithm(unittest.TestCase):
    
    def test_algo(self):

        #generate RSA public and private key pair
        private_key, public_key = rsa_sss.generate_key_pair()

        #split the private key into 5 shards
        shares, required_shares= rsa_sss.split_into_shards(5, 2, private_key)

        #save the 5 shares in 5 different files
        rsa_sss.shares_to_files(public_key, shares)

        #give the two indices (2 and 5) required to reassemble the key
        indices = set(['2','5'])

        #get the shares at the given indices
        shares_from_files = rsa_sss.shares_from_files(indices)

        #regenerate the private key
        regenerated_private_key = rsa_sss.reassemble_shards(required_shares, shares_from_files)

        #give the message to be encrypted
        msg = "Developer proposes, Tester disposes :D"

        #encrypt the message using RSA public key
        ciphertext = rsa_sss.encrypt_message(msg.encode(), public_key)

        #decrypt the message using regenerated private key
        plaintext = rsa_sss.decrypt_message(ciphertext, regenerated_private_key)

        self.assertEqual(plaintext.decode(), "Developer proposes, Tester disposes :D")

if __name__ == "__main__":
    unittest.main()
