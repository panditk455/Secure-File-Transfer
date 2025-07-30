
from Crypto.PublicKey import RSA


class RSAKeyPairGenerator:
  def __init__(self, public_key_file: str = "client/public_key.pem", private_key_file: str = "server/private_key.pem"):
      """
      Initialize the RSAKeyPairGenerator with file paths for saving keys.
      """
      self.pubkey_file = "client/public_key.pem"
      self.privkey_file = "server/private_key.pem"


  @staticmethod
  def newline(s):
      """
      Appends a newline to the given byte string.
      """
      return s + b'\n'




  def save_public_key(self, public_key, filename):
      """
      Save the public key to the specified file.
      """
      with open("client/public_key.pem", 'wb') as file:
          file.write(public_key.export_key(format='PEM'))




  def save_private_key(self, private_key, filename):
      """
      Save the private key to the specified file.
      """
      with open("server/private_key.pem", 'wb') as file:
          file.write(private_key.export_key(format='PEM'))




  def generate_key_pair(self):
      """
      Generate a new 2048-bit RSA key pair and save them to the specified files.
      """
      print('Generating a new 2048-bit RSA key pair...')
      keypair = RSA.generate(2048)
      self.save_public_key(keypair.publickey(), self.pubkey_file)
      self.save_private_key(keypair, self.privkey_file)
      print('Key pair generation complete.')


if __name__ == "__main__":
   generator = RSAKeyPairGenerator()
   generator.generate_key_pair()