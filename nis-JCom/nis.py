#nis Digital signature 
import random
from hashlib import sha512
#import sys
#from termcolor import colored, cprint


def coprime(a, b):
    while b != 0:
        a, b = b, a % b
    return a
    
    
def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

										#Euclid's extended algorithm for finding the multiplicative inverse of two numbers    
def modinv(a, m):
	g, x, y = extended_gcd(a, m)
	if g != 1:
		raise Exception('\033[40;1;43m Modular inverse does not exist :( \033[0m ')
	return x % m    

        
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError(' \033[40;1;43m Both the numbers must be prime :(  \033[0m ')
    elif p == q:
        raise ValueError(' \033[40;1;43m p and q cannot be equal :( \033[0m ')

    n = p * q

    
    phi = (p-1) * (q-1)

   													 #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    											#Use Euclid's Algorithm to verify that e and phi(n) are comprime 
    g = coprime(e, phi)
  
    while g != 1:
        e = random.randrange(1, phi)
        g = coprime(e, phi)

    												# Extended Euclid's Algorithm to generate the private key
    d = modinv(e, phi)

    return ((e, n), (d, n))


def encrypt(privatek, plaintext):
   	
    key, n = privatek

    								#Convert each letter in the plaintext to numbers based on the character using a^b mod m
            
    numberRepr = [ord(char) for char in plaintext]
    print("Number representation before encryption: ", numberRepr)
    print("\r")
    cipher = [pow(ord(char),key,n) for char in plaintext]
    
    															#Return the array of bytes
    return cipher


def decrypt(publick, ciphertext):
    #key into components
    key, n = publick
       
    
    numberRepr = [pow(char, key, n) for char in ciphertext]
    plain = [chr(pow(char, key, n)) for char in ciphertext]

    print("Decrypted number representation is: ", numberRepr)
    print("\r")
    
    #Return the array of bytes as a string
    return ''.join(plain)
    
    
def hashFunction(message):
    hashed = sha512(message.encode("UTF-8")).hexdigest()
    return hashed
    
    
def verify(receivedHashed, message):
    ourHashed = hashFunction(message)
    if receivedHashed == ourHashed:
    	print("\r")
        print(" \033[40;1;43m  Verification successful: \033[0m " )
        print("\r")
        print(receivedHashed, " = ", ourHashed)
    else:
        print("\r")
        print(" \033[40;1;43m Verification failed \033[0m")
        print(receivedHashed, " != ", ourHashed)
        

def main():
	
    p = int(input(" \033[40;1;46m   Enter a prime number (17, 19, 23, etc): \033[0m  "))
    print("\r")
    q = int(input(" \033[40;1;46m   Enter another prime number (Not one you entered above): \033[0m   "))
    print("\r")   
    print("\033[1m Generating your public/private keypairs now . . .   \033[0m ")
    print("\r")
    public, private = generate_keypair(p, q)
    
    print("Your public key is ", public ," and your private key is ", private)
    print("\r")
    print("\r")
    message = input(" \033[40;1;46m Enter a message to encrypt with your private key:  \033[0m ")
    print("\r")
    print("")

    hashed = hashFunction(message)
   
    print(" Encrypting message with private key ", private ," . . .")
    print("\r")
    encrypted_msg = encrypt(private, hashed)   
    print(" \033[40;1;46m Your encrypted hashed message is:   \033[0m ")
    print("\r")
    print(''.join(map(lambda x: str(x), encrypted_msg)))
    
    
    print("")
    print("\r")
    print("Decrypting message with public key ", public ," . . .")

    decrypted_msg = decrypt(public, encrypted_msg)
    print("\033[40;1;46m Your decrypted message is: \033[0m ")  
    print("\r")
    print(decrypted_msg)
    
    print("")
    print("\033[40;1;46m Verification process . . . \033[0m ")
    print("\r")
    verify(decrypted_msg, message)
   
main()    
    
