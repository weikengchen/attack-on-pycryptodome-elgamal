from Cryptodome.PublicKey import ElGamal
from Cryptodome import Random
from Cryptodome.Random import random
import math

# Check if a value is quadratic residue (QR) for safe primes
def isQR(x, p):
    q = (p - 1) / 2
    return pow(x, q, p)

# Find a message that is not a QR, note: half of messages are not QR
def findQNR(p):
    r = random.randint(1, p - 1)
    while isQR(r, p) == 1:
        r = random.randint(1, p - 1)
    return r

# Find a message that is a QR, note: half of messages are not QR
def findQR(p):
    r = random.randint(1, p - 1)
    return pow(r, 2, p)

# Key generation. We use 512-bit only for better performance
print "Generating the key..."
key = ElGamal.generate(512, Random.new().read)

wrong = 0
runs = 1000

print "Running the experiment..."

for i in xrange(runs):
	p = int(key.p)
	pk = int(key.y)

	# Select two messages
	plaintexts = dict()
	plaintexts[0] = findQNR(p)
	plaintexts[1] = findQR(p)

	challenge_bit = random.randint(0,1)
	r = random.randint(1, (p - 1) / 2)
	challenge = key._encrypt(plaintexts[challenge_bit], r)

	# Guess the challenge bit
	output = -1

	# Without the secret key (y is the public key and p is in the public parameter)
	# Guess which one it is.
	if ((isQR(pk, p) == 1) or (isQR(challenge[0], p) == 1)):
	    if isQR(challenge[1], p) == 1:
		output = 1
	    else:
		output = 0
	else:
	    if isQR(challenge[1], p) == 1:
		output = 0
	    else:
		output = 1

	if output != challenge_bit:
	    wrong = wrong + 1

print "Number of times the guess was wrong (should be 50% if ElGamal is secure):", wrong, "/", runs
