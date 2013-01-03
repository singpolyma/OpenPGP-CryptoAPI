import System.Time (getClockTime, ClockTime(..))
import qualified Data.ByteString.Lazy as LZ

import Data.Binary
import Crypto.Random
import Control.Arrow (second)
import qualified Crypto.Cipher.RSA as RSA

import qualified Data.OpenPGP as OpenPGP
import qualified Data.OpenPGP.CryptoAPI as OpenPGP

main :: IO ()
main = do
	time <- getClockTime
	let TOD t _ = time

	rng <- newGenIO :: IO SystemRandom
	-- RSA.generate size in *bytes*
	let Right ((pub,priv),g) = RSA.generate rng 128 65537

	let secretKey = OpenPGP.SecretKeyPacket {
		OpenPGP.version = 4,
		OpenPGP.timestamp = fromIntegral t,
		OpenPGP.key_algorithm = OpenPGP.RSA,
		-- OpenPGP p/q are inverted from Crypto.Cipher.RSA
		OpenPGP.key = map (second OpenPGP.MPI)
			[('n', RSA.public_n pub), ('e', RSA.public_e pub),
			('d', RSA.private_d priv), ('p', RSA.private_q priv),
			('q', RSA.private_p priv), ('u', RSA.private_qinv priv)],
		OpenPGP.s2k_useage = 0,
		OpenPGP.s2k = OpenPGP.S2K 100 LZ.empty, -- Bogus, unused S2K
		OpenPGP.symmetric_algorithm = OpenPGP.Unencrypted,
		OpenPGP.encrypted_data = LZ.empty,
		OpenPGP.is_subkey = False}

	let userID = OpenPGP.UserIDPacket "Test <test@example.com>"
	let message = OpenPGP.Message [secretKey, userID]

	let message' = OpenPGP.Message [secretKey, userID,
		OpenPGP.sign message message OpenPGP.SHA256 [] (fromIntegral t) g]

	LZ.putStr $ encode message'
