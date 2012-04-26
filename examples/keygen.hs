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
		OpenPGP.symmetric_type = undefined,
		OpenPGP.s2k_type = undefined,
		OpenPGP.s2k_hash_algorithm = undefined,
		OpenPGP.s2k_salt = undefined,
		OpenPGP.s2k_count = undefined,
		OpenPGP.encrypted_data = undefined,
		OpenPGP.private_hash = undefined }

	let userID = OpenPGP.UserIDPacket "Test <test@example.com>"
	let message = OpenPGP.Message[ secretKey, userID ]

	let message' = OpenPGP.Message [ secretKey, userID,
		OpenPGP.sign message message OpenPGP.SHA256 [] (fromIntegral t) g]

	LZ.putStr $ encode message'
