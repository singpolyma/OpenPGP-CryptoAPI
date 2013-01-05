import Control.Arrow (second)
import Data.Binary (encode)
import Crypto.Random (newGenIO, SystemRandom)
import Data.Time.Clock.POSIX (getPOSIXTime)
import qualified Crypto.Cipher.RSA as RSA
import qualified Data.ByteString.Lazy as LZ

import qualified Data.OpenPGP as OpenPGP
import qualified Data.OpenPGP.CryptoAPI as OpenPGP

main :: IO ()
main = do
	time <- fmap (floor . realToFrac) getPOSIXTime

	rng <- newGenIO :: IO SystemRandom
	-- RSA.generate size in *bytes*
	let Right ((pub,priv),g) = RSA.generate rng 128 65537

	let secretKey = OpenPGP.SecretKeyPacket {
		OpenPGP.version = 4,
		OpenPGP.timestamp = time,
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
	let OpenPGP.CertificationSignature _ _ [sig] =
		fst $ OpenPGP.sign (OpenPGP.Message [secretKey])
				(OpenPGP.CertificationSignature secretKey userID [])
				OpenPGP.SHA256 [] (fromIntegral time) g
	let message = OpenPGP.Message [secretKey, userID, sig]

	LZ.putStr $ encode message
