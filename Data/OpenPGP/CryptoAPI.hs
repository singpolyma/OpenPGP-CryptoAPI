module Data.OpenPGP.CryptoAPI where

import Numeric
import Data.Word
import Data.Char
import Data.Serialize (encode)
import Crypto.Classes hiding (hash)
import Crypto.Hash.MD5 (MD5)
import Crypto.Hash.SHA1 (SHA1)
import Crypto.Hash.RIPEMD160 (RIPEMD160)
import Crypto.Hash.SHA256 (SHA256)
import Crypto.Hash.SHA384 (SHA384)
import Crypto.Hash.SHA512 (SHA512)
import Crypto.Hash.SHA224 (SHA224)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ

import qualified Data.OpenPGP as OpenPGP

-- | Generate a key fingerprint from a PublicKeyPacket or SecretKeyPacket
-- <http://tools.ietf.org/html/rfc4880#section-12.2>
fingerprint :: OpenPGP.Packet -> String
fingerprint p
	| OpenPGP.version p == 4 = snd $ hash OpenPGP.SHA1 material
	| OpenPGP.version p `elem` [2, 3] = snd $ hash OpenPGP.MD5 material
	| otherwise = error "Unsupported Packet version or type in fingerprint"
	where
	material = LZ.concat $ OpenPGP.fingerprint_material p

hash :: OpenPGP.HashAlgorithm -> LZ.ByteString -> (BS.ByteString, String)
hash OpenPGP.MD5 = hash_ (undefined :: MD5)
hash OpenPGP.SHA1 = hash_ (undefined :: SHA1)
hash OpenPGP.RIPEMD160 = hash_ (undefined :: RIPEMD160)
hash OpenPGP.SHA256 = hash_ (undefined :: SHA256)
hash OpenPGP.SHA384 = hash_ (undefined :: SHA384)
hash OpenPGP.SHA512 = hash_ (undefined :: SHA512)
hash OpenPGP.SHA224 = hash_ (undefined :: SHA224)
hash _ = error "Unsupported HashAlgorithm in hash"

hash_ :: (Hash c d) => d -> LZ.ByteString -> (BS.ByteString, String)
hash_ d bs = (hbs, map toUpper $ pad $ hexString $ BS.unpack $ hbs)
	where
	hbs = encode $ hashFunc d bs
	pad s = (replicate (len - length s) '0') ++ s
	len = (outputLength `for` d) `div` 8

hexString :: [Word8] -> String
hexString = foldr (pad `oo` showHex) ""
	where
	oo = (.) . (.)
	pad s | odd $ length s = '0':s
	      | otherwise = s
